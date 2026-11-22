//! TUN dataplane: IP packets over iroh datagrams.

use std::cmp::Ordering;
use std::collections::BinaryHeap;
use std::net::Ipv4Addr;
use std::sync::Arc;

use anyhow::{Context, bail};
use bytes::Bytes;
use tokio::sync::mpsc;
use tracing::{debug, info, warn};
use tun_rs::{AsyncDevice, DeviceBuilder};

use crate::policy::{AclVerdict, QosVerdict};
use crate::transport::{InboundPacket, IrohTransport};
use crate::wire::{HEADER_LEN, MeshHeader, PacketInfo, decrement_ttl, flow_hash};
use crate::{AgentState, wire};
use stellaris_types::AclDirection;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum InboundAction {
    Deliver(Vec<u8>),
    Forward {
        next: stellaris_types::NodeId,
        frame: Bytes,
    },
    Drop(&'static str),
}

pub async fn start(
    state: AgentState,
    transport: Arc<IrohTransport>,
    mut inbound_rx: mpsc::Receiver<InboundPacket>,
) -> anyhow::Result<()> {
    let local_ip = local_ipv4(&state)?;
    let tun_name = tun_name(&state);
    if !state.config.dataplane.advertise.is_empty() {
        crate::gateway::ensure_forwarding()?;
        if state.config.dataplane.nat {
            crate::gateway::ensure_nat(&state.config.network.cidr.to_string(), &tun_name)?;
            info!("subnet gateway NAT enabled");
        }
        info!(
            prefixes = ?state.config.dataplane.advertise,
            "subnet gateway forwarding enabled"
        );
    }
    let prefix_len = match state.config.network.cidr {
        ipnet::IpNet::V4(cidr) => cidr.prefix_len(),
        ipnet::IpNet::V6(_) => bail!("MVP dataplane supports IPv4 overlay CIDR only"),
    };
    // Conservative initial MTU; the monitor raises it once iroh reports path capacity.
    let initial_mtu = state.config.dataplane.mtu.min(1100);
    let dev = DeviceBuilder::new()
        .name(tun_name.clone())
        .ipv4(local_ip, prefix_len, None)
        .mtu(initial_mtu)
        .build_async()
        .context("create TUN device (need root/CAP_NET_ADMIN)")?;
    let dev = Arc::new(dev);
    info!(
        tun = %tun_name,
        local = %local_ip,
        mtu = initial_mtu,
        "dataplane up"
    );

    spawn_mtu_monitor(dev.clone(), transport.clone(), state.config.dataplane.mtu);
    spawn_route_reconciler(
        state.routes.clone(),
        tun_name.clone(),
        state.config.network.cidr,
    );

    let queue_depth = state.config.qos.queue_depth.unwrap_or(4096);
    let (egress_tx, egress_rx) = mpsc::channel::<EgressFrame>(queue_depth);
    {
        let transport = transport.clone();
        tokio::spawn(async move {
            egress_worker(egress_rx, transport, queue_depth).await;
        });
    }
    {
        let dev = dev.clone();
        let state = state.clone();
        tokio::spawn(async move {
            if let Err(e) = outbound_loop(dev, state, egress_tx).await {
                warn!(error = %e, "outbound loop stopped");
            }
        });
    }

    {
        let dev = dev.clone();
        let state = state.clone();
        let transport = transport.clone();
        tokio::spawn(async move {
            while let Some(inbound) = inbound_rx.recv().await {
                handle_inbound(&state, &dev, &transport, inbound).await;
            }
        });
    }

    Ok(())
}

fn tun_name(state: &AgentState) -> String {
    if cfg!(target_os = "macos") {
        let configured = &state.config.dataplane.tun_name;
        if configured.starts_with("utun")
            && configured.len() > 4
            && configured[4..].chars().all(|c| c.is_ascii_digit())
        {
            configured.clone()
        } else {
            // tun-rs 2.8 requires utunN (a bare "utun" fails to parse).
            "utun42".to_string()
        }
    } else {
        state.config.dataplane.tun_name.clone()
    }
}

fn local_ipv4(state: &AgentState) -> anyhow::Result<Ipv4Addr> {
    let Some(local_ip) = state.config.node.overlay_ip else {
        bail!("node.overlay_ip is required when dataplane is enabled");
    };
    match local_ip {
        std::net::IpAddr::V4(ip) => Ok(ip),
        std::net::IpAddr::V6(_) => bail!("MVP dataplane supports IPv4 overlay only"),
    }
}

fn spawn_route_reconciler(
    routes: Arc<stellaris_routing::RouteEngine>,
    tun_name: String,
    overlay: ipnet::IpNet,
) {
    tokio::spawn(async move {
        let mut installed: std::collections::BTreeSet<ipnet::IpNet> =
            std::collections::BTreeSet::new();
        let mut changed = routes.subscribe();
        loop {
            let desired: std::collections::BTreeSet<ipnet::IpNet> = routes
                .routes(stellaris_routing::RouteView::Rib)
                .into_iter()
                .map(|r| r.prefix)
                .filter(|p| !overlay.contains(&p.network()))
                .collect();

            let missing: Vec<_> = desired.difference(&installed).copied().collect();
            for prefix in missing {
                if install_os_route(prefix, &tun_name) {
                    installed.insert(prefix);
                }
            }
            let stale: Vec<_> = installed.difference(&desired).copied().collect();
            for prefix in stale {
                remove_os_route(prefix, &tun_name);
                installed.remove(&prefix);
            }
            tokio::select! {
                result = changed.changed() => {
                    if result.is_err() {
                        tokio::time::sleep(std::time::Duration::from_secs(30)).await;
                    }
                }
                _ = tokio::time::sleep(std::time::Duration::from_secs(30)) => {}
            }
        }
    });
}

#[cfg(target_os = "linux")]
fn install_os_route(prefix: ipnet::IpNet, tun: &str) -> bool {
    let status = std::process::Command::new("ip")
        .args(["route", "replace", &prefix.to_string(), "dev", tun])
        .status();
    match status {
        Ok(s) if s.success() => true,
        Ok(s) => {
            debug!(%prefix, %tun, code = ?s.code(), "ip route replace failed");
            false
        }
        Err(e) => {
            debug!(%prefix, error = %e, "failed to spawn ip route");
            false
        }
    }
}

#[cfg(target_os = "linux")]
fn remove_os_route(prefix: ipnet::IpNet, tun: &str) {
    let _ = std::process::Command::new("ip")
        .args(["route", "del", &prefix.to_string(), "dev", tun])
        .status();
}

#[cfg(target_os = "macos")]
fn install_os_route(prefix: ipnet::IpNet, tun: &str) -> bool {
    let status = std::process::Command::new("route")
        .args(["-n", "add", "-net", &prefix.to_string(), "-interface", tun])
        .status();
    matches!(status, Ok(s) if s.success())
}

#[cfg(target_os = "macos")]
fn remove_os_route(prefix: ipnet::IpNet, tun: &str) {
    let _ = std::process::Command::new("route")
        .args([
            "-n",
            "delete",
            "-net",
            &prefix.to_string(),
            "-interface",
            tun,
        ])
        .status();
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn install_os_route(_prefix: ipnet::IpNet, _tun: &str) -> bool {
    false
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn remove_os_route(_prefix: ipnet::IpNet, _tun: &str) {}

fn spawn_mtu_monitor(dev: Arc<AsyncDevice>, transport: Arc<IrohTransport>, configured_max: u16) {
    tokio::spawn(async move {
        let mut current = configured_max.min(1100);
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
            let Some(max) = transport.max_datagram_size() else {
                continue;
            };
            let target = max
                .saturating_sub(HEADER_LEN + 32)
                .min(configured_max as usize)
                .max(576) as u16;
            if target != current {
                match dev.set_mtu(target) {
                    Ok(()) => {
                        info!(from = current, to = target, "TUN MTU adjusted");
                        current = target;
                    }
                    Err(e) => debug!(error = %e, target, "failed to adjust TUN MTU"),
                }
            }
        }
    });
}

#[derive(Debug)]
struct EgressFrame {
    next: stellaris_types::NodeId,
    frame: Bytes,
    priority: i32,
    sequence: u64,
}

impl PartialEq for EgressFrame {
    fn eq(&self, other: &Self) -> bool {
        self.priority == other.priority && self.sequence == other.sequence
    }
}
impl Eq for EgressFrame {}
impl Ord for EgressFrame {
    fn cmp(&self, other: &Self) -> Ordering {
        self.priority
            .cmp(&other.priority)
            // Higher priority first; earlier sequence first for equal priority.
            .then_with(|| other.sequence.cmp(&self.sequence))
    }
}
impl PartialOrd for EgressFrame {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

async fn egress_worker(
    mut rx: mpsc::Receiver<EgressFrame>,
    transport: Arc<IrohTransport>,
    queue_depth: usize,
) {
    let mut queue = BinaryHeap::new();
    loop {
        if queue.is_empty() {
            let Some(frame) = rx.recv().await else {
                break;
            };
            queue.push(frame);
        }
        tokio::select! {
            frame = rx.recv() => {
                if let Some(frame) = frame {
                    if queue.len() < queue_depth {
                        queue.push(frame);
                    }
                } else {
                    while let Some(frame) = queue.pop() {
                        if let Err(e) = transport.send(frame.next, frame.frame).await {
                    debug!(peer = %frame.next.short(), error = %e, "egress send failed");
                }
                    }
                    break;
                }
            }
            Some(frame) = async { queue.pop() } => {
                if let Err(e) = transport.send(frame.next, frame.frame).await {
                    debug!(peer = %frame.next.short(), error = %e, "egress send failed");
                }
            }
        }
    }
}

async fn outbound_loop(
    dev: Arc<AsyncDevice>,
    state: AgentState,
    egress_tx: mpsc::Sender<EgressFrame>,
) -> anyhow::Result<()> {
    let mut buf = vec![0u8; 65535];
    let mut sequence = 0u64;
    loop {
        let n = dev.recv(&mut buf).await.context("TUN recv")?;
        if n == 0 {
            continue;
        }
        let Some((next, frame, priority)) = route_outbound_priority(&state, &buf[..n]) else {
            continue;
        };
        sequence = sequence.wrapping_add(1);
        let egress = EgressFrame {
            next,
            frame,
            priority,
            sequence,
        };
        if egress_tx.try_send(egress).is_err() {
            crate::stats::Stats::inc(&state.stats.queue_dropped);
        }
    }
}

/// Turn an outbound IP packet into (next hop, framed datagram), if a route exists.
pub fn route_outbound(
    state: &AgentState,
    packet: &[u8],
) -> Option<(stellaris_types::NodeId, Bytes)> {
    route_outbound_priority(state, packet).map(|(node, frame, _)| (node, frame))
}

fn route_outbound_priority(
    state: &AgentState,
    packet: &[u8],
) -> Option<(stellaris_types::NodeId, Bytes, i32)> {
    let info = PacketInfo::parse(packet)?;
    let local = local_ipv4(state).ok()?;
    if info.dst == std::net::IpAddr::V4(local) {
        return None;
    }
    let entry = state.routes.lookup(info.dst)?;
    let next = entry.select(flow_hash(&info))?;
    if next.node == state.node_id {
        return None;
    }

    let peer = state.peers.get(&next.node);
    let zone = peer.as_ref().and_then(|p| p.zone.as_deref());
    let direction = if state
        .config
        .dataplane
        .advertise
        .iter()
        .any(|prefix| prefix.contains(&info.src))
    {
        AclDirection::Forward
    } else {
        AclDirection::Outbound
    };
    let policy = state.policy.read().unwrap_or_else(|e| e.into_inner());
    if matches!(
        policy.check(direction, &info, Some(next.node), zone),
        AclVerdict::Deny(_)
    ) {
        crate::stats::Stats::inc(&state.stats.acl_denied);
        tracing::info!(target: "stellaris_audit", direction = "outbound", "acl denied");
        return None;
    }
    let priority = policy.qos_priority(&info);
    let header = MeshHeader::new(state.network, 64, flow_hash(&info));
    let mut frame = Vec::with_capacity(HEADER_LEN + packet.len());
    frame.extend_from_slice(&header.encode());
    frame.extend_from_slice(packet);
    if policy.apply_qos(&mut frame[HEADER_LEN..], &info) == QosVerdict::RateLimited {
        crate::stats::Stats::inc(&state.stats.qos_rate_limited);
        return None;
    }
    Some((next.node, Bytes::from(frame), priority))
}

async fn handle_inbound(
    state: &AgentState,
    dev: &Arc<AsyncDevice>,
    transport: &Arc<IrohTransport>,
    inbound: InboundPacket,
) {
    match decide_inbound(state, inbound.from, &inbound.packet) {
        InboundAction::Deliver(packet) => {
            crate::stats::Stats::inc(&state.stats.delivered);
            if let Err(e) = dev.send(&packet).await {
                debug!(error = %e, "TUN send failed");
            }
        }
        InboundAction::Forward { next, frame } => {
            crate::stats::Stats::inc(&state.stats.forwarded);
            if let Err(e) = transport.send(next, frame).await {
                debug!(peer = %next.short(), error = %e, "transit send failed");
            }
        }
        InboundAction::Drop(reason) => {
            debug!(from = %inbound.from.short(), reason, "inbound packet dropped");
        }
    }
}

/// Pure decision function for inbound packets; unit-testable without TUN.
pub fn decide_inbound(
    state: &AgentState,
    from: stellaris_types::NodeId,
    packet: &[u8],
) -> InboundAction {
    if packet.len() < HEADER_LEN {
        return InboundAction::Drop("short packet");
    }
    let Some(header) = MeshHeader::decode(packet) else {
        return InboundAction::Drop("bad header");
    };
    if header.network_hash != wire::network_hash(state.network) {
        return InboundAction::Drop("wrong network");
    }
    let payload = &packet[HEADER_LEN..];
    let Some(info) = PacketInfo::parse(payload) else {
        return InboundAction::Drop("unparsable payload");
    };
    debug!(
        from = %from.short(),
        src = %info.src,
        dst = %info.dst,
        bytes = payload.len(),
        "inbound mesh packet"
    );

    let Some(peer) = state.peers.get(&from) else {
        return InboundAction::Drop("unknown peer");
    };
    if !crate::membership::inbound_source_allowed(state, from, info.src) {
        return InboundAction::Drop("spoofed source");
    }

    let Ok(local) = local_ipv4(state) else {
        return InboundAction::Drop("no local overlay IP");
    };
    let is_local = info.dst == std::net::IpAddr::V4(local);
    let is_gateway = state
        .config
        .dataplane
        .advertise
        .iter()
        .any(|prefix| prefix.contains(&info.dst));
    let direction = if is_local {
        AclDirection::Inbound
    } else {
        AclDirection::Forward
    };
    let policy = state.policy.read().unwrap_or_else(|e| e.into_inner());
    if matches!(
        policy.check(direction, &info, Some(from), peer.zone.as_deref()),
        AclVerdict::Deny(_)
    ) {
        crate::stats::Stats::inc(&state.stats.acl_denied);
        tracing::info!(target: "stellaris_audit", direction = "inbound", "acl denied");
        return InboundAction::Drop("acl denied");
    }

    if is_local || is_gateway {
        let mut delivered = payload.to_vec();
        if policy.apply_qos(&mut delivered, &info) == QosVerdict::RateLimited {
            crate::stats::Stats::inc(&state.stats.qos_rate_limited);
            return InboundAction::Drop("qos rate limit");
        }
        return InboundAction::Deliver(delivered);
    }

    // Transit: decrement TTL and forward if a route exists.
    let mut forwarded = payload.to_vec();
    if !decrement_ttl(&mut forwarded) {
        return InboundAction::Drop("ttl expired");
    }
    if policy.apply_qos(&mut forwarded, &info) == QosVerdict::RateLimited {
        crate::stats::Stats::inc(&state.stats.qos_rate_limited);
        return InboundAction::Drop("qos rate limit");
    }
    let Some(entry) = state.routes.lookup(info.dst) else {
        return InboundAction::Drop("no transit route");
    };
    let Some(next) = entry.select(flow_hash(&info)) else {
        return InboundAction::Drop("no next hop");
    };
    if next.node == state.node_id {
        return InboundAction::Drop("transit loop");
    }
    let mut frame = Vec::with_capacity(HEADER_LEN + forwarded.len());
    frame.extend_from_slice(&header.encode());
    frame.extend_from_slice(&forwarded);
    InboundAction::Forward {
        next: next.node,
        frame: Bytes::from(frame),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use stellaris_types::{Config, NodeId};

    fn node(n: u8) -> NodeId {
        NodeId::new([n; 32])
    }

    fn state() -> AgentState {
        let dir =
            std::env::temp_dir().join(format!("stellaris-dataplane-test-{}", uuid::Uuid::now_v7()));
        std::fs::create_dir_all(&dir).unwrap();
        let toml = format!(
            r#"
[node]
name = "a"
state_dir = "{}"
overlay_ip = "10.7.0.1"

[network]
name = "demo"
cidr = "10.7.0.0/16"

[[peers]]
name = "b"
endpoint_id = "{}"
overlay_ip = "10.7.0.2"
advertised = ["192.168.50.0/24"]

[[peers]]
name = "c"
endpoint_id = "{}"
overlay_ip = "10.7.0.3"

[[routes]]
prefix = "10.8.0.0/16"
via = "c"
"#,
            dir.display(),
            hex::encode([2u8; 32]),
            hex::encode([3u8; 32])
        );
        AgentState::build(Config::from_toml(&toml).unwrap()).unwrap()
    }

    fn v4(src: [u8; 4], dst: [u8; 4], ttl: u8) -> Vec<u8> {
        let mut p = vec![0u8; 20 + 8];
        p[0] = 0x45;
        p[8] = ttl;
        p[9] = 17;
        p[12..16].copy_from_slice(&src);
        p[16..20].copy_from_slice(&dst);
        p[20..22].copy_from_slice(&1234u16.to_be_bytes());
        p[22..24].copy_from_slice(&53u16.to_be_bytes());
        p
    }

    #[test]
    fn outbound_uses_fib() {
        let state = state();
        let p = v4([10, 7, 0, 1], [10, 7, 0, 2], 64);
        let (next, frame) = route_outbound(&state, &p).unwrap();
        assert_eq!(next, node(2));
        assert_eq!(frame.len(), HEADER_LEN + p.len());
        assert_eq!(
            MeshHeader::decode(&frame).unwrap().network_hash,
            wire::network_hash(state.network)
        );
    }

    #[test]
    fn inbound_local_delivers() {
        let state = state();
        let p = v4([10, 7, 0, 2], [10, 7, 0, 1], 64);
        let mut frame = Vec::new();
        frame.extend_from_slice(&MeshHeader::new(state.network, 64, 0).encode());
        frame.extend_from_slice(&p);
        assert_eq!(
            decide_inbound(&state, node(2), &frame),
            InboundAction::Deliver(p)
        );
    }

    #[test]
    fn inbound_spoof_drops() {
        let state = state();
        let p = v4([10, 7, 0, 99], [10, 7, 0, 1], 64);
        let mut frame = Vec::new();
        frame.extend_from_slice(&MeshHeader::new(state.network, 64, 0).encode());
        frame.extend_from_slice(&p);
        assert_eq!(
            decide_inbound(&state, node(2), &frame),
            InboundAction::Drop("spoofed source")
        );
    }

    #[test]
    fn inbound_transit_forwards_and_decrements_ttl() {
        let state = state();
        let p = v4([10, 7, 0, 2], [10, 8, 0, 1], 64);
        let mut frame = Vec::new();
        frame.extend_from_slice(&MeshHeader::new(state.network, 64, 0).encode());
        frame.extend_from_slice(&p);
        match decide_inbound(&state, node(2), &frame) {
            InboundAction::Forward { next, frame } => {
                assert_eq!(next, node(3));
                let payload = &frame[HEADER_LEN..];
                assert_eq!(payload[8], 63);
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn gateway_advertised_prefix_is_delivered_to_tun() {
        let dir =
            std::env::temp_dir().join(format!("stellaris-gateway-test-{}", uuid::Uuid::now_v7()));
        std::fs::create_dir_all(&dir).unwrap();
        let toml = format!(
            r#"
[node]
name = "b"
state_dir = "{}"
overlay_ip = "10.7.0.2"

[network]
name = "demo"
cidr = "10.7.0.0/16"

[dataplane]
advertise = ["192.168.50.0/24"]

[[peers]]
name = "a"
endpoint_id = "{}"
overlay_ip = "10.7.0.1"
"#,
            dir.display(),
            hex::encode([1u8; 32])
        );
        let state = AgentState::build(Config::from_toml(&toml).unwrap()).unwrap();
        let p = v4([10, 7, 0, 1], [192, 168, 50, 3], 64);
        let mut frame = Vec::new();
        frame.extend_from_slice(&MeshHeader::new(state.network, 64, 0).encode());
        frame.extend_from_slice(&p);
        assert_eq!(
            decide_inbound(&state, node(1), &frame),
            InboundAction::Deliver(p)
        );
    }

    #[test]
    fn egress_queue_orders_by_priority() {
        let mut heap = BinaryHeap::new();
        for (priority, sequence) in [(0, 1), (10, 2), (5, 3)] {
            heap.push(EgressFrame {
                next: node(1),
                frame: Bytes::new(),
                priority,
                sequence,
            });
        }
        assert_eq!(heap.pop().unwrap().priority, 10);
        assert_eq!(heap.pop().unwrap().priority, 5);
        assert_eq!(heap.pop().unwrap().priority, 0);
    }

    #[test]
    fn acl_denies_outbound_ssh_and_qos_marks_https() {
        let dir =
            std::env::temp_dir().join(format!("stellaris-policy-test-{}", uuid::Uuid::now_v7()));
        std::fs::create_dir_all(&dir).unwrap();
        let toml = format!(
            r#"
[node]
name = "a"
state_dir = "{}"
overlay_ip = "10.7.0.1"

[network]
name = "demo"
cidr = "10.7.0.0/16"

[acl]
[[acl.rules]]
name = "deny-ssh"
action = "deny"
direction = "outbound"
protocol = 6
dst_port = 22

[qos]
enabled = true
[[qos.classes]]
name = "https"
dscp = 46
dst_port = 443

[[peers]]
name = "b"
endpoint_id = "{}"
overlay_ip = "10.7.0.2"
"#,
            dir.display(),
            hex::encode([2u8; 32])
        );
        let state = AgentState::build(Config::from_toml(&toml).unwrap()).unwrap();

        let ssh = v4([10, 7, 0, 1], [10, 7, 0, 2], 64);
        // v4() uses port 53; rewrite to TCP/22.
        let mut ssh = ssh;
        ssh[9] = 6;
        ssh[22..24].copy_from_slice(&22u16.to_be_bytes());
        assert!(route_outbound(&state, &ssh).is_none());

        let mut https = v4([10, 7, 0, 1], [10, 7, 0, 2], 64);
        https[9] = 6;
        https[22..24].copy_from_slice(&443u16.to_be_bytes());
        let (_, frame) = route_outbound(&state, &https).unwrap();
        assert_eq!(wire::dscp(&frame[HEADER_LEN..]), Some(46));
    }

    #[test]
    fn acl_denies_inbound() {
        let dir =
            std::env::temp_dir().join(format!("stellaris-policy-in-test-{}", uuid::Uuid::now_v7()));
        std::fs::create_dir_all(&dir).unwrap();
        let toml = format!(
            r#"
[node]
name = "a"
state_dir = "{}"
overlay_ip = "10.7.0.1"

[network]
name = "demo"
cidr = "10.7.0.0/16"

[acl]
[[acl.rules]]
name = "deny-http"
action = "deny"
direction = "inbound"
protocol = 6
dst_port = 80

[[peers]]
name = "b"
endpoint_id = "{}"
overlay_ip = "10.7.0.2"
"#,
            dir.display(),
            hex::encode([2u8; 32])
        );
        let state = AgentState::build(Config::from_toml(&toml).unwrap()).unwrap();
        let mut p = v4([10, 7, 0, 2], [10, 7, 0, 1], 64);
        p[9] = 6;
        p[22..24].copy_from_slice(&80u16.to_be_bytes());
        let mut frame = MeshHeader::new(state.network, 64, 0).encode().to_vec();
        frame.extend_from_slice(&p);
        assert_eq!(
            decide_inbound(&state, node(2), &frame),
            InboundAction::Drop("acl denied")
        );
    }

    #[test]
    fn advertised_source_from_gateway_is_allowed() {
        let state = state();
        // c (192.168.50.3) is behind peer b; b relays the reply to a.
        let p = v4([192, 168, 50, 3], [10, 7, 0, 1], 64);
        let mut frame = Vec::new();
        frame.extend_from_slice(&MeshHeader::new(state.network, 64, 0).encode());
        frame.extend_from_slice(&p);
        assert_eq!(
            decide_inbound(&state, node(2), &frame),
            InboundAction::Deliver(p)
        );
    }
}
