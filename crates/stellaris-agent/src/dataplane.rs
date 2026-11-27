//! TUN dataplane: IP packets over iroh datagrams.

use std::cmp::Ordering;
use std::collections::BinaryHeap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};

use anyhow::{Context, bail};
use bytes::Bytes;
use tokio::sync::mpsc;
use tracing::{debug, info, warn};
use tun_rs::{AsyncDevice, DeviceBuilder};

use crate::policy::{AclVerdict, QosVerdict};
use crate::transport::{InboundPacket, IrohTransport};
use crate::wire::{HEADER_LEN, MeshHeader, PacketInfo, decrement_ttl, flow_hash};
use crate::{AgentState, wire};
use stellaris_fib::FibEntry;
use stellaris_types::AclDirection;

/// Handle to the live TUN device for in-process address changes.
#[derive(Clone)]
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub struct DataplaneHandle {
    tun_name: String,
    prefix_len: u8,
    current: IpAddr,
}

impl DataplaneHandle {
    pub fn new(tun_name: String, prefix_len: u8, current: IpAddr) -> Self {
        Self {
            tun_name,
            prefix_len,
            current,
        }
    }

    pub fn current(&self) -> IpAddr {
        self.current
    }

    /// Move the TUN interface to `new_ip` in place. Existing sockets keep
    /// running; in-flight flows see a brief outage.
    pub fn reconfigure(&mut self, new_ip: IpAddr) -> anyhow::Result<()> {
        if new_ip == self.current {
            return Ok(());
        }
        if new_ip.is_ipv4() != self.current.is_ipv4() {
            bail!("changing the address family of a live TUN is not supported");
        }
        let old = self.current;
        if let Err(error) = self.set_address(new_ip) {
            let _ = self.set_address(old);
            return Err(error);
        }
        self.current = new_ip;
        Ok(())
    }

    fn set_address(&self, ip: IpAddr) -> anyhow::Result<()> {
        #[cfg(target_os = "linux")]
        {
            let cidr = format!("{ip}/{}", self.prefix_len);
            let v6 = ip.is_ipv6();
            let flush: &[&str] = if v6 {
                &[
                    "-6",
                    "addr",
                    "flush",
                    "dev",
                    &self.tun_name,
                    "scope",
                    "global",
                ]
            } else {
                &["addr", "flush", "dev", &self.tun_name, "scope", "global"]
            };
            run_ip(flush)?;
            let add: &[&str] = if v6 {
                &["-6", "addr", "add", &cidr, "dev", &self.tun_name, "nodad"]
            } else {
                &["addr", "add", &cidr, "dev", &self.tun_name]
            };
            run_ip(add)?;
            run_ip(&["link", "set", &self.tun_name, "up"])?;
            flush_route_cache();
            Ok(())
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = ip;
            bail!("live overlay reconfiguration is implemented on Linux only")
        }
    }
}

#[cfg(target_os = "linux")]
fn run_ip(args: &[&str]) -> anyhow::Result<()> {
    let output = std::process::Command::new("ip")
        .args(args)
        .output()
        .with_context(|| format!("run ip {args:?}"))?;
    if !output.status.success() {
        bail!(
            "ip {args:?} failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(())
}

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
    let local_ip = wait_for_overlay(&state).await?;
    let tun_name = tun_name(&state);
    if !state.config.dataplane.advertise.is_empty() {
        crate::gateway::ensure_forwarding()?;
        if state.config.dataplane.nat {
            if matches!(state.config.network.cidr, ipnet::IpNet::V4(_)) {
                crate::gateway::ensure_nat(&state.config.network.cidr.to_string(), &tun_name)?;
                info!("subnet gateway NAT44 enabled");
            } else {
                crate::gateway::ensure_nat_v6(&state.config.network.cidr.to_string(), &tun_name)?;
                info!("subnet gateway NAT66 enabled");
            }
        }
        info!(
            prefixes = ?state.config.dataplane.advertise,
            "subnet gateway forwarding enabled"
        );
    }
    let prefix_len = state.config.network.cidr.prefix_len();
    // IPv6 requires a minimum MTU of 1280; IPv4 uses a conservative initial value.
    let initial_mtu = if local_ip.is_ipv6() {
        state.config.dataplane.mtu.max(1280)
    } else {
        state.config.dataplane.mtu.min(1100)
    };
    let builder = DeviceBuilder::new().name(tun_name.clone()).mtu(initial_mtu);
    let dev = match local_ip {
        IpAddr::V4(ip) => builder
            .ipv4(ip, prefix_len, None)
            .build_async()
            .context("create TUN device (need root/CAP_NET_ADMIN)")?,
        IpAddr::V6(ip) => {
            let dev = builder
                .build_async()
                .context("create TUN device (need root/CAP_NET_ADMIN)")?;
            configure_ipv6(&tun_name, ip, prefix_len)?;
            dev
        }
    };
    let dev = Arc::new(dev);
    *state
        .dataplane_handle
        .lock()
        .unwrap_or_else(|e| e.into_inner()) =
        Some(DataplaneHandle::new(tun_name.clone(), prefix_len, local_ip));
    info!(
        tun = %tun_name,
        local = %local_ip,
        mtu = initial_mtu,
        "dataplane up"
    );

    spawn_mtu_monitor(
        dev.clone(),
        transport.clone(),
        state.config.dataplane.mtu,
        state.local_overlay().is_some_and(|ip| ip.is_ipv6()),
    );
    spawn_route_reconciler(
        state.routes.clone(),
        tun_name.clone(),
        state.config.network.cidr,
        state.config.dataplane.allow_default_route,
        state.config.dataplane.replace_existing_routes,
    );

    let queue_depth = state.config.qos.queue_depth.unwrap_or(4096);
    let (egress_tx, egress_rx) = mpsc::channel::<EgressFrame>(queue_depth);
    {
        let transport = transport.clone();
        let per_priority = state.config.qos.queue_depth_per_priority;
        let queue_bytes = state.config.qos.queue_bytes;
        let queue_bytes_per_priority = state.config.qos.queue_bytes_per_priority;
        let class_caps: Vec<(Option<usize>, Option<usize>)> = state
            .config
            .qos
            .classes
            .iter()
            .map(|class| (class.queue_depth, class.queue_bytes))
            .collect();
        let stats = state.stats.clone();
        tokio::spawn(async move {
            egress_worker(
                egress_rx,
                transport,
                queue_depth,
                per_priority,
                queue_bytes,
                queue_bytes_per_priority,
                class_caps,
                stats,
            )
            .await;
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

#[cfg(target_os = "linux")]
fn configure_ipv6(tun: &str, ip: std::net::Ipv6Addr, prefix: u8) -> anyhow::Result<()> {
    let status = std::process::Command::new("ip")
        .args([
            "-6",
            "addr",
            "replace",
            &format!("{ip}/{prefix}"),
            "dev",
            tun,
        ])
        .status()?;
    if !status.success() {
        anyhow::bail!("ip -6 addr replace {ip}/{prefix} dev {tun} failed");
    }
    let status = std::process::Command::new("ip")
        .args(["link", "set", tun, "up"])
        .status()?;
    if !status.success() {
        anyhow::bail!("ip link set {tun} up failed");
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn configure_ipv6(tun: &str, ip: std::net::Ipv6Addr, prefix: u8) -> anyhow::Result<()> {
    let status = std::process::Command::new("ifconfig")
        .args([tun, "inet6", &format!("{ip}/{prefix}"), "up"])
        .status()?;
    if !status.success() {
        anyhow::bail!("ifconfig {tun} inet6 failed");
    }
    Ok(())
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn configure_ipv6(_tun: &str, _ip: std::net::Ipv6Addr, _prefix: u8) -> anyhow::Result<()> {
    anyhow::bail!("IPv6 TUN is supported on Linux/macOS only")
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

async fn wait_for_overlay(state: &AgentState) -> anyhow::Result<IpAddr> {
    if let Some(ip) = state.local_overlay() {
        return Ok(ip);
    }
    if state.config.node.ipam != stellaris_types::IpamMode::Auto {
        return local_ip(state);
    }
    // The control client runs concurrently and stores the credential before
    // the data plane starts.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(120);
    while std::time::Instant::now() < deadline {
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        if let Some(ip) = state.local_overlay() {
            return Ok(ip);
        }
    }
    anyhow::bail!("timed out waiting for a controller-allocated overlay address")
}

fn local_ip(state: &AgentState) -> anyhow::Result<IpAddr> {
    state.local_overlay().ok_or_else(|| {
        anyhow::anyhow!(
            "no overlay address yet: set node.overlay_ip or use node.ipam = \"auto\" with a controller"
        )
    })
}

fn spawn_route_reconciler(
    routes: Arc<stellaris_routing::RouteEngine>,
    tun_name: String,
    overlay: ipnet::IpNet,
    allow_default_route: bool,
    replace_existing_routes: bool,
) {
    let guard = Arc::new(InstalledRoutes {
        tun: tun_name.clone(),
        prefixes: Mutex::new(std::collections::BTreeSet::new()),
    });
    tokio::spawn(async move {
        let mut changed = routes.subscribe();
        loop {
            let desired: std::collections::BTreeSet<ipnet::IpNet> = routes
                .routes(stellaris_routing::RouteView::Rib)
                .into_iter()
                .map(|r| r.prefix)
                .filter(|p| !overlay.contains(&p.network()))
                .filter(|p| {
                    if is_default_prefix(p) && !allow_default_route {
                        warn!(%p, "refusing to install a default route without dataplane.allow_default_route");
                        false
                    } else {
                        true
                    }
                })
                .collect();

            let installed = {
                let guard = guard.prefixes.lock().unwrap_or_else(|e| e.into_inner());
                guard.clone()
            };
            for prefix in desired.difference(&installed).copied().collect::<Vec<_>>() {
                match route_state(prefix, &tun_name) {
                    RouteState::Free | RouteState::Ours => {
                        if install_os_route(prefix, &tun_name) {
                            guard
                                .prefixes
                                .lock()
                                .unwrap_or_else(|e| e.into_inner())
                                .insert(prefix);
                        }
                    }
                    RouteState::Foreign if replace_existing_routes => {
                        warn!(%prefix, "replacing a foreign OS route (dataplane.replace_existing_routes)");
                        if install_os_route(prefix, &tun_name) {
                            guard
                                .prefixes
                                .lock()
                                .unwrap_or_else(|e| e.into_inner())
                                .insert(prefix);
                        }
                    }
                    RouteState::Foreign => {
                        warn!(%prefix, "OS route conflict, skipping (see dataplane.replace_existing_routes)");
                    }
                }
            }
            for prefix in installed.difference(&desired).copied().collect::<Vec<_>>() {
                remove_os_route(prefix, &tun_name);
                guard
                    .prefixes
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .remove(&prefix);
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

/// Routes we install are tagged with a private protocol number so that route
/// ownership can be checked and only our routes are removed.
#[cfg(target_os = "linux")]
const ROUTE_PROTO: &str = "240";

#[allow(dead_code)] // variants are only constructed by the Linux route probe
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RouteState {
    /// No route for this prefix exists.
    Free,
    /// The existing route was installed by us (proto tag + TUN device).
    Ours,
    /// Somebody else owns this prefix.
    Foreign,
}

fn is_default_prefix(prefix: &ipnet::IpNet) -> bool {
    prefix.prefix_len() == 0
}

/// Parse `ip route show <prefix>` output into an ownership decision.
#[cfg(target_os = "linux")]
fn route_state_from(tun: &str, output: &str) -> RouteState {
    let mut seen = false;
    let ours = format!("proto {ROUTE_PROTO}");
    let dev = format!("dev {tun}");
    for line in output.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        seen = true;
        if line.contains(&dev) && line.contains(&ours) {
            return RouteState::Ours;
        }
    }
    if seen {
        RouteState::Foreign
    } else {
        RouteState::Free
    }
}

#[cfg(target_os = "linux")]
fn route_state(prefix: ipnet::IpNet, tun: &str) -> RouteState {
    let mut command = std::process::Command::new("ip");
    if matches!(prefix, ipnet::IpNet::V6(_)) {
        command.arg("-6");
    }
    let output = command
        .args(["route", "show", &prefix.to_string()])
        .output();
    match output {
        Ok(out) if out.status.success() => {
            route_state_from(tun, &String::from_utf8_lossy(&out.stdout))
        }
        Ok(out) => {
            debug!(%prefix, code = ?out.status.code(), "ip route show failed; skipping");
            RouteState::Foreign
        }
        Err(e) => {
            debug!(%prefix, error = %e, "failed to spawn ip route show; skipping");
            RouteState::Foreign
        }
    }
}

#[cfg(not(target_os = "linux"))]
fn route_state(_prefix: ipnet::IpNet, _tun: &str) -> RouteState {
    // Ownership tagging is Linux-only; other platforms keep the previous
    // behaviour and only rely on the device when removing.
    RouteState::Free
}

/// Owns installed OS routes and removes them when the dataplane shuts down.
struct InstalledRoutes {
    tun: String,
    prefixes: Mutex<std::collections::BTreeSet<ipnet::IpNet>>,
}

impl Drop for InstalledRoutes {
    fn drop(&mut self) {
        let prefixes = self.prefixes.lock().unwrap_or_else(|e| e.into_inner());
        for prefix in prefixes.iter() {
            remove_os_route(*prefix, &self.tun);
        }
    }
}

#[cfg(target_os = "linux")]
fn install_os_route(prefix: ipnet::IpNet, tun: &str) -> bool {
    let mut command = std::process::Command::new("ip");
    if matches!(prefix, ipnet::IpNet::V6(_)) {
        command.arg("-6");
    }
    let status = command
        .args([
            "route",
            "replace",
            &prefix.to_string(),
            "dev",
            tun,
            "proto",
            ROUTE_PROTO,
        ])
        .status();
    match status {
        Ok(s) if s.success() => true,
        Ok(s) => {
            warn!(%prefix, %tun, code = ?s.code(), "ip route replace failed");
            false
        }
        Err(e) => {
            warn!(%prefix, error = %e, "failed to spawn ip route");
            false
        }
    }
}

#[cfg(target_os = "linux")]
fn remove_os_route(prefix: ipnet::IpNet, tun: &str) {
    let mut command = std::process::Command::new("ip");
    if matches!(prefix, ipnet::IpNet::V6(_)) {
        command.arg("-6");
    }
    let _ = command
        .args([
            "route",
            "del",
            &prefix.to_string(),
            "dev",
            tun,
            "proto",
            ROUTE_PROTO,
        ])
        .status();
}

#[cfg(target_os = "macos")]
fn install_os_route(prefix: ipnet::IpNet, tun: &str) -> bool {
    let family = if matches!(prefix, ipnet::IpNet::V6(_)) {
        "-inet6"
    } else {
        "-inet"
    };
    let status = std::process::Command::new("route")
        .args([
            "-n",
            "add",
            family,
            "-net",
            &prefix.to_string(),
            "-interface",
            tun,
        ])
        .status();
    matches!(status, Ok(s) if s.success())
}

#[cfg(target_os = "macos")]
fn remove_os_route(prefix: ipnet::IpNet, tun: &str) {
    let family = if matches!(prefix, ipnet::IpNet::V6(_)) {
        "-inet6"
    } else {
        "-inet"
    };
    let _ = std::process::Command::new("route")
        .args([
            "-n",
            "delete",
            family,
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

/// Effective TUN MTU for a given underlay datagram limit.
///
/// IPv6 links must carry at least 1280-byte packets; shrinking the TUN below
/// that would silently disable IPv6, so we clamp and keep generating PTBs via
/// the path-MTU logic instead.
fn effective_mtu(configured_max: u16, max_datagram: usize, ipv6: bool) -> u16 {
    let floor = if ipv6 { 1280 } else { 576 };
    max_datagram
        .saturating_sub(HEADER_LEN + 32)
        .min(configured_max as usize)
        .max(floor as usize) as u16
}

#[cfg(target_os = "linux")]
fn flush_route_cache() {
    let _ = std::process::Command::new("ip")
        .args(["route", "flush", "cache"])
        .status();
}

#[cfg(not(target_os = "linux"))]
fn flush_route_cache() {}

fn spawn_mtu_monitor(
    dev: Arc<AsyncDevice>,
    transport: Arc<IrohTransport>,
    configured_max: u16,
    ipv6: bool,
) {
    tokio::spawn(async move {
        let mut current = configured_max.min(1100);
        let mut warned = false;
        // QUIC's initial datagram size is conservative and can dip to ~1200
        // when a path is revalidated. Lowering the TUN MTU immediately makes it
        // flap and leaves stale PMTU entries in the kernel route cache, so only
        // accept a smaller value after it has persisted for a minute.
        const LOWER_AFTER_SAMPLES: u32 = 30;
        let mut low_streak = 0u32;
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
            let Some(max) = transport.max_datagram_size() else {
                continue;
            };
            let target = effective_mtu(configured_max, max, ipv6);
            if ipv6 && max < 1280 + HEADER_LEN + 32 && !warned {
                warned = true;
                warn!(
                    underlay_max = max,
                    "IPv6 requires at least 1280-byte packets; TUN MTU held at 1280 and oversized packets rely on PTB/MSS"
                );
            }
            if target < current {
                low_streak = low_streak.saturating_add(1);
                if low_streak < LOWER_AFTER_SAMPLES {
                    continue;
                }
            } else {
                low_streak = 0;
            }
            if target != current {
                let raised = target > current;
                match dev.set_mtu(target) {
                    Ok(()) => {
                        info!(from = current, to = target, "TUN MTU adjusted");
                        current = target;
                        if raised {
                            // PMTUD may have cached the old, smaller MTU.
                            flush_route_cache();
                        }
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
    class: Option<usize>,
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

#[allow(clippy::too_many_arguments)]
async fn egress_worker(
    mut rx: mpsc::Receiver<EgressFrame>,
    transport: Arc<IrohTransport>,
    queue_depth: usize,
    per_priority_depth: Option<usize>,
    queue_bytes: Option<usize>,
    queue_bytes_per_priority: Option<usize>,
    class_caps: Vec<(Option<usize>, Option<usize>)>,
    stats: Arc<crate::stats::Stats>,
) {
    let mut queue = BinaryHeap::new();
    let mut by_priority: std::collections::BTreeMap<i32, usize> = std::collections::BTreeMap::new();
    let mut bytes_by_priority: std::collections::BTreeMap<i32, usize> =
        std::collections::BTreeMap::new();
    let mut by_class: std::collections::BTreeMap<usize, usize> = std::collections::BTreeMap::new();
    let mut bytes_by_class: std::collections::BTreeMap<usize, usize> =
        std::collections::BTreeMap::new();
    let mut queued_bytes = 0usize;
    let push = |queue: &mut BinaryHeap<EgressFrame>,
                counts: &mut std::collections::BTreeMap<i32, usize>,
                byte_counts: &mut std::collections::BTreeMap<i32, usize>,
                class_counts: &mut std::collections::BTreeMap<usize, usize>,
                class_bytes: &mut std::collections::BTreeMap<usize, usize>,
                queued_bytes: &mut usize,
                frame: EgressFrame| {
        let current = counts.get(&frame.priority).copied().unwrap_or(0);
        let full_priority = per_priority_depth.is_some_and(|cap| current >= cap);
        let current_bytes = byte_counts.get(&frame.priority).copied().unwrap_or(0);
        let frame_bytes = frame.frame.len();
        let full_priority_bytes =
            queue_bytes_per_priority.is_some_and(|cap| current_bytes + frame_bytes > cap);
        let full_bytes = queue_bytes.is_some_and(|cap| *queued_bytes + frame_bytes > cap);
        let class_full = frame.class.is_some_and(|class| {
            class_caps.get(class).is_some_and(|(depth, bytes)| {
                depth.is_some_and(|cap| class_counts.get(&class).copied().unwrap_or(0) >= cap)
                    || bytes.is_some_and(|cap| {
                        class_bytes.get(&class).copied().unwrap_or(0) + frame_bytes > cap
                    })
            })
        });
        if queue.len() >= queue_depth
            || full_priority
            || full_priority_bytes
            || full_bytes
            || class_full
        {
            crate::stats::Stats::inc(&stats.queue_dropped);
            return;
        }
        *counts.entry(frame.priority).or_default() += 1;
        *byte_counts.entry(frame.priority).or_default() += frame_bytes;
        if let Some(class) = frame.class {
            *class_counts.entry(class).or_default() += 1;
            *class_bytes.entry(class).or_default() += frame_bytes;
        }
        *queued_bytes += frame_bytes;
        queue.push(frame);
    };
    loop {
        if queue.is_empty() {
            let Some(frame) = rx.recv().await else {
                break;
            };
            push(
                &mut queue,
                &mut by_priority,
                &mut bytes_by_priority,
                &mut by_class,
                &mut bytes_by_class,
                &mut queued_bytes,
                frame,
            );
        }
        tokio::select! {
            frame = rx.recv() => {
                if let Some(frame) = frame {
                    push(
                &mut queue,
                &mut by_priority,
                &mut bytes_by_priority,
                &mut by_class,
                &mut bytes_by_class,
                &mut queued_bytes,
                frame,
            );
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
                if let Some(count) = by_priority.get_mut(&frame.priority) {
                    *count = count.saturating_sub(1);
                }
                if let Some(bytes) = bytes_by_priority.get_mut(&frame.priority) {
                    *bytes = bytes.saturating_sub(frame.frame.len());
                }
                if let Some(class) = frame.class {
                    if let Some(count) = by_class.get_mut(&class) {
                        *count = count.saturating_sub(1);
                    }
                    if let Some(bytes) = bytes_by_class.get_mut(&class) {
                        *bytes = bytes.saturating_sub(frame.frame.len());
                    }
                }
                queued_bytes = queued_bytes.saturating_sub(frame.frame.len());
                if let Err(e) = transport.send(frame.next, frame.frame).await {
                    debug!(peer = %frame.next.short(), error = %e, "egress send failed");
                }
            }
        }
    }
}

fn outbound_ptb(
    state: &AgentState,
    packet: &[u8],
    next: stellaris_types::NodeId,
) -> Option<Vec<u8>> {
    let v6 = packet.first().is_some_and(|b| b >> 4 == 6);
    let df = packet.len() >= 8 && packet[0] >> 4 == 4 && packet[6] & 0x40 != 0;
    if !v6 && !df {
        return None;
    }
    let peer = state.peers.get(&next)?;
    let mtu = path_mtu(state, Some(&peer), packet);
    if packet.len() <= mtu as usize {
        return None;
    }
    // Present the PTB as coming from the next-hop overlay address, as a
    // downstream router would. Writing it with our own source address makes
    // the kernel discard the self-generated ICMP error.
    wire::icmp_too_big(packet, mtu, peer.overlay_ip)
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
        let Some((next, frame, priority, class)) = route_outbound_priority(&state, &buf[..n])
        else {
            continue;
        };
        if let Some(error) = outbound_ptb(&state, &buf[..n], next) {
            if let Err(e) = dev.send(&error).await {
                debug!(error = %e, "TUN PTB send failed");
            }
            continue;
        }
        sequence = sequence.wrapping_add(1);
        let egress = EgressFrame {
            next,
            frame,
            priority,
            class,
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
    route_outbound_priority(state, packet).map(|(node, frame, _, _)| (node, frame))
}

fn route_outbound_priority(
    state: &AgentState,
    packet: &[u8],
) -> Option<(stellaris_types::NodeId, Bytes, i32, Option<usize>)> {
    let info = PacketInfo::parse(packet)?;
    let local = state.local_overlay()?;
    if info.dst == local {
        return None;
    }
    let entry = state.routes.lookup(info.dst)?;
    let next = select_connected(state, &entry, flow_hash(&info))?;
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
    if let AclVerdict::Deny(rule) = policy.check(direction, &info, Some(next.node), zone) {
        crate::stats::Stats::inc(&state.stats.acl_denied);
        tracing::warn!(
            target: "stellaris_audit",
            action = "deny",
            direction = "outbound",
            rule = %rule,
            src = %info.src,
            dst = %info.dst,
            protocol = info.protocol,
            peer = %next.node.short(),
            "acl denied"
        );
        return None;
    }
    let priority = policy.qos_priority(&info);
    let class = policy.qos_class_index(&info);
    let mut packet = packet.to_vec();
    let mtu = path_mtu(state, peer.as_ref(), &packet);
    wire::clamp_tcp_mss(&mut packet, mtu);
    let header = MeshHeader::new(state.network, 64, flow_hash(&info));
    let mut frame = Vec::with_capacity(HEADER_LEN + packet.len());
    frame.extend_from_slice(&header.encode());
    frame.extend_from_slice(&packet);
    if policy.apply_qos(&mut frame[HEADER_LEN..], &info) == QosVerdict::RateLimited {
        crate::stats::Stats::inc(&state.stats.qos_rate_limited);
        return None;
    }
    Some((next.node, Bytes::from(frame), priority, class))
}

async fn handle_inbound(
    state: &AgentState,
    dev: &Arc<AsyncDevice>,
    transport: &Arc<IrohTransport>,
    inbound: InboundPacket,
) {
    // Reassemble fragments before ACL/transit decisions so rules see the
    // complete L4 header.
    let framed = {
        let payload = match inbound.packet.get(HEADER_LEN..) {
            Some(payload) => payload,
            None => {
                crate::stats::Stats::inc(&state.stats.frag_dropped);
                return;
            }
        };
        let outcome = {
            let mut reassembly = state.reassembly.lock().unwrap_or_else(|e| e.into_inner());
            reassembly.process(inbound.from, payload, std::time::Instant::now())
        };
        match outcome {
            crate::reassembly::Outcome::Pass => inbound.packet.clone(),
            crate::reassembly::Outcome::Buffered => return,
            crate::reassembly::Outcome::Dropped(reason) => {
                crate::stats::Stats::inc(&state.stats.frag_dropped);
                debug!(from = %inbound.from.short(), reason, "fragment dropped");
                return;
            }
            crate::reassembly::Outcome::Complete(inner) => {
                crate::stats::Stats::inc(&state.stats.frag_reassembled);
                let flow = PacketInfo::parse(&inner).map_or(0, |info| flow_hash(&info));
                let header = MeshHeader::new(state.network, 64, flow);
                let mut frame = Vec::with_capacity(HEADER_LEN + inner.len());
                frame.extend_from_slice(&header.encode());
                frame.extend_from_slice(&inner);
                bytes::Bytes::from(frame)
            }
        }
    };
    match decide_inbound(state, inbound.from, &framed) {
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
            match reason {
                "acl denied" => {
                    // `inbound.packet` still carries the mesh header; ICMP
                    // must quote the inner IP packet only.
                    let original = inbound
                        .packet
                        .get(HEADER_LEN..)
                        .unwrap_or_default()
                        .to_vec();
                    if state.config.acl.deny_action == stellaris_types::AclDenyAction::Reject
                        && let Some(local) = state.local_overlay()
                        && let Some(icmp) = wire::icmp_admin_prohibited(&original, local)
                        && let Some(info) = PacketInfo::parse(&original)
                    {
                        let header = MeshHeader::new(state.network, 64, flow_hash(&info));
                        let mut frame = Vec::with_capacity(HEADER_LEN + icmp.len());
                        frame.extend_from_slice(&header.encode());
                        frame.extend_from_slice(&icmp);
                        match transport
                            .send(inbound.from, bytes::Bytes::from(frame))
                            .await
                        {
                            Ok(()) => {
                                crate::stats::Stats::inc(&state.stats.acl_rejected);
                                tracing::info!(
                                    target: "stellaris_audit",
                                    action = "reject",
                                    from = %inbound.from.short(),
                                    src = %info.src,
                                    dst = %info.dst,
                                    protocol = info.protocol,
                                    "acl rejected with icmp administratively prohibited"
                                );
                            }
                            Err(e) => debug!(error = %e, "failed to send acl reject icmp"),
                        }
                    }
                }
                "spoofed source" => crate::stats::Stats::inc(&state.stats.spoof_dropped),
                _ => {}
            }
            debug!(from = %inbound.from.short(), reason, "inbound packet dropped");
        }
    }
}

fn select_connected<'a>(
    state: &AgentState,
    entry: &'a FibEntry,
    flow: u32,
) -> Option<&'a stellaris_fib::FibNextHop> {
    entry.select_where(flow, |node| {
        state.peers.get(&node).is_some_and(|peer| peer.connected)
    })
}

fn path_mtu(state: &AgentState, peer: Option<&crate::PeerState>, packet: &[u8]) -> u16 {
    let v6 = packet.first().is_some_and(|b| b >> 4 == 6);
    // When no peer path MTU is known yet, use the configured overlay MTU.
    // The old hard-coded 1100 fallback caused bogus PTB values during startup.
    let configured = if v6 {
        state.config.dataplane.mtu.max(1280)
    } else {
        state.config.dataplane.mtu
    };
    let path = peer
        .and_then(|peer| peer.mtu)
        .map(|mtu| mtu.saturating_sub(HEADER_LEN as u16));
    // Do not clamp the *usable* path MTU to IPv6's 1280 floor. If the
    // underlay cannot carry 1296 bytes, holding 1280 here makes the PTB path
    // unreachable and clamps MSS to a segment that transport will drop.
    path.map_or(configured, |mtu| configured.min(mtu)).max(576)
}

fn too_big_action(
    state: &AgentState,
    packet: &[u8],
    peer: Option<&crate::PeerState>,
) -> Option<InboundAction> {
    let mtu = path_mtu(state, peer, packet);
    if packet.len() <= mtu as usize {
        return None;
    }
    let local = state.local_overlay()?;
    let mut error = wire::icmp_too_big(packet, mtu, local)?;
    let error_info = PacketInfo::parse(&error)?;
    let entry = state.routes.lookup(error_info.dst)?;
    let next = select_connected(state, &entry, flow_hash(&error_info))?;
    if next.node == state.node_id {
        return None;
    }
    let header = MeshHeader::new(state.network, 64, flow_hash(&error_info));
    let mut frame = Vec::with_capacity(HEADER_LEN + error.len());
    frame.extend_from_slice(&header.encode());
    frame.append(&mut error);
    Some(InboundAction::Forward {
        next: next.node,
        frame: Bytes::from(frame),
    })
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
    if let Some(action) = too_big_action(state, payload, state.peers.get(&from).as_ref()) {
        return action;
    }

    let Some(local) = state.local_overlay() else {
        return InboundAction::Drop("no local overlay IP");
    };
    let is_local = info.dst == local;
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
    if let AclVerdict::Deny(rule) = policy.check(direction, &info, Some(from), peer.zone.as_deref())
    {
        crate::stats::Stats::inc(&state.stats.acl_denied);
        tracing::warn!(
            target: "stellaris_audit",
            action = "deny",
            direction = "inbound",
            rule = %rule,
            src = %info.src,
            dst = %info.dst,
            protocol = info.protocol,
            from = %from.short(),
            "acl denied"
        );
        return InboundAction::Drop("acl denied");
    }

    if is_local || is_gateway {
        let mut delivered = payload.to_vec();
        let sender = state.peers.get(&from);
        let mtu = path_mtu(state, sender.as_ref(), &delivered);
        wire::clamp_tcp_mss(&mut delivered, mtu);
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
    let Some(next) = select_connected(state, &entry, flow_hash(&info)) else {
        return InboundAction::Drop("no next hop");
    };
    if next.node == state.node_id {
        return InboundAction::Drop("transit loop");
    }
    let next_peer = state.peers.get(&next.node);
    let mtu = path_mtu(state, next_peer.as_ref(), &forwarded);
    if forwarded.len() > mtu as usize {
        // Transit is the only place that can tell the source about a smaller
        // next hop. Quote the original packet and send the PTB back to the
        // previous hop; do not silently hand an oversized frame to transport.
        if let Some(local) = state.local_overlay()
            && let Some(error) = wire::icmp_too_big(payload, mtu, local)
            && let Some(error_info) = PacketInfo::parse(&error)
        {
            let header = MeshHeader::new(state.network, 64, flow_hash(&error_info));
            let mut frame = Vec::with_capacity(HEADER_LEN + error.len());
            frame.extend_from_slice(&header.encode());
            frame.extend_from_slice(&error);
            return InboundAction::Forward {
                next: from,
                frame: Bytes::from(frame),
            };
        }
        return InboundAction::Drop("transit packet exceeds next-hop mtu");
    }
    wire::clamp_tcp_mss(&mut forwarded, mtu);
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
        let state = AgentState::build(Config::from_toml(&toml).unwrap()).unwrap();
        mark_all_connected(&state);
        state
    }

    fn mark_all_connected(state: &AgentState) {
        for peer in state.peers.list() {
            state.peers.mark(
                &peer.node_id,
                true,
                Some("direct".into()),
                Some(1),
                Some(1400),
                Some("127.0.0.1:1".into()),
                1,
            );
        }
    }

    fn state_v6() -> AgentState {
        let dir =
            std::env::temp_dir().join(format!("stellaris-dataplane-v6-{}", uuid::Uuid::now_v7()));
        std::fs::create_dir_all(&dir).unwrap();
        let toml = format!(
            r#"
[node]
name = "a"
state_dir = "{}"
overlay_ip = "fd00::1"

[network]
name = "demo6"
cidr = "fd00::/64"

[[peers]]
name = "b"
endpoint_id = "{}"
overlay_ip = "fd00::2"
"#,
            dir.display(),
            hex::encode([2u8; 32]),
        );
        let state = AgentState::build(Config::from_toml(&toml).unwrap()).unwrap();
        mark_all_connected(&state);
        state
    }

    fn v6(src: [u8; 16], dst: [u8; 16], hop: u8) -> Vec<u8> {
        let mut p = vec![0u8; 40 + 8];
        p[0] = 0x60;
        p[4..6].copy_from_slice(&8u16.to_be_bytes());
        p[6] = 17;
        p[7] = hop;
        p[8..24].copy_from_slice(&src);
        p[24..40].copy_from_slice(&dst);
        p[40..42].copy_from_slice(&1234u16.to_be_bytes());
        p[42..44].copy_from_slice(&53u16.to_be_bytes());
        p
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
    fn peer_advertised_prefix_is_routable() {
        let state = state();
        let p = v4([10, 7, 0, 1], [192, 168, 50, 10], 64);
        let (next, _) = route_outbound(&state, &p).unwrap();
        assert_eq!(next, node(2));
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
                class: None,
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
        mark_all_connected(&state);

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
    #[test]
    fn ipv6_mtu_never_drops_below_1280() {
        assert_eq!(effective_mtu(1400, 1200, true), 1280);
        assert_eq!(effective_mtu(1400, 1200, false), 1152);
        assert_eq!(effective_mtu(1280, 1500, true), 1280);
        assert_eq!(effective_mtu(900, 1500, false), 900);
    }

    #[test]
    fn default_routes_are_opt_in() {
        assert!(is_default_prefix(&"0.0.0.0/0".parse().unwrap()));
        assert!(is_default_prefix(&"::/0".parse().unwrap()));
        assert!(!is_default_prefix(&"10.0.0.0/8".parse().unwrap()));
        assert!(!is_default_prefix(&"2001:db8::/32".parse().unwrap()));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn route_ownership_is_parsed_from_ip_output() {
        use super::RouteState;
        let ours = format!("10.9.0.0/16 dev stellaris0 proto {ROUTE_PROTO} scope link");
        assert_eq!(route_state_from("stellaris0", &ours), RouteState::Ours);
        let foreign = "10.9.0.0/16 dev eth0 scope link";
        assert_eq!(route_state_from("stellaris0", foreign), RouteState::Foreign);
        assert_eq!(route_state_from("stellaris0", ""), RouteState::Free);
        // Same device but not our proto tag is still foreign.
        let untagged = "10.9.0.0/16 dev stellaris0 scope link";
        assert_eq!(
            route_state_from("stellaris0", untagged),
            RouteState::Foreign
        );
    }

    #[test]
    fn transit_too_big_returns_ptb_to_previous_hop() {
        let state = state();
        let from = node(2);
        let next = node(3);
        // Previous hop can carry the packet; the next hop cannot.
        state.peers.mark(
            &from,
            true,
            Some("direct".into()),
            Some(1),
            Some(1500),
            None,
            1,
        );
        state.peers.mark(
            &next,
            true,
            Some("direct".into()),
            Some(1),
            Some(1100),
            None,
            1,
        );
        let mut packet = v4([10, 7, 0, 2], [10, 8, 0, 5], 64);
        packet[9] = 17;
        packet.resize(1400, 0);
        packet[2..4].copy_from_slice(&1400u16.to_be_bytes());
        let info = PacketInfo::parse(&packet).unwrap();
        let header = MeshHeader::new(state.network, 64, flow_hash(&info));
        let mut framed = Vec::with_capacity(HEADER_LEN + packet.len());
        framed.extend_from_slice(&header.encode());
        framed.extend_from_slice(&packet);
        match decide_inbound(&state, from, &framed) {
            InboundAction::Forward { next: hop, frame } => {
                assert_eq!(hop, from, "PTB must go back to the previous hop");
                let inner = &frame[HEADER_LEN..];
                assert_eq!(inner[0] >> 4, 4);
                assert_eq!(inner[9], 1, "expected ICMP");
            }
            other => panic!("expected PTB forward, got {other:?}"),
        }
    }

    #[test]
    fn ipv6_path_mtu_is_not_pinned_to_1280() {
        let state = state_v6();
        let peer = node(2);
        state.peers.mark(
            &peer,
            true,
            Some("direct".into()),
            Some(1),
            Some(1248),
            None,
            1,
        );
        let mut packet = v6(
            [0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
            [0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2],
            64,
        );
        packet.resize(700, 0);
        let peer = state.peers.get(&peer);
        let mtu = path_mtu(&state, peer.as_ref(), &packet);
        assert_eq!(mtu, 1232, "usable MTU must follow the underlay, not 1280");
    }

    #[test]
    fn path_mtu_limits_clamped_mss() {
        let state = state();
        state.peers.mark(
            &node(2),
            true,
            Some("direct".into()),
            Some(5),
            Some(1100),
            None,
            0,
        );
        let mut p = vec![0u8; 44];
        p[0] = 0x45;
        p[2..4].copy_from_slice(&44u16.to_be_bytes());
        p[8] = 64;
        p[9] = 6;
        p[12..16].copy_from_slice(&[10, 7, 0, 1]);
        p[16..20].copy_from_slice(&[10, 7, 0, 2]);
        p[32] = 6 << 4;
        p[40] = 2;
        p[41] = 4;
        p[42..44].copy_from_slice(&1460u16.to_be_bytes());
        let (_, frame) = route_outbound(&state, &p).unwrap();
        // path MTU 1100 - mesh header 16 = 1084; MSS = 1084 - 40.
        assert_eq!(
            u16::from_be_bytes([frame[HEADER_LEN + 42], frame[HEADER_LEN + 43]]),
            1044
        );
    }

    #[test]
    fn ipv6_outbound_uses_fib() {
        let state = state_v6();
        let p = v6(
            "fd00::1".parse::<std::net::Ipv6Addr>().unwrap().octets(),
            "fd00::2".parse::<std::net::Ipv6Addr>().unwrap().octets(),
            64,
        );
        let (next, frame) = route_outbound(&state, &p).unwrap();
        assert_eq!(next, node(2));
        assert_eq!(frame.len(), HEADER_LEN + p.len());
    }

    #[test]
    fn ipv6_inbound_local_delivers() {
        let state = state_v6();
        let p = v6(
            "fd00::2".parse::<std::net::Ipv6Addr>().unwrap().octets(),
            "fd00::1".parse::<std::net::Ipv6Addr>().unwrap().octets(),
            64,
        );
        let mut frame = Vec::new();
        frame.extend_from_slice(&MeshHeader::new(state.network, 64, 0).encode());
        frame.extend_from_slice(&p);
        assert_eq!(
            decide_inbound(&state, node(2), &frame),
            InboundAction::Deliver(p)
        );
    }
    #[test]
    fn oversized_outbound_df_generates_peer_sourced_ptb() {
        let state = state();
        state.peers.mark(
            &node(2),
            true,
            Some("direct".into()),
            Some(5),
            Some(1000),
            None,
            0,
        );
        let mut p = vec![0u8; 1400];
        p[0] = 0x45;
        p[2..4].copy_from_slice(&1400u16.to_be_bytes());
        p[6] = 0x40;
        p[8] = 64;
        p[9] = 17;
        p[12..16].copy_from_slice(&[10, 7, 0, 1]);
        p[16..20].copy_from_slice(&[10, 7, 0, 2]);
        let error = outbound_ptb(&state, &p, node(2)).expect("PTB");
        assert_eq!(error[0] >> 4, 4);
        assert_eq!(&error[12..16], &[10, 7, 0, 2]);
        assert_eq!(&error[16..20], &[10, 7, 0, 1]);
        assert_eq!(error[20], 3);
        assert_eq!(error[21], 4);
        assert_eq!(u16::from_be_bytes([error[26], error[27]]), 984);
    }

    #[test]
    fn oversized_inbound_generates_packet_too_big() {
        let state = state();
        state.peers.mark(
            &node(2),
            true,
            Some("direct".into()),
            Some(5),
            Some(1000),
            None,
            0,
        );
        let mut p = vec![0u8; 1400];
        p[0] = 0x45;
        p[2..4].copy_from_slice(&1400u16.to_be_bytes());
        p[8] = 64;
        p[9] = 17;
        p[12..16].copy_from_slice(&[10, 7, 0, 2]);
        p[16..20].copy_from_slice(&[10, 7, 0, 1]);
        let mut frame = Vec::new();
        frame.extend_from_slice(&MeshHeader::new(state.network, 64, 0).encode());
        frame.extend_from_slice(&p);
        match decide_inbound(&state, node(2), &frame) {
            InboundAction::Forward { frame, .. } => {
                let payload = &frame[HEADER_LEN..];
                assert_eq!(payload[0] >> 4, 4);
                assert_eq!(payload[9], 1);
                assert_eq!(payload[20], 3);
                assert_eq!(payload[21], 4);
                assert_eq!(u16::from_be_bytes([payload[26], payload[27]]), 984);
            }
            other => panic!("expected ICMP forward, got {other:?}"),
        }
    }
}
