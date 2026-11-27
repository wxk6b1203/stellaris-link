//! iroh transport: one endpoint, static peers, unreliable datagrams.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use anyhow::{Context, bail};
use bytes::Bytes;
use iroh::{
    Endpoint, EndpointAddr, EndpointId, RelayMode, RelayUrl, SecretKey, TransportAddr,
    endpoint::presets,
};
use stellaris_types::{AuthMode, Config, NetworkId, NodeId, PeerConfig};
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

use crate::PeerRegistry;
use crate::wire::{HEADER_LEN, MeshHeader, network_hash};

pub const DATA_ALPN: &[u8] = b"stellaris/data/1";

#[derive(Clone, Debug)]
pub struct InboundPacket {
    pub from: NodeId,
    pub packet: Bytes,
}

pub enum ControlEvent {
    Up {
        node: NodeId,
        conn: iroh::endpoint::Connection,
        stable_id: usize,
    },
    Down {
        node: NodeId,
        stable_id: usize,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum LinkRole {
    Primary,
    Standby,
}

struct LinkState {
    conn: iroh::endpoint::Connection,
    stable_id: usize,
    role: LinkRole,
    relay: Option<RelayUrl>,
}

#[derive(Default)]
struct PeerLinks {
    links: Vec<LinkState>,
    /// Index into `links` of the connection used for application datagrams.
    active: Option<usize>,
}

impl PeerLinks {
    fn active_conn(&self) -> Option<iroh::endpoint::Connection> {
        self.active
            .and_then(|index| self.links.get(index))
            .map(|link| link.conn.clone())
    }

    fn active_stable_id(&self) -> Option<usize> {
        self.active
            .and_then(|index| self.links.get(index))
            .map(|link| link.stable_id)
    }
}

pub struct IrohTransport {
    endpoint: Endpoint,
    standby_endpoint: Option<Endpoint>,
    config: Arc<Config>,
    state: crate::AgentState,
    controller_keys: Vec<NodeId>,
    /// Endpoint ids allowed to connect in `AuthMode::Static`.
    static_keys: HashSet<NodeId>,
    network: NetworkId,
    peers: PeerRegistry,
    inbound_tx: mpsc::Sender<InboundPacket>,
    control_tx: Option<mpsc::Sender<ControlEvent>>,
    conns: Arc<RwLock<HashMap<NodeId, PeerLinks>>>,
    /// Peers that were explicitly revoked; connect/accept loops stay idle
    /// (without reconnect churn) until the controller re-authorizes them.
    blocked: Arc<RwLock<HashSet<NodeId>>>,
    /// Configured relays tried when reconnecting to a peer, in order.
    relay_fallbacks: Vec<RelayUrl>,
}

fn standby_listen_port(port: Option<u16>) -> Option<u16> {
    match port {
        // 0 means "OS-assigned"; keep it ephemeral instead of trying port 1.
        Some(0) => Some(0),
        Some(port) => port.checked_add(1),
        None => None,
    }
}

async fn build_endpoint(
    config: &Config,
    secret: &SecretKey,
    relay: Option<&RelayUrl>,
    relay_disabled: bool,
    port: Option<u16>,
) -> anyhow::Result<Endpoint> {
    let mut builder = Endpoint::builder(presets::N0)
        .secret_key(secret.clone())
        // The data endpoint also carries the controller control ALPN when
        // `control.endpoint_id` is used, so the member does not register a
        // second endpoint with the same NodeId on the same relay.
        .alpns(vec![
            DATA_ALPN.to_vec(),
            crate::control_wire::CONTROL_ALPN.to_vec(),
        ]);
    if let Some(port) = port {
        let ip = config
            .transport
            .bind_ip
            .unwrap_or(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED));
        let addr = std::net::SocketAddr::new(ip, port);
        builder = builder
            .bind_addr(addr)
            .with_context(|| format!("bind_addr {addr}"))?;
    }
    if config.transport.disable_discovery {
        builder = builder.clear_address_lookup();
    }
    if relay_disabled {
        builder = builder.relay_mode(RelayMode::Disabled);
    } else if let Some(relay) = relay {
        builder = builder.relay_mode(RelayMode::custom(vec![relay.clone()]));
    } else if !config.transport.relay_urls.is_empty() {
        let urls: Vec<RelayUrl> = config
            .transport
            .relay_urls
            .iter()
            .map(|s| s.parse())
            .collect::<Result<_, _>>()
            .context("parse relay_urls")?;
        builder = builder.relay_mode(RelayMode::custom(urls));
    }
    builder.bind().await.context("bind iroh endpoint")
}

impl IrohTransport {
    pub async fn start(
        state: crate::AgentState,
        config: Arc<Config>,
        network: NetworkId,
        secret: [u8; 32],
        peers: PeerRegistry,
        inbound_tx: mpsc::Sender<InboundPacket>,
        control_tx: Option<mpsc::Sender<ControlEvent>>,
    ) -> anyhow::Result<Arc<Self>> {
        let secret = SecretKey::from_bytes(&secret);
        let relay_disabled = match config.transport.relay_mode {
            stellaris_types::RelayModeConfig::Disabled => true,
            stellaris_types::RelayModeConfig::Custom => false,
            stellaris_types::RelayModeConfig::N0 => false,
            stellaris_types::RelayModeConfig::Auto => config.transport.disable_relay,
        };
        let mut relay_urls: Vec<RelayUrl> = Vec::new();
        for raw in &config.transport.relay_urls {
            let url: RelayUrl = raw.parse().context("parse relay_urls")?;
            if !relay_urls.contains(&url) {
                relay_urls.push(url);
            }
        }
        // Two endpoints with the same identity are needed to pin one QUIC
        // connection to each relay; a single endpoint may use either relay for
        // both connections.
        let dual = !relay_disabled && relay_urls.len() >= 2;
        let endpoint = build_endpoint(
            &config,
            &secret,
            if dual { Some(&relay_urls[0]) } else { None },
            relay_disabled,
            config.transport.listen_port,
        )
        .await?;
        let standby_endpoint = if dual {
            let port = standby_listen_port(config.transport.listen_port);
            Some(build_endpoint(&config, &secret, Some(&relay_urls[1]), false, port).await?)
        } else {
            None
        };
        if !relay_disabled {
            // A relay being down must not block startup forever: `online()`
            // waits for any home relay, and a dual-relay node with one broken
            // relay would otherwise never start its API or dataplane.
            if tokio::time::timeout(Duration::from_secs(10), endpoint.online())
                .await
                .is_err()
            {
                warn!("primary relay did not come online within 10s; starting anyway");
            }
            if let Some(standby) = &standby_endpoint
                && tokio::time::timeout(Duration::from_secs(10), standby.online())
                    .await
                    .is_err()
            {
                warn!("standby relay did not come online within 10s; starting anyway");
            }
        }
        let me = endpoint.id();
        info!(endpoint = %me, addr = ?endpoint.addr(), "iroh endpoint ready");

        let controller_keys: Vec<NodeId> = config
            .control
            .controller_keys
            .iter()
            .filter_map(|key| key.parse().ok())
            .collect();
        let static_keys: HashSet<NodeId> = config
            .peers
            .iter()
            .filter_map(|peer| peer.endpoint_id.parse().ok())
            .collect();
        let transport = Arc::new(Self {
            endpoint: endpoint.clone(),
            standby_endpoint: standby_endpoint.clone(),
            config: config.clone(),
            state,
            controller_keys,
            static_keys,
            network,
            peers: peers.clone(),
            inbound_tx: inbound_tx.clone(),
            control_tx: control_tx.clone(),
            conns: Arc::new(RwLock::new(HashMap::new())),
            blocked: Arc::new(RwLock::new(HashSet::new())),
            relay_fallbacks: config
                .transport
                .relay_urls
                .iter()
                .filter_map(|url| url.parse().ok())
                .collect(),
        });

        // Accept loop per endpoint: authenticated iroh connection -> peer reader.
        for accept_endpoint in std::iter::once(endpoint.clone()).chain(standby_endpoint.clone()) {
            let transport = transport.clone();
            let accept_tx = inbound_tx.clone();
            let control_tx = control_tx.clone();
            let accept_config = config.clone();
            tokio::spawn(async move {
                loop {
                    let Some(incoming) = accept_endpoint.accept().await else {
                        break;
                    };
                    let accepting = match incoming.accept() {
                        Ok(a) => a,
                        Err(e) => {
                            debug!(error = %e, "incoming accept setup failed");
                            continue;
                        }
                    };
                    let conn = match accepting.await {
                        Ok(c) => c,
                        Err(e) => {
                            debug!(error = %e, "incoming handshake failed");
                            continue;
                        }
                    };
                    if conn.alpn() != DATA_ALPN {
                        debug!(alpn = ?conn.alpn(), "ignoring non-data inbound connection");
                        conn.close(4u8.into(), b"wrong alpn");
                        continue;
                    }
                    let remote = conn.remote_id();
                    let node = NodeId::new(*remote.as_bytes());
                    if transport.is_blocked(node) {
                        debug!(peer = %node.short(), "rejecting blocked inbound connection");
                        conn.close(3u8.into(), b"revoked");
                        continue;
                    }
                    if accept_config.network.auth.mode == AuthMode::Static
                        && !transport.static_keys.contains(&node)
                    {
                        warn!(peer = %node.short(), "peer key is not in the static allowlist");
                        conn.close(2u8.into(), b"not allowlisted");
                        continue;
                    }
                    if accept_config.network.auth.mode == AuthMode::Controller {
                        let credential = transport.state.credential();
                        let auth = tokio::time::timeout(
                            Duration::from_secs(5),
                            crate::membership::authenticate_server(
                                &conn,
                                &transport.network,
                                &transport.controller_keys,
                                credential.as_ref(),
                                |peer| transport.state.revision(peer),
                            ),
                        )
                        .await;
                        match auth {
                            Ok(Ok(verified)) => transport.state.install_grant(&verified),
                            Ok(Err(error)) => {
                                warn!(peer = %node.short(), error = %error, "membership authentication failed");
                                conn.close(2u8.into(), b"auth failed");
                                continue;
                            }
                            Err(_) => {
                                warn!(peer = %node.short(), "membership authentication timed out");
                                conn.close(2u8.into(), b"auth timeout");
                                continue;
                            }
                        }
                    }
                    let Some(role) = transport.next_inbound_role(node) else {
                        debug!(peer = %node.short(), "duplicate inbound link; closing");
                        conn.close(5u8.into(), b"duplicate link");
                        continue;
                    };
                    let relay = selected_relay(&conn);
                    if !transport.insert_conn(node, conn.clone(), role, relay.clone()) {
                        debug!(peer = %node.short(), "link role already filled; closing");
                        conn.close(5u8.into(), b"duplicate link");
                        continue;
                    }
                    info!(peer = %node.short(), ?role, ?relay, "inbound iroh connection");
                    spawn_path_watch(conn.clone(), node, conn.stable_id(), transport.clone());
                    if let Some(tx) = &control_tx {
                        let _ = tx
                            .send(ControlEvent::Up {
                                node,
                                conn: conn.clone(),
                                stable_id: conn.stable_id(),
                            })
                            .await;
                    }
                    let (path, rtt, mtu, addr, path_count) = path_status(&conn);
                    transport
                        .peers
                        .mark(&node, true, path, rtt, mtu, addr, path_count);
                    let tx = accept_tx.clone();
                    let network_hash = network_hash(transport.network);
                    let down_tx = control_tx.clone();
                    let transport_for_close = transport.clone();
                    let stable_id = conn.stable_id();
                    tokio::spawn(async move {
                        read_loop(conn, node, network_hash, tx).await;
                        let _ = transport_for_close.remove_conn(node, stable_id);
                        if let Some(tx) = &down_tx {
                            let _ = tx.send(ControlEvent::Down { node, stable_id }).await;
                        }
                    });
                }
            });
        }

        // Connect loop per configured peer.
        for peer in config.peers.clone() {
            transport.add_peer(peer, true);
        }

        Ok(transport)
    }

    /// Add a peer at runtime (LSA auto-discovery). Returns false if already known.
    pub fn add_peer(self: &Arc<Self>, peer: PeerConfig, force: bool) -> bool {
        let node: NodeId = match peer.endpoint_id.parse() {
            Ok(node) => node,
            Err(e) => {
                warn!(peer = %peer.name, error = %e, "invalid dynamic peer endpoint_id");
                return false;
            }
        };
        if !force && self.peers.get(&node).is_some() {
            return false;
        }
        // Static mode is a closed allowlist: discovery/LSA must not introduce
        // dynamic peers.
        if self.config.network.auth.mode == AuthMode::Static && !self.static_keys.contains(&node) {
            debug!(peer = %node.short(), "ignoring dynamic peer outside the static allowlist");
            return false;
        }
        if self.is_blocked(node) && !force {
            debug!(peer = %node.short(), "ignoring blocked peer");
            return false;
        }
        if force {
            self.allow_peer(node);
        }
        self.peers.upsert(crate::PeerState {
            node_id: node,
            name: peer.name.clone(),
            overlay_ip: peer.overlay_ip,
            endpoint_id: peer.endpoint_id.clone(),
            advertised: peer.advertised.clone(),
            zone: peer.zone.clone(),
            connected: false,
            path: None,
            rtt_ms: None,
            path_addr: None,
            path_count: 0,
            mtu: None,
            path_changes: 0,
        });
        // Only the numerically smaller NodeId dials; the other side accepts.
        // Both sides dialing creates duplicate links per role and breaks the
        // failure/role bookkeeping, so single-sided configurations must rely
        // on discovery or the smaller side being configured.
        let local = NodeId::new(*self.endpoint.id().as_bytes());
        if local >= node {
            debug!(peer = %node.short(), "peer will dial us");
            return true;
        }
        let tx = self.inbound_tx.clone();
        let control_tx = self.control_tx.clone();
        let plan = if self.standby_endpoint.is_some() && self.relay_fallbacks.len() >= 2 {
            vec![
                (LinkRole::Primary, Some(self.relay_fallbacks[0].clone())),
                (LinkRole::Standby, Some(self.relay_fallbacks[1].clone())),
            ]
        } else {
            link_plan(&peer, &self.relay_fallbacks)
        };
        for (role, relay) in plan {
            let endpoint = match role {
                LinkRole::Primary => self.endpoint.clone(),
                LinkRole::Standby => match &self.standby_endpoint {
                    Some(endpoint) => endpoint.clone(),
                    None => continue,
                },
            };
            let transport = self.clone();
            let peer = peer.clone();
            let tx = tx.clone();
            let control_tx = control_tx.clone();
            tokio::spawn(async move {
                connect_loop(transport, peer, role, relay, endpoint, tx, control_tx).await;
            });
        }
        true
    }

    fn is_blocked(&self, node: NodeId) -> bool {
        self.blocked
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .contains(&node)
    }

    /// Allow a controller-authorized peer to reconnect after a previous revoke.
    pub fn allow_peer(&self, node: NodeId) {
        self.blocked
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&node);
    }

    pub fn endpoint_id(&self) -> EndpointId {
        self.endpoint.id()
    }

    /// Shared endpoint used for control connections when possible.
    pub fn endpoint(&self) -> Endpoint {
        self.endpoint.clone()
    }

    /// Force-close every link to a peer (used when the controller revokes it).
    /// The peer is fenced and its connect/accept loops stay idle until a
    /// controller snapshot explicitly re-authorizes it.
    pub fn close_peer(&self, node: NodeId) {
        self.blocked
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .insert(node);
        self.drop_links(node, b"revoked");
    }

    /// Close links and drop the cached grant so the peer re-authenticates with
    /// its new credential. Unlike `close_peer` this is not a revocation and
    /// must not fence the peer: the connect loop is expected to reconnect.
    pub fn reconnect_peer(&self, node: NodeId) {
        self.drop_links(node, b"credential changed");
    }

    fn drop_links(&self, node: NodeId, reason: &[u8]) {
        let links = self
            .conns
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&node);
        if let Some(links) = links {
            for link in links.links {
                link.conn.close(3u8.into(), reason);
            }
            warn!(peer = %node.short(), "closed peer connections");
        }
        self.state.drop_grant(node);
    }

    /// Close one link (used by the link-state heartbeat when a relay path is
    /// silent). The connection manager promotes the other link immediately.
    pub fn close_link(&self, node: NodeId, stable_id: usize) {
        let conn = self
            .conns
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .get(&node)
            .and_then(|links| {
                links
                    .links
                    .iter()
                    .find(|link| link.stable_id == stable_id)
                    .map(|link| link.conn.clone())
            });
        if let Some(conn) = conn {
            warn!(peer = %node.short(), stable_id, "closing unhealthy relay link");
            conn.close(4u8.into(), b"heartbeat timeout");
        }
    }

    /// Minimum application datagram size across the active links.
    pub fn max_datagram_size(&self) -> Option<usize> {
        let guard = self.conns.read().unwrap_or_else(|e| e.into_inner());
        guard
            .values()
            .filter_map(|peer| peer.active_conn())
            .filter_map(|conn| conn.max_datagram_size())
            .min()
    }

    pub async fn send(&self, node: NodeId, packet: Bytes) -> anyhow::Result<()> {
        let links = {
            let guard = self.conns.read().unwrap_or_else(|e| e.into_inner());
            guard.get(&node).map(|peer| {
                let active = peer.active_conn();
                let mut ordered = Vec::with_capacity(peer.links.len());
                if let Some(conn) = active {
                    ordered.push(conn);
                }
                for link in &peer.links {
                    if peer.active_stable_id() != Some(link.stable_id) {
                        ordered.push(link.conn.clone());
                    }
                }
                ordered
            })
        };
        let Some(links) = links else {
            bail!("peer {} not connected", node.short());
        };
        if links.is_empty() {
            bail!("peer {} not connected", node.short());
        }
        for conn in links {
            if let Some(max) = conn.max_datagram_size()
                && packet.len() > max
            {
                bail!("datagram too large: {} > {}", packet.len(), max);
            }
            if conn.send_datagram(packet.clone()).is_ok() {
                if self.set_active(node, conn.stable_id()) {
                    let (path, rtt, mtu, addr, path_count) = path_status(&conn);
                    self.peers
                        .mark(&node, true, path, rtt, mtu, addr, path_count);
                }
                return Ok(());
            }
        }
        bail!("all links to peer {} failed", node.short())
    }

    fn next_inbound_role(&self, node: NodeId) -> Option<LinkRole> {
        let guard = self.conns.read().unwrap_or_else(|e| e.into_inner());
        let Some(links) = guard.get(&node) else {
            return Some(LinkRole::Primary);
        };
        if links.links.len() >= 2 {
            return None;
        }
        if links
            .links
            .iter()
            .any(|link| link.role == LinkRole::Primary)
        {
            Some(LinkRole::Standby)
        } else {
            Some(LinkRole::Primary)
        }
    }

    fn insert_conn(
        &self,
        node: NodeId,
        conn: iroh::endpoint::Connection,
        role: LinkRole,
        relay: Option<RelayUrl>,
    ) -> bool {
        let stable_id = conn.stable_id();
        let mut guard = self.conns.write().unwrap_or_else(|e| e.into_inner());
        let links = guard.entry(node).or_default();
        let duplicate_role = links.links.iter().any(|link| link.role == role);
        let duplicate_relay = relay.is_some() && links.links.iter().any(|link| link.relay == relay);
        if links.links.iter().any(|link| link.stable_id == stable_id)
            || duplicate_role
            || duplicate_relay
            || links.links.len() >= 2
        {
            return false;
        }
        let index = links.links.len();
        links.links.push(LinkState {
            conn: conn.clone(),
            stable_id,
            role,
            relay,
        });
        if links.active.is_none() {
            links.active = Some(index);
        }
        let active = links.active == Some(index);
        drop(guard);
        info!(
            peer = %node.short(),
            stable_id,
            ?role,
            active,
            "connection installed"
        );
        if active {
            let (path, rtt, mtu, addr, path_count) = path_status(&conn);
            self.peers
                .mark(&node, true, path, rtt, mtu, addr, path_count);
        }
        true
    }

    /// Remove one link. Returns `(no_links_left, was_active)`.
    fn remove_conn(&self, node: NodeId, stable_id: usize) -> (bool, bool) {
        let mut guard = self.conns.write().unwrap_or_else(|e| e.into_inner());
        let Some(links) = guard.get_mut(&node) else {
            return (true, false);
        };
        let active_before = links.active_stable_id();
        let was_active = active_before == Some(stable_id);
        links.links.retain(|link| link.stable_id != stable_id);
        if links.links.is_empty() {
            guard.remove(&node);
            // Clear peer/grant state while still holding the connection lock:
            // otherwise a new link can be inserted between the empty check and
            // the cleanup, and the stale cleanup would fence a live peer.
            self.peers.mark(&node, false, None, None, None, None, 0);
            self.state.drop_grant(node);
            return (true, was_active);
        }
        if was_active {
            // Prefer a primary link, then any live link; the caller will
            // reconnect the missing standby/primary in the background.
            links.active = links
                .links
                .iter()
                .position(|link| link.role == LinkRole::Primary)
                .or(Some(0));
        }
        let new_active = links.active_conn();
        drop(guard);
        if let Some(conn) = new_active {
            let (path, rtt, mtu, addr, path_count) = path_status(&conn);
            self.peers
                .mark(&node, true, path, rtt, mtu, addr, path_count);
        }
        warn!(peer = %node.short(), stable_id, was_active, "connection close observed");
        (false, was_active)
    }

    fn set_active(&self, node: NodeId, stable_id: usize) -> bool {
        let mut guard = self.conns.write().unwrap_or_else(|e| e.into_inner());
        let Some(links) = guard.get_mut(&node) else {
            return false;
        };
        let Some(index) = links
            .links
            .iter()
            .position(|link| link.stable_id == stable_id)
        else {
            return false;
        };
        if links.active == Some(index) {
            return false;
        }
        links.active = Some(index);
        true
    }

    #[allow(dead_code)]
    fn active_stable(&self, node: NodeId) -> Option<usize> {
        self.conns
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .get(&node)
            .and_then(PeerLinks::active_stable_id)
    }

    fn has_role(&self, node: NodeId, role: LinkRole) -> bool {
        self.conns
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .get(&node)
            .is_some_and(|links| links.links.iter().any(|link| link.role == role))
    }

    fn is_active_link(&self, node: NodeId, stable_id: usize) -> bool {
        self.conns
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .get(&node)
            .and_then(PeerLinks::active_stable_id)
            == Some(stable_id)
    }
}

/// Refresh `/v1/peers` path/RTT/MTU while the link is alive. iroh can migrate
/// an established connection between direct and relay paths, so sampling only
/// at connect time leaves the API permanently stale after a failover.
fn spawn_path_watch(
    conn: iroh::endpoint::Connection,
    node: NodeId,
    stable_id: usize,
    transport: Arc<IrohTransport>,
) {
    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = tokio::time::sleep(Duration::from_secs(2)) => {}
                _ = conn.closed() => break,
            }
            if conn.paths().is_empty() {
                break;
            }
            if !transport.is_active_link(node, stable_id) {
                continue;
            }
            let (path, rtt, mtu, addr, path_count) = path_status(&conn);
            if path.is_some() {
                transport
                    .peers
                    .mark(&node, true, path, rtt, mtu, addr, path_count);
            }
        }
    });
}

fn selected_relay(conn: &iroh::endpoint::Connection) -> Option<RelayUrl> {
    conn.paths().iter().find_map(|path| {
        if path.is_selected()
            && let iroh::TransportAddr::Relay(url) = path.remote_addr()
        {
            Some(url.clone())
        } else {
            None
        }
    })
}

fn link_plan(peer: &PeerConfig, fallbacks: &[RelayUrl]) -> Vec<(LinkRole, Option<RelayUrl>)> {
    let mut relays = Vec::new();
    if let Some(raw) = &peer.relay_url
        && let Ok(url) = raw.parse::<RelayUrl>()
        && !relays.contains(&url)
    {
        relays.push(url);
    }
    for relay in fallbacks {
        if !relays.contains(relay) {
            relays.push(relay.clone());
        }
    }
    match relays.as_slice() {
        [primary, standby, ..] => vec![
            (LinkRole::Primary, Some(primary.clone())),
            (LinkRole::Standby, Some(standby.clone())),
        ],
        [primary] => vec![(LinkRole::Primary, Some(primary.clone()))],
        [] => vec![(LinkRole::Primary, None)],
    }
}

async fn read_loop(
    conn: iroh::endpoint::Connection,
    from: NodeId,
    expected_network_hash: u32,
    tx: mpsc::Sender<InboundPacket>,
) {
    loop {
        match conn.read_datagram().await {
            Ok(data) => {
                if data.len() < HEADER_LEN {
                    continue;
                }
                let Some(header) = MeshHeader::decode(&data) else {
                    continue;
                };
                if header.network_hash != expected_network_hash {
                    continue;
                }
                if tx.send(InboundPacket { from, packet: data }).await.is_err() {
                    break;
                }
            }
            Err(e) => {
                debug!(peer = %from.short(), error = %e, "datagram read closed");
                break;
            }
        }
    }
}

fn path_status(
    conn: &iroh::endpoint::Connection,
) -> (
    Option<String>,
    Option<u64>,
    Option<u16>,
    Option<String>,
    usize,
) {
    let paths = conn.paths();
    let path_count = paths.iter().count();
    for path in paths.iter() {
        if path.is_selected() {
            let kind = if path.is_relay() {
                "relay"
            } else if path.is_ip() {
                "direct"
            } else {
                "other"
            };
            return (
                Some(kind.to_string()),
                Some(path.rtt().as_millis() as u64),
                conn.max_datagram_size()
                    .map(|n| n.min(u16::MAX as usize) as u16),
                match path.remote_addr() {
                    iroh::TransportAddr::Ip(addr) => Some(addr.to_string()),
                    iroh::TransportAddr::Relay(url) => Some(url.to_string()),
                    _ => None,
                },
                path_count,
            );
        }
    }
    (None, None, None, None, 0)
}

async fn connect_loop(
    transport: Arc<IrohTransport>,
    peer: PeerConfig,
    role: LinkRole,
    relay: Option<RelayUrl>,
    endpoint: Endpoint,
    inbound_tx: mpsc::Sender<InboundPacket>,
    control_tx: Option<mpsc::Sender<ControlEvent>>,
) {
    let node: NodeId = match peer.endpoint_id.parse() {
        Ok(n) => n,
        Err(e) => {
            warn!(peer = %peer.name, error = %e, "invalid peer endpoint_id");
            return;
        }
    };
    let remote = match EndpointId::from_bytes(node.as_bytes()) {
        Ok(id) => id,
        Err(e) => {
            warn!(peer = %peer.name, error = %e, "invalid iroh endpoint id");
            return;
        }
    };
    let mut addrs = Vec::new();
    // In dual-relay mode each endpoint is pinned to exactly one relay so the
    // two links really use different relays. With a single endpoint the relay
    // is a fallback: keep the configured direct addresses so iroh can still
    // pick a direct path (and roam back to it) instead of forcing relay-only.
    let force_relay = relay.is_some() && transport.standby_endpoint.is_some();
    if force_relay {
        if let Some(relay) = &relay {
            addrs.push(TransportAddr::Relay(relay.clone()));
        }
    } else {
        for addr in &peer.addrs {
            addrs.push(TransportAddr::Ip(*addr));
        }
        if let Some(relay) = &relay {
            addrs.push(TransportAddr::Relay(relay.clone()));
        }
        for candidate in &transport.relay_fallbacks {
            let candidate = TransportAddr::Relay(candidate.clone());
            if !addrs.contains(&candidate) {
                addrs.push(candidate);
            }
        }
    }
    let addr = EndpointAddr::from_parts(remote, addrs);
    loop {
        if transport.is_blocked(node) {
            tokio::time::sleep(Duration::from_secs(2)).await;
            continue;
        }
        if transport.has_role(node, role) {
            tokio::time::sleep(Duration::from_secs(2)).await;
            continue;
        }
        match endpoint.connect(addr.clone(), DATA_ALPN).await {
            Ok(conn) => {
                if transport.is_blocked(node) {
                    conn.close(3u8.into(), b"revoked");
                    continue;
                }
                if transport.config.network.auth.mode == AuthMode::Controller {
                    let credential = transport.state.credential();
                    let auth = tokio::time::timeout(
                        Duration::from_secs(5),
                        crate::membership::authenticate_client(
                            &conn,
                            &transport.network,
                            &transport.controller_keys,
                            credential.as_ref(),
                            |peer| transport.state.revision(peer),
                        ),
                    )
                    .await;
                    match auth {
                        Ok(Ok(verified)) => transport.state.install_grant(&verified),
                        Ok(Err(error)) => {
                            warn!(peer = %peer.name, error = %error, "membership authentication failed");
                            conn.close(2u8.into(), b"auth failed");
                            tokio::time::sleep(Duration::from_secs(2)).await;
                            continue;
                        }
                        Err(_) => {
                            warn!(peer = %peer.name, "membership authentication timed out");
                            conn.close(2u8.into(), b"auth timeout");
                            tokio::time::sleep(Duration::from_secs(2)).await;
                            continue;
                        }
                    }
                }
                if transport.is_blocked(node) {
                    conn.close(3u8.into(), b"revoked");
                    continue;
                }
                if !transport.insert_conn(node, conn.clone(), role, relay.clone()) {
                    debug!(peer = %peer.name, ?role, "link role already filled; closing");
                    conn.close(5u8.into(), b"duplicate link");
                    tokio::time::sleep(Duration::from_secs(2)).await;
                    continue;
                }
                let stable_id = conn.stable_id();
                info!(peer = %peer.name, ?role, "outbound iroh connected");
                spawn_path_watch(conn.clone(), node, stable_id, transport.clone());
                if let Some(tx) = &control_tx {
                    let _ = tx
                        .send(ControlEvent::Up {
                            node,
                            conn: conn.clone(),
                            stable_id,
                        })
                        .await;
                }
                let (path, rtt, mtu, addr, path_count) = path_status(&conn);
                transport
                    .peers
                    .mark(&node, true, path, rtt, mtu, addr, path_count);
                let tx = inbound_tx.clone();
                let network_hash = network_hash(transport.network);
                let read_conn = conn.clone();
                tokio::spawn(async move {
                    read_loop(read_conn, node, network_hash, tx).await;
                });
                conn.closed().await;
                let _ = transport.remove_conn(node, stable_id);
                if let Some(tx) = &control_tx {
                    let _ = tx.send(ControlEvent::Down { node, stable_id }).await;
                }
                warn!(peer = %peer.name, ?role, "connection closed; reconnecting");
            }
            Err(e) => {
                debug!(peer = %peer.name, ?role, error = %e, "connect failed");
            }
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use iroh_relay::server::{RelayConfig, Server, ServerConfig};
    use std::net::Ipv4Addr;
    use stellaris_types::Config;

    fn config(name: &str, state: &std::path::Path, relay: &str, overlay: &str) -> Config {
        let toml = format!(
            r#"
[node]
name = "{name}"
state_dir = "{}"
overlay_ip = "{overlay}"
[network]
name = "relay-test"
cidr = "10.7.0.0/16"
[transport]
disable_relay = false
relay_urls = ["{relay}"]
[api]
bind = "127.0.0.1:0"
"#,
            state.display()
        );
        Config::from_toml(&toml).unwrap()
    }

    fn config_multi(
        name: &str,
        state: &std::path::Path,
        relays: &[String],
        overlay: &str,
    ) -> Config {
        let relay_list = relays
            .iter()
            .map(|r| format!("\"{r}\""))
            .collect::<Vec<_>>()
            .join(", ");
        let toml = format!(
            r#"
[node]
name = "{name}"
state_dir = "{}"
overlay_ip = "{overlay}"
[network]
name = "relay-failover-test"
cidr = "10.8.0.0/16"
[transport]
disable_relay = false
disable_discovery = true
relay_urls = [{relay_list}]
[api]
bind = "127.0.0.1:0"
"#,
            state.display()
        );
        Config::from_toml(&toml).unwrap()
    }

    async fn start_relay() -> (iroh_relay::server::Server, String) {
        let mut relay = RelayConfig::new((Ipv4Addr::LOCALHOST, 0));
        relay.key_cache_capacity = Some(1024);
        let mut server_config = ServerConfig::default();
        server_config.relay = Some(relay);
        let server = Server::spawn(server_config).await.unwrap();
        let url = format!("http://{}", server.http_addr().unwrap());
        (server, url)
    }

    #[tokio::test]
    #[ignore = "iroh-relay Server::shutdown does not sever established sessions; Phase 0 in RELAY-FAILOVER.md"]
    async fn endpoint_fails_over_to_the_second_relay_when_the_active_relay_dies() {
        let (relay1, url1) = start_relay().await;
        let (relay2, url2) = start_relay().await;
        let base =
            std::env::temp_dir().join(format!("stellaris-relay-use-{}", uuid::Uuid::now_v7()));
        std::fs::create_dir_all(&base).unwrap();
        let config_a = config_multi(
            "a",
            &base.join("a"),
            &[url1.clone(), url2.clone()],
            "10.8.0.1",
        );
        let config_b = config_multi(
            "b",
            &base.join("b"),
            &[url1.clone(), url2.clone()],
            "10.8.0.2",
        );
        let network = NetworkId::new();
        let (tx_a, _rx_a) = mpsc::channel(64);
        let (tx_b, _rx_b) = mpsc::channel(64);
        let state_a = crate::AgentState::build(config_a.clone()).unwrap();
        let a = IrohTransport::start(
            state_a,
            Arc::new(config_a),
            network,
            [11u8; 32],
            PeerRegistry::from_config(
                &Config::from_toml(&format!(
                    r#"
[node]
name = "a"
state_dir = "{}"
[network]
name = "relay-use"
cidr = "10.8.0.0/16"
"#,
                    base.join("a").display()
                ))
                .unwrap(),
            )
            .unwrap(),
            tx_a,
            None,
        )
        .await
        .unwrap();
        let state_b = crate::AgentState::build(config_b.clone()).unwrap();
        let b = IrohTransport::start(
            state_b,
            Arc::new(config_b),
            network,
            [12u8; 32],
            PeerRegistry::from_config(
                &Config::from_toml(&format!(
                    r#"
[node]
name = "b"
state_dir = "{}"
[network]
name = "relay-use"
cidr = "10.8.0.0/16"
"#,
                    base.join("b").display()
                ))
                .unwrap(),
            )
            .unwrap(),
            tx_b,
            None,
        )
        .await
        .unwrap();
        let a_id = NodeId::new(*a.endpoint_id().as_bytes());
        let b_id = NodeId::new(*b.endpoint_id().as_bytes());
        a.add_peer(
            PeerConfig {
                name: "b".into(),
                endpoint_id: b_id.to_string(),
                overlay_ip: "10.8.0.2".parse().unwrap(),
                addrs: vec![],
                relay_url: Some(url1.clone()),
                advertised: vec![],
                zone: None,
            },
            true,
        );
        b.add_peer(
            PeerConfig {
                name: "a".into(),
                endpoint_id: a_id.to_string(),
                overlay_ip: "10.8.0.1".parse().unwrap(),
                addrs: vec![],
                relay_url: Some(url1.clone()),
                advertised: vec![],
                zone: None,
            },
            true,
        );
        for _ in 0..100 {
            if a.peers.get(&b_id).is_some_and(|p| p.connected) {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        let mut relay_path = false;
        for _ in 0..50 {
            if let Some(peer) = a.peers.get(&b_id)
                && peer.connected
                && peer.path.as_deref() == Some("relay")
            {
                relay_path = true;
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
        assert!(relay_path, "peer did not report a relay path");
        let before1 = relay1.metrics().server.send_packets_recv.get();
        let before2 = relay2.metrics().server.send_packets_recv.get();
        a.send(b_id, Bytes::from_static(b"relay-probe"))
            .await
            .unwrap();
        let mut carried = false;
        for _ in 0..50 {
            if relay1.metrics().server.send_packets_recv.get() > before1
                || relay2.metrics().server.send_packets_recv.get() > before2
            {
                carried = true;
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
        assert!(carried, "datagram did not traverse a relay");

        // Kill the relay that actually carried traffic and require the peer to
        // reconnect through the other configured relay.
        let mut r1 = Some(relay1);
        let mut r2 = Some(relay2);
        let use_first = r1
            .as_ref()
            .unwrap()
            .metrics()
            .server
            .send_packets_recv
            .get()
            > before1;
        let survivor_before = if use_first {
            r2.as_ref()
                .unwrap()
                .metrics()
                .server
                .send_packets_recv
                .get()
        } else {
            r1.as_ref()
                .unwrap()
                .metrics()
                .server
                .send_packets_recv
                .get()
        };
        if use_first {
            r1.take().unwrap().shutdown().await.unwrap();
        } else {
            r2.take().unwrap().shutdown().await.unwrap();
        }
        let mut recovered = false;
        for _ in 0..900 {
            let survivor_now = if use_first {
                r2.as_ref()
                    .unwrap()
                    .metrics()
                    .server
                    .send_packets_recv
                    .get()
            } else {
                r1.as_ref()
                    .unwrap()
                    .metrics()
                    .server
                    .send_packets_recv
                    .get()
            };
            if a.send(b_id, Bytes::from_static(b"relay-failover-probe"))
                .await
                .is_ok()
                && survivor_now > survivor_before
            {
                recovered = true;
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
        assert!(
            recovered,
            "traffic did not move to the second relay after the active relay died"
        );
        drop(a);
        drop(b);
        std::fs::remove_dir_all(base).unwrap();
    }

    #[tokio::test]
    async fn endpoint_connects_over_http_relay() {
        let mut relay = RelayConfig::new((Ipv4Addr::LOCALHOST, 0));
        relay.key_cache_capacity = Some(1024);
        let mut server_config = ServerConfig::default();
        server_config.relay = Some(relay);
        let server = Server::spawn(server_config).await.unwrap();
        let relay_url = format!("http://{}", server.http_addr().unwrap());
        let base = std::env::temp_dir().join(format!("stellaris-relay-{}", uuid::Uuid::now_v7()));
        std::fs::create_dir_all(&base).unwrap();
        let config_a = config("a", &base.join("a"), &relay_url, "10.7.0.1");
        let config_b = config("b", &base.join("b"), &relay_url, "10.7.0.2");
        let network = NetworkId::new();
        let (tx_a, _rx_a) = mpsc::channel(64);
        let (tx_b, _rx_b) = mpsc::channel(64);
        let state_a = crate::AgentState::build(config_a.clone()).unwrap();
        let a = IrohTransport::start(
            state_a,
            Arc::new(config_a.clone()),
            network,
            [1u8; 32],
            PeerRegistry::from_config(&config_a).unwrap(),
            tx_a,
            None,
        )
        .await
        .unwrap();
        let state_b = crate::AgentState::build(config_b.clone()).unwrap();
        let b = IrohTransport::start(
            state_b,
            Arc::new(config_b.clone()),
            network,
            [2u8; 32],
            PeerRegistry::from_config(&config_b).unwrap(),
            tx_b,
            None,
        )
        .await
        .unwrap();
        let a_id = NodeId::new(*a.endpoint_id().as_bytes());
        let b_id = NodeId::new(*b.endpoint_id().as_bytes());
        let peer = |name: &str, id: NodeId, overlay: &str| PeerConfig {
            name: name.into(),
            endpoint_id: id.to_string(),
            overlay_ip: overlay.parse().unwrap(),
            addrs: vec![],
            relay_url: Some(relay_url.clone()),
            advertised: vec![],
            zone: None,
        };
        a.add_peer(peer("b", b_id, "10.7.0.2"), true);
        b.add_peer(peer("a", a_id, "10.7.0.1"), true);
        for _ in 0..200 {
            if a.peers
                .get(&b_id)
                .is_some_and(|p| p.connected && p.path.is_some())
                && b.peers
                    .get(&a_id)
                    .is_some_and(|p| p.connected && p.path.is_some())
            {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        let path = a.peers.get(&b_id).and_then(|p| p.path);
        assert_eq!(path.as_deref(), Some("relay"), "path={path:?}");
        drop(a);
        drop(b);
        drop(server);
        std::fs::remove_dir_all(base).unwrap();
    }

    fn node_for(secret: [u8; 32]) -> NodeId {
        NodeId::new(*SecretKey::from_bytes(&secret).public().as_bytes())
    }

    fn credential(
        controller_secret: &[u8; 32],
        network: &NetworkId,
        node: NodeId,
        overlay: &str,
    ) -> crate::credential::SignedCredential {
        crate::credential::SignedCredential::sign(
            controller_secret,
            crate::credential::MembershipCredential {
                network: network.to_string(),
                node,
                overlay_ip: Some(overlay.parse().unwrap()),
                prefixes: Vec::new(),
                capabilities: vec!["member".into()],
                revision: 1,
                issued_at: crate::credential::now_secs(),
                not_after: crate::credential::now_secs() + 600,
            },
        )
    }

    fn controller_config(config: &mut Config, controller: NodeId) {
        config.network.auth.mode = AuthMode::Controller;
        config.control.controller_keys = vec![controller.to_string()];
        config.control.url = Some("http://127.0.0.1:1".into());
        config.control.credential_ttl_secs = 600;
    }

    #[tokio::test]
    async fn controller_credentials_gate_connections_and_install_grants() {
        let (server, relay_url) = start_relay().await;
        let base = std::env::temp_dir().join(format!("stellaris-cred-{}", uuid::Uuid::now_v7()));
        std::fs::create_dir_all(&base).unwrap();
        let controller_secret = [9u8; 32];
        let controller = node_for(controller_secret);
        let mut config_a = config("a", &base.join("a"), &relay_url, "10.7.0.1");
        let mut config_b = config("b", &base.join("b"), &relay_url, "10.7.0.2");
        let mut config_c = config("c", &base.join("c"), &relay_url, "10.7.0.3");
        for config in [&mut config_a, &mut config_b, &mut config_c] {
            controller_config(config, controller);
        }
        let state_a = crate::AgentState::build(config_a.clone()).unwrap();
        let state_b = crate::AgentState::build(config_b.clone()).unwrap();
        let state_c = crate::AgentState::build(config_c.clone()).unwrap();
        let network = state_a.network;
        state_a.set_credential(credential(
            &controller_secret,
            &network,
            node_for([1u8; 32]),
            "10.7.0.1",
        ));
        state_b.set_credential(credential(
            &controller_secret,
            &network,
            node_for([2u8; 32]),
            "10.7.0.2",
        ));
        let (tx_a, _rx_a) = mpsc::channel(64);
        let (tx_b, _rx_b) = mpsc::channel(64);
        let (tx_c, _rx_c) = mpsc::channel(64);
        let a = IrohTransport::start(
            state_a.clone(),
            state_a.config.clone(),
            network,
            [1u8; 32],
            PeerRegistry::from_config(&config_a).unwrap(),
            tx_a,
            None,
        )
        .await
        .unwrap();
        let b = IrohTransport::start(
            state_b.clone(),
            state_b.config.clone(),
            network,
            [2u8; 32],
            PeerRegistry::from_config(&config_b).unwrap(),
            tx_b,
            None,
        )
        .await
        .unwrap();
        let c = IrohTransport::start(
            state_c.clone(),
            state_c.config.clone(),
            network,
            [3u8; 32],
            PeerRegistry::from_config(&config_c).unwrap(),
            tx_c,
            None,
        )
        .await
        .unwrap();
        let peer = |name: &str, id: NodeId, overlay: &str| PeerConfig {
            name: name.into(),
            endpoint_id: id.to_string(),
            overlay_ip: overlay.parse().unwrap(),
            addrs: vec![],
            relay_url: Some(relay_url.clone()),
            advertised: vec![],
            zone: None,
        };
        let a_id = node_for([1u8; 32]);
        let b_id = node_for([2u8; 32]);
        a.add_peer(peer("b", b_id, "10.7.0.2"), true);
        b.add_peer(peer("a", a_id, "10.7.0.1"), true);
        c.add_peer(peer("b", b_id, "10.7.0.2"), true);
        for _ in 0..100 {
            if a.peers.get(&b_id).is_some_and(|p| p.connected)
                && b.peers.get(&a_id).is_some_and(|p| p.connected)
            {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        assert!(a.peers.get(&b_id).is_some_and(|p| p.connected));
        assert!(b.peers.get(&a_id).is_some_and(|p| p.connected));
        // The handshake installs grants derived from the presented credentials.
        assert!(state_a.grants.read().unwrap().contains_key(&b_id));
        assert!(state_b.grants.read().unwrap().contains_key(&a_id));
        // A node with no credential cannot join the data plane.
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        assert!(!c.peers.get(&b_id).is_some_and(|p| p.connected));
        drop(a);
        drop(b);
        drop(c);
        drop(server);
        let _ = std::fs::remove_dir_all(base);
    }

    fn static_config(config: &mut Config, peers: Vec<PeerConfig>) {
        config.network.auth.mode = AuthMode::Static;
        config.peers = peers;
    }

    #[tokio::test]
    async fn static_mode_only_accepts_allowlisted_keys() {
        let (server, relay_url) = start_relay().await;
        let base = std::env::temp_dir().join(format!("stellaris-static-{}", uuid::Uuid::now_v7()));
        std::fs::create_dir_all(&base).unwrap();
        let a_id = node_for([1u8; 32]);
        let b_id = node_for([2u8; 32]);
        let c_id = node_for([3u8; 32]);
        let peer = |name: &str, id: NodeId, overlay: &str| PeerConfig {
            name: name.into(),
            endpoint_id: id.to_string(),
            overlay_ip: overlay.parse().unwrap(),
            addrs: vec![],
            relay_url: Some(relay_url.clone()),
            advertised: vec![],
            zone: None,
        };
        let mut config_a = config("a", &base.join("a"), &relay_url, "10.7.0.1");
        static_config(&mut config_a, vec![peer("b", b_id, "10.7.0.2")]);
        let mut config_b = config("b", &base.join("b"), &relay_url, "10.7.0.2");
        static_config(&mut config_b, vec![peer("a", a_id, "10.7.0.1")]);
        let mut config_c = config("c", &base.join("c"), &relay_url, "10.7.0.3");
        static_config(&mut config_c, vec![peer("b", b_id, "10.7.0.2")]);
        let state_a = crate::AgentState::build(config_a.clone()).unwrap();
        let state_b = crate::AgentState::build(config_b.clone()).unwrap();
        let state_c = crate::AgentState::build(config_c.clone()).unwrap();
        let network = state_a.network;
        let (tx_a, _rx_a) = mpsc::channel(64);
        let (tx_b, _rx_b) = mpsc::channel(64);
        let (tx_c, _rx_c) = mpsc::channel(64);
        let a = IrohTransport::start(
            state_a.clone(),
            state_a.config.clone(),
            network,
            [1u8; 32],
            PeerRegistry::from_config(&config_a).unwrap(),
            tx_a,
            None,
        )
        .await
        .unwrap();
        let b = IrohTransport::start(
            state_b.clone(),
            state_b.config.clone(),
            network,
            [2u8; 32],
            PeerRegistry::from_config(&config_b).unwrap(),
            tx_b,
            None,
        )
        .await
        .unwrap();
        let c = IrohTransport::start(
            state_c.clone(),
            state_c.config.clone(),
            network,
            [3u8; 32],
            PeerRegistry::from_config(&config_c).unwrap(),
            tx_c,
            None,
        )
        .await
        .unwrap();
        for _ in 0..100 {
            if a.peers.get(&b_id).is_some_and(|p| p.connected)
                && b.peers.get(&a_id).is_some_and(|p| p.connected)
            {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        assert!(a.peers.get(&b_id).is_some_and(|p| p.connected));
        assert!(b.peers.get(&a_id).is_some_and(|p| p.connected));
        // c is not in b's allowlist, so the inbound connection is rejected.
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        assert!(!c.peers.get(&b_id).is_some_and(|p| p.connected));
        // Dynamic add (discovery/LSA) is refused outside the allowlist.
        assert!(!b.add_peer(peer("c", c_id, "10.7.0.3"), false));
        drop(a);
        drop(b);
        drop(c);
        drop(server);
        let _ = std::fs::remove_dir_all(base);
    }

    /// Manual spike: can one iroh 1.5 connection keep two relay paths and
    /// migrate when one relay dies? Run with:
    /// `cargo test -p stellaris-agent --lib multipath_spike -- --ignored --nocapture`
    #[tokio::test]
    #[ignore = "manual iroh multipath spike"]
    async fn multipath_spike_two_relays() {
        use futures::StreamExt;
        use iroh::endpoint::Connection;
        use std::time::Instant;

        async fn probe(conn: &Connection) -> bool {
            match conn.open_bi().await {
                Ok((mut send, _recv)) => send.write_all(b"spike").await.is_ok(),
                Err(_) => false,
            }
        }

        fn dump(conn: &Connection, label: &str) {
            let paths = conn.paths();
            println!("SPIKE {label}: paths={}", paths.len());
            for path in paths.iter() {
                println!(
                    "SPIKE {label}: selected={} addr={:?}",
                    path.is_selected(),
                    path.remote_addr()
                );
            }
        }

        let (relay1, url1) = start_relay().await;
        let (relay2, url2) = start_relay().await;
        let relays: Vec<RelayUrl> = vec![url1.parse().unwrap(), url2.parse().unwrap()];
        let mk = |secret: [u8; 32], bind: Option<&str>| {
            let mut builder = Endpoint::builder(presets::N0)
                .secret_key(SecretKey::from_bytes(&secret))
                .relay_mode(RelayMode::custom(relays.clone()))
                .clear_address_lookup()
                .alpns(vec![b"multipath-spike".to_vec()]);
            if let Some(addr) = bind {
                builder = builder
                    .bind_addr(addr.parse::<std::net::SocketAddr>().unwrap())
                    .unwrap();
            }
            builder
        };
        let bind_a = std::env::var("SPIKE_BIND_A").ok();
        let bind_b = std::env::var("SPIKE_BIND_B").ok();
        let a = mk([21u8; 32], bind_a.as_deref()).bind().await.unwrap();
        let b = mk([22u8; 32], bind_b.as_deref()).bind().await.unwrap();
        let b_id = b.id();
        let b2 = b.clone();
        let accept = tokio::spawn(async move {
            let incoming = b2.accept().await.unwrap();
            incoming.accept().unwrap().await.unwrap()
        });
        let addrs = vec![
            TransportAddr::Relay(relays[0].clone()),
            TransportAddr::Relay(relays[1].clone()),
        ];
        println!("SPIKE connect: addrs={addrs:?}");
        let conn = a
            .connect(EndpointAddr::from_parts(b_id, addrs), b"multipath-spike")
            .await
            .unwrap();
        let _server_conn = accept.await.unwrap();
        tokio::time::sleep(Duration::from_secs(2)).await;
        dump(&conn, "after-connect");
        println!("SPIKE probe before kill: {}", probe(&conn).await);

        let selected_relay = conn.paths().iter().find_map(|path| {
            if path.is_selected()
                && let TransportAddr::Relay(url) = path.remote_addr()
            {
                Some(url.clone())
            } else {
                None
            }
        });
        let kill_first = selected_relay.as_ref() == Some(&relays[0]);
        println!("SPIKE selected relay={selected_relay:?} kill_first={kill_first}");
        let mut r1 = Some(relay1);
        let mut r2 = Some(relay2);
        if kill_first {
            r1.take().unwrap().shutdown().await.unwrap();
        } else {
            r2.take().unwrap().shutdown().await.unwrap();
        }
        let start = Instant::now();
        let mut first_ok = None;
        let mut events = conn.path_events();
        loop {
            if first_ok.is_none() && probe(&conn).await {
                first_ok = Some(start.elapsed());
            }
            match tokio::time::timeout(Duration::from_millis(500), events.next()).await {
                Ok(Some(event)) => {
                    let kind = match &event {
                        iroh::endpoint::PathEvent::Opened { remote_addr, .. } => {
                            format!("opened {remote_addr:?}")
                        }
                        iroh::endpoint::PathEvent::Closed { remote_addr, .. } => {
                            format!("closed {remote_addr:?}")
                        }
                        iroh::endpoint::PathEvent::Selected { remote_addr, .. } => {
                            format!("selected {remote_addr:?}")
                        }
                        iroh::endpoint::PathEvent::Lagged { missed, .. } => {
                            format!("lagged {missed}")
                        }
                        _ => "other".to_string(),
                    };
                    println!("SPIKE event at {:?}: {kind}", start.elapsed());
                }
                Ok(None) => {
                    println!("SPIKE event stream ended at {:?}", start.elapsed());
                    break;
                }
                Err(_) => {}
            }
            if start.elapsed() > Duration::from_secs(20) {
                break;
            }
        }
        dump(&conn, "after-kill");
        println!("SPIKE first successful stream after relay1 kill: {first_ok:?}");
        conn.close(0u8.into(), b"spike done");
        a.close().await;
        b.close().await;
        drop(r1);
        drop(r2);
    }

    #[test]
    fn standby_port_zero_stays_ephemeral() {
        assert_eq!(standby_listen_port(Some(0)), Some(0));
        assert_eq!(standby_listen_port(Some(5901)), Some(5902));
        assert_eq!(standby_listen_port(None), None);
        assert_eq!(standby_listen_port(Some(u16::MAX)), None);
    }

    #[tokio::test]
    async fn dual_relay_links_fail_over_when_the_active_connection_closes() {
        let (relay1, url1) = start_relay().await;
        let (relay2, url2) = start_relay().await;
        let base =
            std::env::temp_dir().join(format!("stellaris-dual-relay-{}", uuid::Uuid::now_v7()));
        std::fs::create_dir_all(&base).unwrap();
        let network = NetworkId::new();
        let (tx_a, _rx_a) = mpsc::channel(64);
        let (tx_b, _rx_b) = mpsc::channel(64);
        let config_a = config_multi(
            "a",
            &base.join("a"),
            &[url1.clone(), url2.clone()],
            "10.8.0.1",
        );
        let config_b = config_multi(
            "b",
            &base.join("b"),
            &[url1.clone(), url2.clone()],
            "10.8.0.2",
        );
        let state_a = crate::AgentState::build(config_a.clone()).unwrap();
        let state_b = crate::AgentState::build(config_b.clone()).unwrap();
        let a = IrohTransport::start(
            state_a,
            Arc::new(config_a),
            network,
            [11u8; 32],
            PeerRegistry::from_config(
                &Config::from_toml(&format!(
                    r#"
[node]
name = "a"
state_dir = "{}"
[network]
name = "relay-use"
cidr = "10.8.0.0/16"
"#,
                    base.join("a").display()
                ))
                .unwrap(),
            )
            .unwrap(),
            tx_a,
            None,
        )
        .await
        .unwrap();
        let b = IrohTransport::start(
            state_b,
            Arc::new(config_b),
            network,
            [12u8; 32],
            PeerRegistry::from_config(
                &Config::from_toml(&format!(
                    r#"
[node]
name = "b"
state_dir = "{}"
[network]
name = "relay-use"
cidr = "10.8.0.0/16"
"#,
                    base.join("b").display()
                ))
                .unwrap(),
            )
            .unwrap(),
            tx_b,
            None,
        )
        .await
        .unwrap();
        let a_id = NodeId::new(*a.endpoint_id().as_bytes());
        let b_id = NodeId::new(*b.endpoint_id().as_bytes());
        a.add_peer(
            PeerConfig {
                name: "b".into(),
                endpoint_id: b_id.to_string(),
                overlay_ip: "10.8.0.2".parse().unwrap(),
                addrs: vec![],
                relay_url: Some(url1.clone()),
                advertised: vec![],
                zone: None,
            },
            true,
        );
        b.add_peer(
            PeerConfig {
                name: "a".into(),
                endpoint_id: a_id.to_string(),
                overlay_ip: "10.8.0.1".parse().unwrap(),
                addrs: vec![],
                relay_url: Some(url1.clone()),
                advertised: vec![],
                zone: None,
            },
            true,
        );
        let mut links = 0;
        for _ in 0..100 {
            links = a
                .conns
                .read()
                .unwrap_or_else(|e| e.into_inner())
                .get(&b_id)
                .map(|peer| peer.links.len())
                .unwrap_or(0);
            if links >= 2 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert_eq!(links, 2, "both relay links should be established");
        a.send(b_id, Bytes::from_static(b"primary")).await.unwrap();
        let old_active = a.active_stable(b_id).expect("active link");
        let old_conn = a
            .conns
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .get(&b_id)
            .and_then(|peer| peer.active_conn())
            .expect("active connection");
        old_conn.close(0u8.into(), b"test failover");
        let mut switched = None;
        for _ in 0..100 {
            if let Some(active) = a.active_stable(b_id)
                && active != old_active
                && a.send(b_id, Bytes::from_static(b"standby")).await.is_ok()
            {
                switched = Some(active);
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert!(switched.is_some(), "standby link should take over");

        // A revoked peer must not churn while blocked, but must be able to
        // reconnect when the controller authorizes it again.
        a.close_peer(b_id);
        tokio::time::sleep(Duration::from_secs(1)).await;
        assert!(
            a.conns
                .read()
                .unwrap_or_else(|e| e.into_inner())
                .get(&b_id)
                .is_none(),
            "revoked peer should have no live links"
        );
        a.allow_peer(b_id);
        let mut restored = 0;
        for _ in 0..100 {
            restored = a
                .conns
                .read()
                .unwrap_or_else(|e| e.into_inner())
                .get(&b_id)
                .map(|peer| peer.links.len())
                .unwrap_or(0);
            if restored >= 2 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert_eq!(restored, 2, "re-authorized peer should reconnect");

        // A credential revision change closes the links so the next handshake
        // presents the new credential, but must not fence the peer: the
        // connect loop has to bring both links back without a controller
        // snapshot calling `allow_peer`.
        a.reconnect_peer(b_id);
        let mut reconnected = 0;
        for _ in 0..100 {
            reconnected = a
                .conns
                .read()
                .unwrap_or_else(|e| e.into_inner())
                .get(&b_id)
                .map(|peer| peer.links.len())
                .unwrap_or(0);
            if reconnected >= 2 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert_eq!(
            reconnected, 2,
            "credential-change reconnect must not leave the peer blocked"
        );
        a.endpoint.close().await;
        b.endpoint.close().await;
        relay1.shutdown().await.unwrap();
        relay2.shutdown().await.unwrap();
        let _ = std::fs::remove_dir_all(base);
    }
}
