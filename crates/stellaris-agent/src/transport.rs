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
    },
    Down {
        node: NodeId,
    },
}

pub struct IrohTransport {
    endpoint: Endpoint,
    config: Arc<Config>,
    state: crate::AgentState,
    controller_keys: Vec<NodeId>,
    /// Endpoint ids allowed to connect in `AuthMode::Static`.
    static_keys: HashSet<NodeId>,
    network: NetworkId,
    peers: PeerRegistry,
    inbound_tx: mpsc::Sender<InboundPacket>,
    control_tx: Option<mpsc::Sender<ControlEvent>>,
    conns: Arc<RwLock<HashMap<NodeId, iroh::endpoint::Connection>>>,
    conn_ids: Arc<RwLock<HashMap<NodeId, usize>>>,
    /// Configured relays tried when reconnecting to a peer, in order.
    relay_fallbacks: Vec<RelayUrl>,
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
        let mut builder = Endpoint::builder(presets::N0)
            .secret_key(secret)
            .alpns(vec![DATA_ALPN.to_vec()]);
        if let Some(port) = config.transport.listen_port {
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
        let relay_disabled = match config.transport.relay_mode {
            stellaris_types::RelayModeConfig::Disabled => true,
            stellaris_types::RelayModeConfig::Custom => false,
            stellaris_types::RelayModeConfig::N0 => false,
            stellaris_types::RelayModeConfig::Auto => config.transport.disable_relay,
        };
        if relay_disabled {
            builder = builder.relay_mode(RelayMode::Disabled);
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
        let endpoint = builder.bind().await.context("bind iroh endpoint")?;
        if !relay_disabled {
            endpoint.online().await;
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
            config: config.clone(),
            state,
            controller_keys,
            static_keys,
            network,
            peers: peers.clone(),
            inbound_tx: inbound_tx.clone(),
            control_tx: control_tx.clone(),
            conns: Arc::new(RwLock::new(HashMap::new())),
            conn_ids: Arc::new(RwLock::new(HashMap::new())),
            relay_fallbacks: config
                .transport
                .relay_urls
                .iter()
                .filter_map(|url| url.parse().ok())
                .collect(),
        });

        // Accept loop: authenticated iroh connection -> peer reader.
        {
            let transport = transport.clone();
            let accept_tx = inbound_tx.clone();
            let control_tx = control_tx.clone();
            let accept_config = config.clone();
            tokio::spawn(async move {
                loop {
                    let Some(incoming) = transport.endpoint.accept().await else {
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
                    let remote = conn.remote_id();
                    let node = NodeId::new(*remote.as_bytes());
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
                    info!(peer = %node.short(), "inbound iroh connection");
                    transport.insert_conn(node, conn.clone());
                    if let Some(tx) = &control_tx {
                        let _ = tx
                            .send(ControlEvent::Up {
                                node,
                                conn: conn.clone(),
                            })
                            .await;
                    }
                    let (path, rtt, mtu, addr, path_count) = path_status(&conn);
                    transport
                        .peers
                        .mark(&node, true, path, rtt, mtu, addr, path_count);
                    spawn_path_watch(conn.clone(), node, transport.peers.clone());
                    let tx = accept_tx.clone();
                    let peers = transport.peers.clone();
                    let network_hash = network_hash(transport.network);
                    let down_tx = control_tx.clone();
                    tokio::spawn(async move {
                        read_loop(conn, node, network_hash, tx).await;
                        peers.mark(&node, false, None, None, None, None, 0);
                        if let Some(tx) = &down_tx {
                            let _ = tx.send(ControlEvent::Down { node }).await;
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
        let transport = self.clone();
        let tx = self.inbound_tx.clone();
        let control_tx = self.control_tx.clone();
        tokio::spawn(async move {
            connect_loop(transport, peer, tx, control_tx).await;
        });
        true
    }

    pub fn endpoint_id(&self) -> EndpointId {
        self.endpoint.id()
    }

    /// Force-close a peer connection (used when the controller revokes it).
    pub fn close_peer(&self, node: NodeId) {
        let conn = self
            .conns
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&node);
        if let Some(conn) = conn {
            conn.close(3u8.into(), b"revoked");
            warn!(peer = %node.short(), "closed revoked peer connection");
        }
        self.state.drop_grant(node);
    }

    /// Minimum application datagram size across active connections, if any.
    pub fn max_datagram_size(&self) -> Option<usize> {
        let guard = self.conns.read().unwrap_or_else(|e| e.into_inner());
        guard.values().filter_map(|c| c.max_datagram_size()).min()
    }

    pub async fn send(&self, node: NodeId, packet: Bytes) -> anyhow::Result<()> {
        let conn = {
            let guard = self.conns.read().unwrap_or_else(|e| e.into_inner());
            guard.get(&node).cloned()
        };
        let Some(conn) = conn else {
            bail!("peer {} not connected", node.short());
        };
        if let Some(max) = conn.max_datagram_size()
            && packet.len() > max
        {
            bail!("datagram too large: {} > {}", packet.len(), max);
        }
        conn.send_datagram(packet).context("send_datagram")?;
        Ok(())
    }

    fn insert_conn(&self, node: NodeId, conn: iroh::endpoint::Connection) {
        let stable_id = conn.stable_id();
        info!(peer = %node.short(), stable_id, "connection installed");
        self.conns
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .insert(node, conn);
        self.conn_ids
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .insert(node, stable_id);
    }

    fn remove_conn_if(&self, node: NodeId, stable_id: usize) {
        let current = self
            .conn_ids
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .get(&node)
            .copied();
        info!(peer = %node.short(), stable_id, current, "connection close observed");
        if current == Some(stable_id) {
            self.conns
                .write()
                .unwrap_or_else(|e| e.into_inner())
                .remove(&node);
            self.conn_ids
                .write()
                .unwrap_or_else(|e| e.into_inner())
                .remove(&node);
        }
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
                    _ => None,
                },
                path_count,
            );
        }
    }
    (None, None, None, None, 0)
}

fn spawn_path_watch(conn: iroh::endpoint::Connection, node: NodeId, peers: PeerRegistry) {
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(5)).await;
            if conn.paths().is_empty() {
                break;
            }
            let (path, rtt, mtu, addr, path_count) = path_status(&conn);
            peers.mark(&node, true, path, rtt, mtu, addr, path_count);
        }
    });
}

async fn connect_loop(
    transport: Arc<IrohTransport>,
    peer: PeerConfig,
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
    for addr in &peer.addrs {
        addrs.push(TransportAddr::Ip(*addr));
    }
    if let Some(relay) = &peer.relay_url {
        match relay.parse::<RelayUrl>() {
            Ok(url) => addrs.push(TransportAddr::Relay(url)),
            Err(e) => warn!(peer = %peer.name, error = %e, "invalid relay_url"),
        }
    }
    // Fall back to every configured relay so a dead home relay does not pin
    // reconnects to the same dead endpoint.
    for relay in &transport.relay_fallbacks {
        let candidate = TransportAddr::Relay(relay.clone());
        if !addrs.contains(&candidate) {
            addrs.push(candidate);
        }
    }
    let addr = EndpointAddr::from_parts(remote, addrs);
    loop {
        match transport.endpoint.connect(addr.clone(), DATA_ALPN).await {
            Ok(conn) => {
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
                info!(peer = %peer.name, "outbound iroh connected");
                transport.insert_conn(node, conn.clone());
                if let Some(tx) = &control_tx {
                    let _ = tx
                        .send(ControlEvent::Up {
                            node,
                            conn: conn.clone(),
                        })
                        .await;
                }
                let (path, rtt, mtu, addr, path_count) = path_status(&conn);
                transport
                    .peers
                    .mark(&node, true, path, rtt, mtu, addr, path_count);
                spawn_path_watch(conn.clone(), node, transport.peers.clone());
                let tx = inbound_tx.clone();
                let peers = transport.peers.clone();
                let network_hash = network_hash(transport.network);
                let conn2 = conn.clone();
                let down_tx = control_tx.clone();
                tokio::spawn(async move {
                    read_loop(conn2, node, network_hash, tx).await;
                    peers.mark(&node, false, None, None, None, None, 0);
                    if let Some(tx) = &down_tx {
                        let _ = tx.send(ControlEvent::Down { node }).await;
                    }
                });
                let stable_id = conn.stable_id();
                conn.closed().await;
                transport.remove_conn_if(node, stable_id);
                transport.state.drop_grant(node);
                transport
                    .peers
                    .mark(&node, false, None, None, None, None, 0);
                if let Some(tx) = &control_tx {
                    let _ = tx.send(ControlEvent::Down { node }).await;
                }
                warn!(peer = %peer.name, "connection closed; reconnecting");
            }
            Err(e) => {
                debug!(peer = %peer.name, error = %e, "connect failed");
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
        for _ in 0..100 {
            if a.peers.get(&b_id).is_some_and(|p| p.connected)
                && b.peers.get(&a_id).is_some_and(|p| p.connected)
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
}
