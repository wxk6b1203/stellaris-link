//! iroh transport: one endpoint, static peers, unreliable datagrams.

use std::collections::HashMap;
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
    network: NetworkId,
    local: NodeId,
    peers: PeerRegistry,
    inbound_tx: mpsc::Sender<InboundPacket>,
    control_tx: Option<mpsc::Sender<ControlEvent>>,
    conns: Arc<RwLock<HashMap<NodeId, iroh::endpoint::Connection>>>,
    conn_ids: Arc<RwLock<HashMap<NodeId, usize>>>,
}

impl IrohTransport {
    pub async fn start(
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
        if config.transport.disable_relay {
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
        if !config.transport.disable_relay {
            endpoint.online().await;
        }
        let me = endpoint.id();
        let local = NodeId::new(*me.as_bytes());
        info!(endpoint = %me, addr = ?endpoint.addr(), "iroh endpoint ready");

        let transport = Arc::new(Self {
            endpoint: endpoint.clone(),
            config: config.clone(),
            network,
            local,
            peers: peers.clone(),
            inbound_tx: inbound_tx.clone(),
            control_tx: control_tx.clone(),
            conns: Arc::new(RwLock::new(HashMap::new())),
            conn_ids: Arc::new(RwLock::new(HashMap::new())),
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
                    if accept_config.network.auth.mode == AuthMode::Psk {
                        let secret = accept_config.network.auth.secret.as_deref().unwrap_or("");
                        let auth = tokio::time::timeout(
                            Duration::from_secs(5),
                            crate::membership::authenticate_server(
                                &conn,
                                transport.network,
                                transport.local,
                                secret,
                                &accept_config.network.auth.allowed_nodes,
                            ),
                        )
                        .await;
                        if !matches!(auth, Ok(Ok(_))) {
                            warn!(peer = %node.short(), "membership authentication failed");
                            conn.close(2u8.into(), b"auth failed");
                            continue;
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
                    let (path, rtt) = path_status(&conn);
                    transport.peers.mark(&node, true, path, rtt);
                    spawn_path_watch(conn.clone(), node, transport.peers.clone());
                    let tx = accept_tx.clone();
                    let peers = transport.peers.clone();
                    let network_hash = network_hash(transport.network);
                    let down_tx = control_tx.clone();
                    tokio::spawn(async move {
                        read_loop(conn, node, network_hash, tx).await;
                        peers.mark(&node, false, None, None);
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

fn path_status(conn: &iroh::endpoint::Connection) -> (Option<String>, Option<u64>) {
    let paths = conn.paths();
    for path in paths.iter() {
        if path.is_selected() {
            let kind = if path.is_relay() {
                "relay"
            } else if path.is_ip() {
                "direct"
            } else {
                "other"
            };
            return (Some(kind.to_string()), Some(path.rtt().as_millis() as u64));
        }
    }
    (None, None)
}

fn spawn_path_watch(conn: iroh::endpoint::Connection, node: NodeId, peers: PeerRegistry) {
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(5)).await;
            if conn.paths().is_empty() {
                break;
            }
            let (path, rtt) = path_status(&conn);
            peers.mark(&node, true, path, rtt);
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
    let addr = EndpointAddr::from_parts(remote, addrs);
    loop {
        match transport.endpoint.connect(addr.clone(), DATA_ALPN).await {
            Ok(conn) => {
                if transport.config.network.auth.mode == AuthMode::Psk {
                    let secret = transport
                        .config
                        .network
                        .auth
                        .secret
                        .as_deref()
                        .unwrap_or("");
                    let auth = tokio::time::timeout(
                        Duration::from_secs(5),
                        crate::membership::authenticate_client(
                            &conn,
                            transport.network,
                            transport.local,
                            node,
                            secret,
                        ),
                    )
                    .await;
                    if !matches!(auth, Ok(Ok(()))) {
                        warn!(peer = %peer.name, "membership authentication failed");
                        conn.close(2u8.into(), b"auth failed");
                        tokio::time::sleep(Duration::from_secs(2)).await;
                        continue;
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
                let (path, rtt) = path_status(&conn);
                transport.peers.mark(&node, true, path, rtt);
                spawn_path_watch(conn.clone(), node, transport.peers.clone());
                let tx = inbound_tx.clone();
                let peers = transport.peers.clone();
                let network_hash = network_hash(transport.network);
                let conn2 = conn.clone();
                let down_tx = control_tx.clone();
                tokio::spawn(async move {
                    read_loop(conn2, node, network_hash, tx).await;
                    peers.mark(&node, false, None, None);
                    if let Some(tx) = &down_tx {
                        let _ = tx.send(ControlEvent::Down { node }).await;
                    }
                });
                let stable_id = conn.stable_id();
                conn.closed().await;
                transport.remove_conn_if(node, stable_id);
                transport.peers.mark(&node, false, None, None);
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
