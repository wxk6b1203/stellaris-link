//! Peer-to-peer LSA exchange over iroh bi-directional control streams.
//!
//! Each connection carries length-prefixed JSON `ControlFrame`s. Besides LSAs,
//! the stream has a Ping/Pong heartbeat so a dead peer is detected even when
//! the QUIC path does not close immediately.

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::Context;
use serde::{Deserialize, Serialize};
use stellaris_linkstate::{Link, LinkStateDb, Lsa, Prefix};
use stellaris_types::NodeId;
use tokio::sync::{Mutex, broadcast, mpsc};
use tracing::{debug, info, warn};

use crate::AgentState;
use crate::transport::{ControlEvent, IrohTransport};

const MAX_FRAME: usize = 1 << 20;
const HEARTBEAT: Duration = Duration::from_secs(2);
const PEER_TIMEOUT: Duration = Duration::from_secs(7);

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum ControlFrame {
    Lsa { lsa: Lsa },
    Ping { seq: u64 },
    Pong { seq: u64 },
}

pub struct Service {
    state: AgentState,
    transport: Arc<IrohTransport>,
    db: RwLock<LinkStateDb>,
    tx: broadcast::Sender<Lsa>,
    connections: RwLock<HashMap<NodeId, u32>>,
    seq: AtomicU64,
}

pub async fn run(
    state: AgentState,
    mut conn_rx: mpsc::Receiver<ControlEvent>,
    transport: Arc<IrohTransport>,
) {
    let (tx, _) = broadcast::channel(256);
    let service = Arc::new(Service {
        state: state.clone(),
        transport,
        db: RwLock::new(LinkStateDb::new()),
        tx,
        connections: RwLock::new(HashMap::new()),
        seq: AtomicU64::new(now_seq()),
    });
    service.publish_local();
    info!(node = %state.node_id.short(), "link-state service started");

    {
        let service = service.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_secs(5));
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                tick.tick().await;
                service.publish_local();
                let removed = service
                    .db
                    .write()
                    .unwrap_or_else(|e| e.into_inner())
                    .expire(Duration::from_secs(30));
                if removed > 0 {
                    service.recompute();
                }
            }
        });
    }

    while let Some(event) = conn_rx.recv().await {
        match event {
            ControlEvent::Up { node, conn } => {
                let first = {
                    let mut connections = service
                        .connections
                        .write()
                        .unwrap_or_else(|e| e.into_inner());
                    let count = connections.entry(node).or_insert(0);
                    *count += 1;
                    *count == 1
                };
                if first {
                    service.publish_local();
                }
                let service = service.clone();
                tokio::spawn(async move {
                    if let Err(e) = peer_task(service.clone(), node, conn).await {
                        debug!(error = %e, "link-state peer task ended");
                    }
                    service.on_down(node);
                });
            }
            ControlEvent::Down { node } => {
                service.on_down(node);
            }
        }
    }
}

impl Service {
    fn publish_local(&self) {
        let connected: HashSet<NodeId> = self
            .connections
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .keys()
            .copied()
            .collect();
        let seq = self.seq.fetch_add(1, Ordering::Relaxed);
        let lsa = local_lsa(&self.state, seq, &connected);
        self.publish(lsa);
    }

    fn publish(&self, lsa: Lsa) {
        if lsa.origin != self.state.node_id && !crate::membership::lsa_authorized(&self.state, &lsa)
        {
            tracing::debug!(origin = %lsa.origin.short(), "unauthorized LSA dropped");
            return;
        }
        self.discover(&lsa);
        let changed = {
            let mut db = self.db.write().unwrap_or_else(|e| e.into_inner());
            db.apply(lsa.clone())
        };
        if !changed {
            return;
        }
        self.recompute();
        let _ = self.tx.send(lsa);
    }

    fn discover(&self, lsa: &Lsa) {
        if lsa.origin == self.state.node_id || self.state.peers.get(&lsa.origin).is_some() {
            return;
        }
        let (Some(overlay_ip), false) = (lsa.overlay_ip, lsa.addrs.is_empty()) else {
            return;
        };
        let peer = stellaris_types::PeerConfig {
            name: format!("auto-{}", lsa.origin.short()),
            endpoint_id: lsa.origin.to_string(),
            overlay_ip,
            addrs: lsa.addrs.clone(),
            relay_url: None,
            advertised: lsa.prefixes.iter().map(|p| p.prefix).collect(),
            zone: lsa.zone.clone(),
        };
        if self.transport.add_peer(peer, false) {
            info!(peer = %lsa.origin.short(), "discovered peer via LSA");
        }
    }

    fn on_down(&self, node: NodeId) {
        let removed = {
            let mut connections = self.connections.write().unwrap_or_else(|e| e.into_inner());
            if let Some(count) = connections.get_mut(&node) {
                *count = count.saturating_sub(1);
                if *count == 0 {
                    connections.remove(&node);
                    true
                } else {
                    false
                }
            } else {
                false
            }
        };
        if removed {
            self.publish_local();
        }
    }

    fn recompute(&self) {
        let mut routes = {
            let db = self.db.read().unwrap_or_else(|e| e.into_inner());
            db.compute_routes(self.state.node_id, self.state.network)
        };
        if self.state.config.routing.prefer_same_zone
            && let Some(local_zone) = self.state.config.node.zone.as_deref()
        {
            for route in &mut routes {
                if route.attrs.zone.as_deref() == Some(local_zone) {
                    route.local_pref = route.local_pref.saturating_add(100);
                }
            }
        }
        if let Err(e) = self.state.routes.replace_link_state_routes(routes) {
            warn!(error = %e, "failed to install link-state routes");
        }
    }

    fn snapshot(&self) -> Vec<Lsa> {
        let db = self.db.read().unwrap_or_else(|e| e.into_inner());
        db.all().cloned().collect()
    }
}

async fn peer_task(
    service: Arc<Service>,
    node: NodeId,
    conn: iroh::endpoint::Connection,
) -> anyhow::Result<()> {
    info!(peer = %node.short(), "link-state control connection");
    let mut events = service.tx.subscribe();
    let (mut send, _recv) = conn.open_bi().await.context("open LSA stream")?;
    for lsa in service.snapshot() {
        write_frame(&mut send, &ControlFrame::Lsa { lsa }).await?;
    }
    let send = Arc::new(Mutex::new(send));
    let last_pong = Arc::new(Mutex::new(Instant::now()));
    let reader = {
        let service = service.clone();
        let conn = conn.clone();
        let send = send.clone();
        let last_pong = last_pong.clone();
        tokio::spawn(async move {
            loop {
                let Ok((_send, mut recv)) = conn.accept_bi().await else {
                    break;
                };
                while let Some(frame) = read_frame(&mut recv).await? {
                    match frame {
                        ControlFrame::Lsa { lsa } => service.publish(lsa),
                        ControlFrame::Ping { seq } => {
                            let mut guard = send.lock().await;
                            write_frame(&mut guard, &ControlFrame::Pong { seq }).await?;
                        }
                        ControlFrame::Pong { .. } => {
                            *last_pong.lock().await = Instant::now();
                        }
                    }
                }
            }
            Ok::<_, anyhow::Error>(())
        })
    };

    let mut heartbeat = tokio::time::interval(HEARTBEAT);
    heartbeat.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut ping_seq = 0u64;
    loop {
        tokio::select! {
            _ = conn.closed() => break,
            _ = heartbeat.tick() => {
                if last_pong.lock().await.elapsed() > PEER_TIMEOUT {
                    warn!(peer = %node.short(), "link-state peer heartbeat timeout");
                    service.on_down(node);
                    // Never close the shared transport connection here: it also
                    // carries dataplane datagrams. Just stop this control peer task.
                    break;
                }
                ping_seq = ping_seq.wrapping_add(1);
                let mut guard = send.lock().await;
                if write_frame(&mut guard, &ControlFrame::Ping { seq: ping_seq }).await.is_err() {
                    service.on_down(node);
                    break;
                }
            }
            event = events.recv() => match event {
                Ok(lsa) => {
                    let mut guard = send.lock().await;
                    if write_frame(&mut guard, &ControlFrame::Lsa { lsa }).await.is_err() {
                        service.on_down(node);
                        break;
                    }
                }
                Err(broadcast::error::RecvError::Lagged(_)) => {
                    let mut guard = send.lock().await;
                    for lsa in service.snapshot() {
                        if write_frame(&mut guard, &ControlFrame::Lsa { lsa }).await.is_err() {
                            break;
                        }
                    }
                }
                Err(broadcast::error::RecvError::Closed) => break,
            }
        }
    }
    let _ = reader.await;
    Ok(())
}

async fn write_frame(
    send: &mut iroh::endpoint::SendStream,
    frame: &ControlFrame,
) -> anyhow::Result<()> {
    let bytes = serde_json::to_vec(frame).context("serialize control frame")?;
    if bytes.len() > MAX_FRAME {
        anyhow::bail!("control frame too large");
    }
    send.write_all(&(bytes.len() as u32).to_be_bytes()).await?;
    send.write_all(&bytes).await?;
    Ok(())
}

async fn read_frame(recv: &mut iroh::endpoint::RecvStream) -> anyhow::Result<Option<ControlFrame>> {
    let mut len = [0u8; 4];
    if let Err(e) = recv.read_exact(&mut len).await {
        debug!(error = %e, "control stream closed");
        return Ok(None);
    }
    let len = u32::from_be_bytes(len) as usize;
    if len == 0 || len > MAX_FRAME {
        anyhow::bail!("invalid control frame length {len}");
    }
    let mut bytes = vec![0u8; len];
    recv.read_exact(&mut bytes).await?;
    Ok(Some(
        serde_json::from_slice(&bytes).context("parse control frame")?,
    ))
}

fn local_lsa(state: &AgentState, seq: u64, connected: &HashSet<NodeId>) -> Lsa {
    let links = state
        .peers
        .list()
        .into_iter()
        .filter_map(|peer| {
            let to: NodeId = peer.endpoint_id.parse().ok()?;
            if !connected.contains(&to) {
                return None;
            }
            Some(Link {
                to,
                metric: link_metric(state, &peer),
                zone: peer.zone.clone(),
            })
        })
        .collect();

    let mut prefixes = Vec::new();
    if let Some(ip) = state.config.node.overlay_ip {
        prefixes.push(Prefix {
            prefix: stellaris_types::host_prefix(ip),
            metric: 0,
        });
    }
    for prefix in &state.config.dataplane.advertise {
        prefixes.push(Prefix {
            prefix: *prefix,
            metric: 10,
        });
    }

    Lsa {
        origin: state.node_id,
        seq,
        zone: state.config.node.zone.clone(),
        links,
        prefixes,
        overlay_ip: state.config.node.overlay_ip,
        addrs: state.config.transport.advertise.clone(),
    }
}

fn link_metric(state: &AgentState, peer: &crate::PeerState) -> u32 {
    let latency = peer
        .rtt_ms
        .map(|rtt| ((rtt / 10).max(1)) as u32)
        .unwrap_or(1);
    let cross_zone = state.config.node.zone.is_some()
        && peer.zone.is_some()
        && state.config.node.zone != peer.zone;
    if cross_zone {
        latency.saturating_add(state.config.routing.cross_zone_penalty)
    } else {
        latency
    }
}

fn now_seq() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(1)
}

#[cfg(test)]
mod tests {
    use super::*;
    use stellaris_types::Config;

    #[test]
    fn cross_zone_link_gets_penalty() {
        let dir =
            std::env::temp_dir().join(format!("stellaris-ls-metric-test-{}", uuid::Uuid::now_v7()));
        std::fs::create_dir_all(&dir).unwrap();
        let toml = format!(
            r#"
[node]
name = "a"
state_dir = "{}"
overlay_ip = "10.7.0.1"
zone = "az-a"

[network]
name = "demo"
cidr = "10.7.0.0/16"

[routing]
link_state = true
cross_zone_penalty = 20

[[peers]]
name = "b"
endpoint_id = "{}"
overlay_ip = "10.7.0.2"
zone = "az-b"
"#,
            dir.display(),
            hex::encode([2u8; 32])
        );
        let state = AgentState::build(Config::from_toml(&toml).unwrap()).unwrap();
        let connected = HashSet::from([NodeId::new([2u8; 32])]);
        let lsa = local_lsa(&state, 1, &connected);
        assert_eq!(lsa.links[0].metric, 21);
        assert_eq!(lsa.links[0].zone.as_deref(), Some("az-b"));

        state.peers.mark(
            &NodeId::new([2u8; 32]),
            true,
            Some("direct".into()),
            Some(100),
            Some(1200),
            None,
            0,
        );
        let lsa = local_lsa(&state, 2, &connected);
        assert_eq!(lsa.links[0].metric, 30);
    }
}
