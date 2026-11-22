use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, RwLock};

use anyhow::Context;
use ipnet::IpNet;
use serde::Serialize;
use stellaris_types::{Config, NodeId};

#[derive(Clone, Debug, Serialize)]
pub struct PeerState {
    pub node_id: NodeId,
    pub name: String,
    pub overlay_ip: IpAddr,
    pub endpoint_id: String,
    pub advertised: Vec<IpNet>,
    pub zone: Option<String>,
    pub connected: bool,
    pub path: Option<String>,
    pub rtt_ms: Option<u64>,
}

#[derive(Clone, Default)]
pub struct PeerRegistry {
    inner: Arc<RwLock<HashMap<NodeId, PeerState>>>,
}

impl PeerRegistry {
    pub fn from_config(config: &Config) -> anyhow::Result<Self> {
        let mut peers = HashMap::new();
        for peer in &config.peers {
            let node_id: NodeId = peer
                .endpoint_id
                .parse()
                .with_context(|| format!("peer {} endpoint_id", peer.name))?;
            peers.insert(
                node_id,
                PeerState {
                    node_id,
                    name: peer.name.clone(),
                    overlay_ip: peer.overlay_ip,
                    endpoint_id: peer.endpoint_id.clone(),
                    advertised: peer.advertised.clone(),
                    zone: peer.zone.clone(),
                    connected: false,
                    path: None,
                    rtt_ms: None,
                },
            );
        }
        Ok(Self {
            inner: Arc::new(RwLock::new(peers)),
        })
    }

    pub fn upsert(&self, peer: PeerState) {
        let mut guard = self.inner.write().unwrap_or_else(|e| e.into_inner());
        guard.insert(peer.node_id, peer);
    }

    pub fn list(&self) -> Vec<PeerState> {
        let guard = self.inner.read().unwrap_or_else(|e| e.into_inner());
        let mut out: Vec<_> = guard.values().cloned().collect();
        out.sort_by(|a, b| a.name.cmp(&b.name));
        out
    }

    pub fn get(&self, node: &NodeId) -> Option<PeerState> {
        let guard = self.inner.read().unwrap_or_else(|e| e.into_inner());
        guard.get(node).cloned()
    }

    pub fn mark(&self, node: &NodeId, connected: bool, path: Option<String>, rtt_ms: Option<u64>) {
        let mut guard = self.inner.write().unwrap_or_else(|e| e.into_inner());
        if let Some(peer) = guard.get_mut(node) {
            peer.connected = connected;
            peer.path = path;
            peer.rtt_ms = rtt_ms;
        }
    }

    pub fn connected_count(&self) -> usize {
        let guard = self.inner.read().unwrap_or_else(|e| e.into_inner());
        guard.values().filter(|p| p.connected).count()
    }

    pub fn total(&self) -> usize {
        let guard = self.inner.read().unwrap_or_else(|e| e.into_inner());
        guard.len()
    }
}
