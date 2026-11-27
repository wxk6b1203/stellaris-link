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
    /// Remote address of the selected transport path, if direct/relay IP.
    pub path_addr: Option<String>,
    /// Number of currently open transport paths.
    pub path_count: usize,
    /// Path MTU reported by the current transport path, if known.
    pub mtu: Option<u16>,
    /// Number of selected-path changes observed for this peer.
    pub path_changes: u64,
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
                    path_addr: None,
                    path_count: 0,
                    mtu: None,
                    path_changes: 0,
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

    #[allow(clippy::too_many_arguments)]
    pub fn mark(
        &self,
        node: &NodeId,
        connected: bool,
        path: Option<String>,
        rtt_ms: Option<u64>,
        mtu: Option<u16>,
        path_addr: Option<String>,
        path_count: usize,
    ) {
        let mut guard = self.inner.write().unwrap_or_else(|e| e.into_inner());
        if let Some(peer) = guard.get_mut(node) {
            // A relay-to-relay switch keeps `path == "relay"`; compare the
            // concrete address as well so the API and metrics reflect it.
            if connected
                && path.is_some()
                && (peer.path != path || (peer.connected && peer.path_addr != path_addr))
            {
                peer.path_changes = peer.path_changes.saturating_add(1);
            }
            peer.connected = connected;
            peer.path = path;
            peer.rtt_ms = rtt_ms;
            peer.mtu = mtu;
            peer.path_addr = path_addr;
            peer.path_count = path_count;
        }
    }

    /// Update the overlay address of an existing peer; returns true if it
    /// changed.
    pub fn update_overlay(&self, node: &NodeId, ip: IpAddr) -> bool {
        let mut guard = self.inner.write().unwrap_or_else(|e| e.into_inner());
        if let Some(peer) = guard.get_mut(node)
            && peer.overlay_ip != ip
        {
            peer.overlay_ip = ip;
            return true;
        }
        false
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

#[cfg(test)]
mod tests {
    use super::*;
    use stellaris_types::Config;

    #[test]
    fn path_changes_count_selected_path_switches() {
        let dir = std::env::temp_dir().join(format!("stellaris-peers-{}", uuid::Uuid::now_v7()));
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
endpoint_id = "0202020202020202020202020202020202020202020202020202020202020202"
overlay_ip = "10.7.0.2"
"#,
            dir.display()
        );
        let registry = PeerRegistry::from_config(&Config::from_toml(&toml).unwrap()).unwrap();
        let node: NodeId = "0202020202020202020202020202020202020202020202020202020202020202"
            .parse()
            .unwrap();
        registry.mark(
            &node,
            true,
            Some("direct".into()),
            Some(5),
            Some(1200),
            None,
            0,
        );
        registry.mark(
            &node,
            true,
            Some("direct".into()),
            Some(6),
            Some(1200),
            None,
            0,
        );
        assert_eq!(registry.get(&node).unwrap().path_changes, 1);
        registry.mark(
            &node,
            true,
            Some("relay".into()),
            Some(50),
            Some(1100),
            None,
            0,
        );
        assert_eq!(registry.get(&node).unwrap().path_changes, 2);
        // Relay-to-relay switches keep `path == "relay"`; the concrete relay
        // URL must still be counted.
        registry.mark(
            &node,
            true,
            Some("relay".into()),
            Some(51),
            Some(1100),
            Some("https://r1.example/".into()),
            0,
        );
        assert_eq!(registry.get(&node).unwrap().path_changes, 3);
        registry.mark(
            &node,
            true,
            Some("relay".into()),
            Some(52),
            Some(1100),
            Some("https://r2.example/".into()),
            0,
        );
        assert_eq!(registry.get(&node).unwrap().path_changes, 4);
        registry.mark(
            &node,
            true,
            Some("relay".into()),
            Some(53),
            Some(1100),
            Some("https://r2.example/".into()),
            0,
        );
        assert_eq!(registry.get(&node).unwrap().path_changes, 4);
    }
}
