//! Stellaris agent library: identity, peer registry, route engine, API.

pub mod api;
pub mod control_client;
pub mod control_wire;
pub mod controller;
pub mod controller_model;
pub mod controller_raft;
pub mod credential;
pub mod dataplane;
pub mod discovery;
pub mod gateway;
pub mod identity;
pub mod link_state;
pub mod lsa_auth;
pub mod membership;
pub mod peers;
pub mod policy;
pub mod reassembly;
pub mod serve;
pub mod stats;
pub mod transport;
pub mod wire;

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, RwLock};
use std::time::Instant;

use anyhow::Context;
use stellaris_routing::RouteEngine;
use stellaris_types::{Config, NetworkId, NodeId, PeerConfig, RouteAttributes};
use uuid::Uuid;

pub use peers::{PeerRegistry, PeerState};

#[derive(Clone)]
pub struct AgentState {
    pub config: Arc<Config>,
    pub network: NetworkId,
    pub node_id: NodeId,
    /// Ed25519 secret, used by the iroh transport.
    pub identity_secret: [u8; 32],
    pub routes: Arc<RouteEngine>,
    pub peers: PeerRegistry,
    pub grants: membership::GrantMap,
    /// Our own controller-signed membership credential, when configured.
    pub credential: Arc<RwLock<Option<credential::SignedCredential>>>,
    /// Highest credential revision observed per node (replay fencing).
    pub revisions: Arc<RwLock<HashMap<NodeId, u64>>>,
    /// Effective local overlay address (config or controller-allocated).
    pub local_overlay: Arc<RwLock<Option<std::net::IpAddr>>>,
    pub policy: Arc<RwLock<policy::Policy>>,
    pub stats: Arc<stats::Stats>,
    pub reassembly: Arc<std::sync::Mutex<reassembly::Reassembler>>,
    pub started_at: Instant,
}

/// Same-zone routes get a local_pref bonus; the zone is kept for explain/UI.
fn route_zone(config: &Config, peer: &PeerConfig) -> (u32, RouteAttributes) {
    let same_zone = config.routing.prefer_same_zone
        && config.node.zone.is_some()
        && config.node.zone == peer.zone;
    let attrs = RouteAttributes {
        zone: peer.zone.clone(),
        region: peer.zone.clone(),
        ..Default::default()
    };
    (if same_zone { 100 } else { 0 }, attrs)
}

impl AgentState {
    pub fn build(config: Config) -> anyhow::Result<Self> {
        config.validate().map_err(|e| anyhow::anyhow!(e))?;
        let state_dir = PathBuf::from(&config.node.state_dir);
        std::fs::create_dir_all(&state_dir)
            .with_context(|| format!("create state dir {}", state_dir.display()))?;

        let identity = identity::load_or_create(&state_dir)?;
        let network = config.network.id.unwrap_or_else(|| {
            NetworkId(Uuid::new_v5(
                &Uuid::NAMESPACE_DNS,
                config.network.name.as_bytes(),
            ))
        });

        let routes = Arc::new(RouteEngine::new(
            network,
            identity.node_id,
            config.routing.ecmp_max,
            config.routing.max_routes,
        ));

        let intents_path = state_dir.join("routes.json");
        if let Err(e) = routes.load(&intents_path) {
            tracing::warn!(error = %e, "failed to load persisted routes; starting empty");
        }

        // Direct peer /32 routes make the overlay reachable even with no static routes.
        for peer in &config.peers {
            let via: NodeId = peer.endpoint_id.parse().context("parse peer endpoint_id")?;
            let prefix = stellaris_types::host_prefix(peer.overlay_ip);
            let (pref, attrs) = route_zone(&config, peer);
            routes
                .add_static_with_attrs(
                    prefix,
                    via,
                    None,
                    Some(pref),
                    Some(0),
                    None,
                    false,
                    None,
                    attrs,
                    "peer",
                )
                .with_context(|| format!("seed peer route {}", peer.overlay_ip))?;
            for advertised in &peer.advertised {
                let (pref, attrs) = route_zone(&config, peer);
                routes
                    .add_static_with_attrs(
                        *advertised,
                        via,
                        None,
                        Some(pref),
                        Some(20),
                        None,
                        false,
                        None,
                        attrs,
                        "peer-advertised",
                    )
                    .with_context(|| {
                        format!("seed advertised route {advertised} via {}", peer.name)
                    })?;
            }
        }

        for route in &config.routes {
            let peer = config.peer_by_name(&route.via).ok_or_else(|| {
                anyhow::anyhow!("route {} via unknown peer {}", route.prefix, route.via)
            })?;
            let via: NodeId = peer.endpoint_id.parse().context("parse peer endpoint_id")?;
            let (pref, attrs) = route_zone(&config, peer);
            routes
                .add_static_with_attrs(
                    route.prefix,
                    via,
                    None,
                    Some(pref),
                    Some(10),
                    None,
                    false,
                    None,
                    attrs,
                    "config",
                )
                .with_context(|| format!("seed route {}", route.prefix))?;
        }

        routes
            .set_policies(config.routing.policies.clone())
            .context("apply route policies")?;

        let peers = PeerRegistry::from_config(&config)?;
        let policy_path = state_dir.join("policy.json");
        let policy = if let Ok(bytes) = std::fs::read(&policy_path) {
            match serde_json::from_slice::<policy::PolicyFile>(&bytes) {
                Ok(file) if file.validate().is_ok() => policy::Policy::from_file(file),
                _ => policy::Policy::from_config(config.acl.clone(), config.qos.clone()),
            }
        } else {
            policy::Policy::from_config(config.acl.clone(), config.qos.clone())
        };
        let policy = Arc::new(RwLock::new(policy));
        let credential = load_credential(&state_dir).filter(|credential| {
            credential.credential.network == network.to_string()
                && credential.credential.node == identity.node_id
        });
        let cached_overlay = if config.node.ipam == stellaris_types::IpamMode::Auto {
            credential
                .as_ref()
                .and_then(|credential| credential.credential.overlay_ip)
        } else {
            None
        };
        let local_overlay = config.node.overlay_ip.or(cached_overlay);

        Ok(Self {
            config: Arc::new(config),
            network,
            node_id: identity.node_id,
            identity_secret: identity.secret,
            routes,
            peers,
            grants: Arc::new(RwLock::new(HashMap::new())),
            credential: Arc::new(RwLock::new(credential)),
            revisions: Arc::new(RwLock::new(HashMap::new())),
            local_overlay: Arc::new(RwLock::new(local_overlay)),
            policy,
            stats: Arc::new(stats::Stats::default()),
            reassembly: Arc::new(std::sync::Mutex::new(reassembly::Reassembler::default())),
            started_at: Instant::now(),
        })
    }

    pub fn routes_path(&self) -> PathBuf {
        PathBuf::from(&self.config.node.state_dir).join("routes.json")
    }

    /// Effective overlay address for this node.
    pub fn local_overlay(&self) -> Option<std::net::IpAddr> {
        *self.local_overlay.read().unwrap_or_else(|e| e.into_inner())
    }

    pub fn set_local_overlay(&self, ip: std::net::IpAddr) {
        *self
            .local_overlay
            .write()
            .unwrap_or_else(|e| e.into_inner()) = Some(ip);
    }

    pub fn credential_path(&self) -> PathBuf {
        PathBuf::from(&self.config.node.state_dir).join("credential.json")
    }

    pub fn credential(&self) -> Option<credential::SignedCredential> {
        self.credential
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    /// Install a freshly issued credential and persist it for restarts.
    pub fn set_credential(&self, credential: credential::SignedCredential) {
        if let Some(existing) = self
            .revisions
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .get(&credential.credential.node)
        {
            tracing::debug!(revision = *existing, "replacing local credential");
        }
        self.observe_revision(credential.credential.node, credential.credential.revision);
        let path = self.credential_path();
        if let Some(parent) = path.parent()
            && let Err(e) = std::fs::create_dir_all(parent)
        {
            tracing::warn!(error = %e, path = %parent.display(), "create credential dir");
        }
        match serde_json::to_vec(&credential) {
            Ok(bytes) => match std::fs::write(&path, bytes) {
                Ok(()) => tracing::info!(path = %path.display(), "membership credential stored"),
                Err(e) => tracing::warn!(error = %e, "failed to persist membership credential"),
            },
            Err(e) => tracing::warn!(error = %e, "failed to serialize membership credential"),
        }
        *self.credential.write().unwrap_or_else(|e| e.into_inner()) = Some(credential);
    }

    /// Highest credential revision seen for `node`.
    pub fn revision(&self, node: NodeId) -> u64 {
        self.revisions
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .get(&node)
            .copied()
            .unwrap_or(0)
    }

    pub fn observe_revision(&self, node: NodeId, revision: u64) {
        let mut revisions = self.revisions.write().unwrap_or_else(|e| e.into_inner());
        let entry = revisions.entry(node).or_insert(0);
        if revision > *entry {
            *entry = revision;
        }
    }

    /// Record a peer's verified credential as its dataplane grant.
    pub fn install_grant(&self, credential: &credential::VerifiedCredential) {
        self.observe_revision(credential.node, credential.revision);
        self.grants
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .insert(
                credential.node,
                membership::Grant::from_verified(credential),
            );
    }

    pub fn drop_grant(&self, node: NodeId) {
        self.grants
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&node);
    }

    pub fn policy_path(&self) -> PathBuf {
        PathBuf::from(&self.config.node.state_dir).join("policy.json")
    }

    pub fn save_routes(&self) {
        if let Err(e) = self.routes.save(self.routes_path()) {
            tracing::warn!(error = %e, "failed to persist routes");
        }
    }
}

fn load_credential(state_dir: &std::path::Path) -> Option<credential::SignedCredential> {
    let path = state_dir.join("credential.json");
    let bytes = std::fs::read(&path).ok()?;
    match serde_json::from_slice(&bytes) {
        Ok(credential) => Some(credential),
        Err(e) => {
            tracing::warn!(error = %e, path = %path.display(), "ignoring invalid credential");
            None
        }
    }
}

pub async fn run(state: AgentState) -> anyhow::Result<()> {
    let (inbound_tx, mut inbound_rx) = tokio::sync::mpsc::channel(1024);
    let (control_tx, control_rx) = if state.config.routing.link_state {
        let (tx, rx) = tokio::sync::mpsc::channel(64);
        (Some(tx), Some(rx))
    } else {
        (None, None)
    };
    let control_configured =
        state.config.control.url.is_some() || state.config.control.endpoint_id.is_some();
    let want_transport = state.config.dataplane.enabled
        || !state.config.peers.is_empty()
        || control_configured
        || state.config.transport.discovery_port.is_some()
        || state.config.transport.mdns;
    if want_transport {
        let transport = transport::IrohTransport::start(
            state.clone(),
            state.config.clone(),
            state.network,
            state.identity_secret,
            state.peers.clone(),
            inbound_tx,
            control_tx,
        )
        .await?;
        if state.config.control.url.is_some() || state.config.control.endpoint_id.is_some() {
            let control_state = state.clone();
            let base = control_state.config.control.url.clone();
            let secret = control_state.config.control.secret.clone();
            let control_transport = transport.clone();
            tokio::spawn(async move {
                control_client::run(control_state, base, secret, Some(control_transport)).await;
            });
        }
        discovery::start(state.clone(), transport.clone());
        if let Some(rx) = control_rx {
            let state = state.clone();
            let transport = transport.clone();
            tokio::spawn(async move {
                link_state::run(state, rx, transport).await;
            });
        }
        if state.config.dataplane.enabled {
            dataplane::start(state.clone(), transport.clone(), inbound_rx).await?;
        } else {
            tracing::info!("transport-only mode (dataplane disabled)");
            tokio::spawn(async move {
                while let Some(packet) = inbound_rx.recv().await {
                    tracing::debug!(from = %packet.from.short(), "inbound packet ignored (no dataplane)");
                }
            });
        }
    } else {
        tracing::info!("dataplane/transport disabled; API-only mode");
    }

    {
        // Expire routes with an `expires_at` (pin/TTL) even when no route
        // events arrive; FIB rebuilds only happen on changes.
        let expiry = state.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(std::time::Duration::from_secs(1));
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                tick.tick().await;
                if let Err(e) = expiry.routes.expire() {
                    tracing::debug!(error = %e, "route expiry failed");
                }
            }
        });
    }

    let app = api::router(state.clone());
    let addr: std::net::SocketAddr = state
        .config
        .api
        .bind
        .parse()
        .with_context(|| format!("api.bind {}", state.config.api.bind))?;
    tracing::info!(
        node = %state.node_id.short(),
        network = %state.network,
        api = %state.config.api.bind,
        tls = state.config.api.tls_cert.is_some(),
        "stellaris agent started"
    );
    let tls = state
        .config
        .api
        .tls_cert
        .clone()
        .zip(state.config.api.tls_key.clone());
    serve::serve(addr, app, tls, "API").await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn same_zone_route_wins_by_local_pref() {
        let dir =
            std::env::temp_dir().join(format!("stellaris-zone-test-{}", uuid::Uuid::now_v7()));
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

[[peers]]
name = "b"
endpoint_id = "{}"
overlay_ip = "10.7.0.2"
zone = "az-a"

[[peers]]
name = "c"
endpoint_id = "{}"
overlay_ip = "10.7.0.3"
zone = "az-b"

[[routes]]
prefix = "192.168.50.0/24"
via = "b"

[[routes]]
prefix = "192.168.50.0/24"
via = "c"
"#,
            dir.display(),
            hex::encode([2u8; 32]),
            hex::encode([3u8; 32])
        );
        let state = AgentState::build(Config::from_toml(&toml).unwrap()).unwrap();
        let entry = state
            .routes
            .lookup("192.168.50.1".parse().unwrap())
            .unwrap();
        assert_eq!(entry.next_hops[0].node, NodeId::new([2u8; 32]));
        let primary = state
            .routes
            .routes(stellaris_routing::RouteView::Rib)
            .into_iter()
            .find(|r| {
                r.prefix.to_string() == "192.168.50.0/24" && r.next_hop == NodeId::new([2u8; 32])
            })
            .unwrap();
        assert_eq!(primary.attrs.zone.as_deref(), Some("az-a"));
        state.routes.delete(primary.id, false).unwrap();
        let failover = state
            .routes
            .lookup("192.168.50.1".parse().unwrap())
            .unwrap();
        assert_eq!(failover.next_hops[0].node, NodeId::new([3u8; 32]));
    }
}
