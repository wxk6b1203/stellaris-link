//! Stellaris agent library: identity, peer registry, route engine, API.

pub mod api;
pub mod control_client;
pub mod control_wire;
pub mod controller;
pub mod controller_model;
pub mod controller_raft;
pub use stellaris_types::credential;
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

use std::collections::{BTreeMap, HashMap};
use std::path::PathBuf;
use std::sync::{Arc, RwLock};
use std::time::Instant;

use anyhow::Context;
use serde::{Deserialize, Serialize};
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
    /// Last applied `(epoch, generation)` from a signed snapshot. Persisted so
    /// a replayed old snapshot cannot revive revoked members after a restart.
    pub snapshot_floor: Arc<RwLock<(u64, u64)>>,
    /// Last accepted `(epoch, generation)` from a signed membership manifest.
    pub manifest_floor: Arc<RwLock<(u64, u64)>>,
    control_state_path: PathBuf,
    /// Effective local overlay address (config or controller-allocated).
    pub local_overlay: Arc<RwLock<Option<std::net::IpAddr>>>,
    /// Live TUN handle, set once the dataplane has created the device.
    pub dataplane_handle: Arc<std::sync::Mutex<Option<crate::dataplane::DataplaneHandle>>>,
    pub policy: Arc<RwLock<policy::Policy>>,
    pub stats: Arc<stats::Stats>,
    pub reassembly: Arc<std::sync::Mutex<reassembly::Reassembler>>,
    pub started_at: Instant,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct ControlStateDisk {
    #[serde(default)]
    revisions: BTreeMap<String, u64>,
    #[serde(default)]
    snapshot_epoch: u64,
    #[serde(default)]
    snapshot_generation: u64,
    #[serde(default)]
    manifest_epoch: u64,
    #[serde(default)]
    manifest_generation: u64,
}

fn load_control_state(path: &std::path::Path) -> ControlStateDisk {
    match std::fs::read(path) {
        Ok(bytes) => serde_json::from_slice(&bytes).unwrap_or_else(|e| {
            tracing::warn!(error = %e, path = %path.display(), "invalid control state; starting empty");
            ControlStateDisk::default()
        }),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => ControlStateDisk::default(),
        Err(e) => {
            tracing::warn!(error = %e, path = %path.display(), "read control state");
            ControlStateDisk::default()
        }
    }
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
        let controller_keys: Vec<NodeId> = config
            .control
            .controller_keys
            .iter()
            .filter_map(|key| key.parse().ok())
            .collect();
        let credential = load_credential(&state_dir).filter(|credential| {
            if credential.credential.network != network.to_string()
                || credential.credential.node != identity.node_id
            {
                return false;
            }
            if controller_keys.is_empty() {
                tracing::warn!(
                    "cached credential cannot be verified: control.controller_keys is empty"
                );
                return false;
            }
            match credential.verify(
                &network,
                identity.node_id,
                &controller_keys,
                0,
                credential::now_secs(),
            ) {
                Ok(_) => true,
                Err(error) => {
                    tracing::warn!(%error, "cached credential rejected at startup");
                    false
                }
            }
        });
        if let Some(credential) = &credential
            && config.network.auth.mode == stellaris_types::AuthMode::Controller
            && config.node.ipam == stellaris_types::IpamMode::Static
            && let Some(overlay) = credential.credential.overlay_ip
            && config.node.overlay_ip.is_some()
            && config.node.overlay_ip != Some(overlay)
        {
            anyhow::bail!(
                "credential overlay {overlay} does not match node.overlay_ip {}; reissue the credential or fix the config",
                config.node.overlay_ip.expect("checked")
            );
        }
        let cached_overlay = if config.node.ipam == stellaris_types::IpamMode::Auto {
            credential
                .as_ref()
                .and_then(|credential| credential.credential.overlay_ip)
        } else {
            None
        };
        let local_overlay = config.node.overlay_ip.or(cached_overlay);
        let control_state_path = state_dir.join("control-state.json");
        let control_state = load_control_state(&control_state_path);
        let revisions: HashMap<NodeId, u64> = control_state
            .revisions
            .iter()
            .filter_map(|(node, revision)| node.parse().ok().map(|node| (node, *revision)))
            .collect();
        let snapshot_floor = (
            control_state.snapshot_epoch,
            control_state.snapshot_generation,
        );
        let manifest_floor = (
            control_state.manifest_epoch,
            control_state.manifest_generation,
        );

        Ok(Self {
            config: Arc::new(config),
            network,
            node_id: identity.node_id,
            identity_secret: identity.secret,
            routes,
            peers,
            grants: Arc::new(RwLock::new(HashMap::new())),
            credential: Arc::new(RwLock::new(credential)),
            revisions: Arc::new(RwLock::new(revisions)),
            snapshot_floor: Arc::new(RwLock::new(snapshot_floor)),
            manifest_floor: Arc::new(RwLock::new(manifest_floor)),
            control_state_path,
            local_overlay: Arc::new(RwLock::new(local_overlay)),
            dataplane_handle: Arc::new(std::sync::Mutex::new(None)),
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

    /// Apply a controller-issued overlay change in place when the dataplane is
    /// already running; otherwise just update the state used to create the TUN.
    pub fn reconfigure_overlay(&self, ip: std::net::IpAddr) -> anyhow::Result<()> {
        {
            let mut handle = self
                .dataplane_handle
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            if let Some(handle) = handle.as_mut() {
                handle.reconfigure(ip)?;
            }
        }
        self.set_local_overlay(ip);
        Ok(())
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
        let changed = {
            let mut revisions = self.revisions.write().unwrap_or_else(|e| e.into_inner());
            let entry = revisions.entry(node).or_insert(0);
            if revision > *entry {
                *entry = revision;
                true
            } else {
                false
            }
        };
        if changed {
            self.save_control_state();
        }
    }

    pub fn snapshot_floor(&self) -> (u64, u64) {
        *self
            .snapshot_floor
            .read()
            .unwrap_or_else(|e| e.into_inner())
    }

    /// Accept a snapshot only when it is newer than the persisted floor. A
    /// higher epoch permits a lower generation (new controller incarnation);
    /// within an epoch the generation must strictly increase.
    pub fn snapshot_floor_allows(&self, epoch: u64, generation: u64) -> bool {
        let (last_epoch, last_generation) = self.snapshot_floor();
        epoch > last_epoch || (epoch == last_epoch && generation > last_generation)
    }

    pub fn record_snapshot_floor(&self, epoch: u64, generation: u64) {
        let changed = {
            let mut floor = self
                .snapshot_floor
                .write()
                .unwrap_or_else(|e| e.into_inner());
            if epoch > floor.0 || (epoch == floor.0 && generation > floor.1) {
                *floor = (epoch, generation);
                true
            } else {
                false
            }
        };
        if changed {
            self.save_control_state();
        }
    }

    pub fn manifest_floor(&self) -> (u64, u64) {
        *self
            .manifest_floor
            .read()
            .unwrap_or_else(|e| e.into_inner())
    }

    /// A manifest with the same `(epoch, generation)` is idempotent; anything
    /// older is a replay and must be ignored.
    pub fn manifest_floor_allows(&self, epoch: u64, generation: u64) -> bool {
        let (last_epoch, last_generation) = self.manifest_floor();
        epoch > last_epoch || (epoch == last_epoch && generation >= last_generation)
    }

    pub fn record_manifest_floor(&self, epoch: u64, generation: u64) {
        let changed = {
            let mut floor = self
                .manifest_floor
                .write()
                .unwrap_or_else(|e| e.into_inner());
            if epoch > floor.0 || (epoch == floor.0 && generation > floor.1) {
                *floor = (epoch, generation);
                true
            } else {
                false
            }
        };
        if changed {
            self.save_control_state();
        }
    }

    fn save_control_state(&self) {
        let revisions: BTreeMap<String, u64> = self
            .revisions
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .map(|(node, revision)| (node.to_string(), *revision))
            .collect();
        let (snapshot_epoch, snapshot_generation) = self.snapshot_floor();
        let (manifest_epoch, manifest_generation) = self.manifest_floor();
        let disk = ControlStateDisk {
            revisions,
            snapshot_epoch,
            snapshot_generation,
            manifest_epoch,
            manifest_generation,
        };
        let Ok(bytes) = serde_json::to_vec(&disk) else {
            return;
        };
        let tmp = self
            .control_state_path
            .with_extension(format!("json.tmp.{}", std::process::id()));
        if let Err(e) = std::fs::write(&tmp, bytes)
            .and_then(|_| std::fs::rename(&tmp, &self.control_state_path))
        {
            tracing::warn!(error = %e, path = %self.control_state_path.display(), "persist control floor");
        }
    }

    /// Install the controller-signed member table as grants. This lets a
    /// member authorize multi-hop LSAs (B may flood C's LSA to A even when A
    /// has no direct credential exchange with C). The snapshot/manifest is
    /// already signature-verified by the controller channel.
    pub fn install_snapshot_grant(
        &self,
        node: NodeId,
        overlay_ip: Option<std::net::IpAddr>,
        prefixes: Vec<ipnet::IpNet>,
        capabilities: Vec<String>,
        revision: u64,
    ) {
        if revision < self.revision(node) {
            return;
        }
        self.observe_revision(node, revision);
        self.grants
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .insert(
                node,
                membership::Grant {
                    overlay_ip,
                    prefixes,
                    capabilities,
                    expires_at: None,
                },
            );
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

    /// Drop handshake grants whose credential deadline has passed. Returns the
    /// affected nodes so the caller can close/re-authenticate their links even
    /// when the controller is unreachable.
    pub fn expire_grants(&self, now: u64) -> Vec<NodeId> {
        let mut grants = self.grants.write().unwrap_or_else(|e| e.into_inner());
        let expired: Vec<NodeId> = grants
            .iter()
            .filter(|(_, grant)| grant.expires_at.is_some_and(|deadline| deadline <= now))
            .map(|(node, _)| *node)
            .collect();
        for node in &expired {
            grants.remove(node);
        }
        expired
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

/// Controller-auth nodes need either a live control endpoint or a pre-issued
/// credential before they can bring up transport. API-only mode is still
/// allowed for inspection/repair.
fn controller_bootstrap_error(
    config: &Config,
    control_configured: bool,
    has_credential: bool,
    want_transport: bool,
) -> Option<&'static str> {
    if !want_transport
        || config.network.auth.mode != stellaris_types::AuthMode::Controller
        || control_configured
        || has_credential
    {
        return None;
    }
    Some(
        "controller auth needs control.url/endpoint_id or a cached credential.json; place an offline-issued credential in the state dir, or disable the dataplane for API-only mode",
    )
}

pub async fn run(state: AgentState) -> anyhow::Result<()> {
    let (inbound_tx, mut inbound_rx) = tokio::sync::mpsc::channel(1024);
    let (control_tx, control_rx) = if state.config.routing.link_state {
        let (tx, rx) = tokio::sync::mpsc::channel(64);
        (Some(tx), Some(rx))
    } else {
        (None, None)
    };
    let control_configured = state.config.control.url.is_some()
        || state.config.control.endpoint_id.is_some()
        || !state.config.control.failover_urls.is_empty();
    let want_transport = state.config.dataplane.enabled
        || !state.config.peers.is_empty()
        || control_configured
        || state.config.transport.discovery_port.is_some()
        || state.config.transport.mdns;
    if let Some(error) = controller_bootstrap_error(
        &state.config,
        control_configured,
        state.credential().is_some(),
        want_transport,
    ) {
        anyhow::bail!("{error}");
    }
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
            let bases = control_client::controller_bases(&control_state.config);
            let secret = control_state.config.control.secret.clone();
            let control_transport = transport.clone();
            tokio::spawn(async move {
                control_client::run(control_state, bases, secret, Some(control_transport)).await;
            });
        }
        discovery::start(state.clone(), transport.clone());
        {
            let expiry_state = state.clone();
            let expiry_transport = transport.clone();
            tokio::spawn(async move {
                let mut tick = tokio::time::interval(std::time::Duration::from_secs(30));
                tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
                loop {
                    tick.tick().await;
                    for node in expiry_state.expire_grants(crate::credential::now_secs()) {
                        tracing::warn!(
                            peer = %node.short(),
                            "peer credential expired while connected; re-authenticating"
                        );
                        expiry_transport.reconnect_peer(node);
                    }
                }
            });
        }
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
    fn revisions_and_control_floors_survive_restart() {
        let dir =
            std::env::temp_dir().join(format!("stellaris-control-state-{}", uuid::Uuid::now_v7()));
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
"#,
            dir.display()
        );
        let config = Config::from_toml(&toml).unwrap();
        let node = NodeId::new([1u8; 32]);
        {
            let state = AgentState::build(config.clone()).unwrap();
            state.observe_revision(node, 7);
            state.record_snapshot_floor(5, 9);
            state.record_manifest_floor(5, 11);
        }
        let state = AgentState::build(config).unwrap();
        assert_eq!(state.revision(node), 7);
        assert_eq!(state.snapshot_floor(), (5, 9));
        assert_eq!(state.manifest_floor(), (5, 11));
        assert!(!state.snapshot_floor_allows(5, 9));
        assert!(state.snapshot_floor_allows(5, 10));
        assert!(state.snapshot_floor_allows(6, 1));
        assert!(!state.manifest_floor_allows(5, 10));
    }

    #[test]
    fn expired_handshake_grant_is_dropped() {
        let dir =
            std::env::temp_dir().join(format!("stellaris-grant-expiry-{}", uuid::Uuid::now_v7()));
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
"#,
            dir.display()
        );
        let state = AgentState::build(Config::from_toml(&toml).unwrap()).unwrap();
        let node = NodeId::new([3u8; 32]);
        state.grants.write().unwrap().insert(
            node,
            membership::Grant {
                overlay_ip: Some("10.7.0.3".parse().unwrap()),
                prefixes: Vec::new(),
                capabilities: Vec::new(),
                expires_at: Some(10),
            },
        );
        assert!(state.expire_grants(9).is_empty());
        assert_eq!(state.expire_grants(10), vec![node]);
        assert!(state.grants.read().unwrap().is_empty());
    }

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

    #[test]
    fn controller_bootstrap_requires_url_or_credential() {
        let toml = r#"
[node]
name = "offline"
[network]
name = "offline-demo"
cidr = "10.7.0.0/16"
[network.auth]
mode = "controller"
[control]
controller_keys = ["0000000000000000000000000000000000000000000000000000000000000000"]
"#;
        let config = Config::from_toml(toml).unwrap();
        assert!(
            controller_bootstrap_error(&config, false, false, true).is_some(),
            "dataplane startup needs a bootstrap source"
        );
        assert!(controller_bootstrap_error(&config, false, false, false).is_none());
        assert!(controller_bootstrap_error(&config, false, true, true).is_none());
        assert!(controller_bootstrap_error(&config, true, false, true).is_none());
    }

    #[test]
    fn offline_controller_credential_loads_without_controller_url() {
        let dir =
            std::env::temp_dir().join(format!("stellaris-offline-cred-{}", uuid::Uuid::now_v7()));
        let state_dir = dir.join("node");
        std::fs::create_dir_all(&state_dir).unwrap();
        let identity = identity::load_or_create(&state_dir).unwrap();
        let network = NetworkId::new();
        let secret = [7u8; 32];
        let issuer = NodeId::new(
            ed25519_dalek::SigningKey::from_bytes(&secret)
                .verifying_key()
                .to_bytes(),
        );
        let now = credential::now_secs();
        let signed = credential::SignedCredential::sign(
            &secret,
            credential::MembershipCredential {
                network: network.to_string(),
                node: identity.node_id,
                overlay_ip: Some("10.7.0.2".parse().unwrap()),
                prefixes: vec![],
                capabilities: vec!["member".into()],
                revision: 1,
                issued_at: now,
                not_after: now + 3600,
            },
        );
        std::fs::write(
            state_dir.join("credential.json"),
            serde_json::to_vec(&signed).unwrap(),
        )
        .unwrap();
        let toml = format!(
            r#"
[node]
name = "offline"
state_dir = "{}"
overlay_ip = "10.7.0.2"

[network]
id = "{}"
name = "offline-demo"
cidr = "10.7.0.0/16"

[network.auth]
mode = "controller"

[control]
controller_keys = ["{}"]
"#,
            state_dir.display(),
            network,
            issuer
        );
        let state = AgentState::build(Config::from_toml(&toml).unwrap()).unwrap();
        assert_eq!(state.local_overlay(), Some("10.7.0.2".parse().unwrap()));
        assert!(state.credential().is_some());

        let mismatched = toml.replace("overlay_ip = \"10.7.0.2\"", "overlay_ip = \"10.7.0.9\"");
        assert!(AgentState::build(Config::from_toml(&mismatched).unwrap()).is_err());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn cached_credential_signature_expiry_and_trust_anchor_are_enforced() {
        let dir =
            std::env::temp_dir().join(format!("stellaris-cached-cred-{}", uuid::Uuid::now_v7()));
        let state_dir = dir.join("node");
        std::fs::create_dir_all(&state_dir).unwrap();
        let identity = identity::load_or_create(&state_dir).unwrap();
        let network = NetworkId::new();
        let secret = [9u8; 32];
        let issuer = NodeId::new(
            ed25519_dalek::SigningKey::from_bytes(&secret)
                .verifying_key()
                .to_bytes(),
        );
        let now = credential::now_secs();
        let make = |not_after: u64| {
            credential::SignedCredential::sign(
                &secret,
                credential::MembershipCredential {
                    network: network.to_string(),
                    node: identity.node_id,
                    overlay_ip: Some("10.7.0.2".parse().unwrap()),
                    prefixes: vec![],
                    capabilities: vec!["member".into()],
                    revision: 1,
                    issued_at: now,
                    not_after,
                },
            )
        };
        let credential_path = state_dir.join("credential.json");
        let config = |keys: String| {
            Config::from_toml(&format!(
                r#"
[node]
name = "cached"
state_dir = "{}"
overlay_ip = "10.7.0.2"

[network]
id = "{}"
name = "cached-demo"
cidr = "10.7.0.0/16"

[network.auth]
mode = "controller"

[control]
{keys}
"#,
                state_dir.display(),
                network
            ))
            .unwrap()
        };
        let keys = format!("controller_keys = [\"{issuer}\"]");
        let rejected = |keys: String| {
            AgentState::build(config(keys))
                .map(|state| state.credential().is_none())
                .unwrap_or(true)
        };
        std::fs::write(
            &credential_path,
            serde_json::to_vec(&make(now + 3600)).unwrap(),
        )
        .unwrap();
        assert!(
            AgentState::build(config(keys.clone()))
                .unwrap()
                .credential()
                .is_some()
        );

        let mut tampered = make(now + 3600);
        tampered.signature = "00".repeat(64);
        std::fs::write(&credential_path, serde_json::to_vec(&tampered).unwrap()).unwrap();
        assert!(rejected(keys.clone()));

        std::fs::write(
            &credential_path,
            serde_json::to_vec(&make(now.saturating_sub(1))).unwrap(),
        )
        .unwrap();
        assert!(rejected(keys.clone()));

        let _ = std::fs::remove_dir_all(dir);
    }
}
