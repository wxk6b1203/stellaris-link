//! Stellaris controller: signed snapshots over HTTP and the iroh control protocol.
//!
//! HTTP is kept for compatibility/debugging; members can use `control.endpoint_id`
//! + `control.addrs` to use iroh instead. HA/openraft is still future work.

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};

use anyhow::{Context, bail};
use axum::extract::{Path, Query, State};
use axum::http::HeaderValue;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, patch, post};
use axum::{Json, Router};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use hmac::{Hmac, Mac};
use ipnet::IpNet;
use iroh::{Endpoint, RelayMode, RelayUrl, SecretKey, endpoint::presets};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::Sha256;
use stellaris_linkstate::{LinkStateDb, Lsa};
use stellaris_types::{
    AddressPool, Config, ControllerMemberConfig, NetworkId, NodeId, RaftTiming, RouteEntry,
    RouteId, RouteSource, RouteState,
};

use crate::credential::{MembershipCredential, SignedCredential};
use uuid::Uuid;

use crate::controller_raft::{StateMachineStore, TypeConfig};
use openraft::async_runtime::WatchReceiver;
use openraft::{BasicNode, Raft, ReadPolicy};

use crate::controller_model::{ControllerCommand, ControllerModel, MemberRecord};

#[derive(Debug, Default, Serialize, Deserialize)]
struct PersistedMembers {
    #[serde(default)]
    grants: Vec<ControllerMemberConfig>,
}

#[derive(Debug, Serialize, Deserialize)]
struct PersistedLsas {
    saved_at: u64,
    lsas: Vec<Lsa>,
}

#[derive(Clone)]
pub struct ControllerState {
    pub network: NetworkId,
    pub cidr: IpNet,
    secret: Option<String>,
    admin_secret: Option<String>,
    routes: Arc<RwLock<Vec<RouteEntry>>>,
    link_state: Arc<RwLock<LinkStateDb>>,
    acks: Arc<RwLock<HashMap<NodeId, u64>>>,
    acks_path: PathBuf,
    members_path: PathBuf,
    lsas_path: PathBuf,
    commands_path: PathBuf,
    previous_secrets: Vec<String>,
    grants: Arc<RwLock<HashMap<NodeId, ControllerMemberConfig>>>,
    model: Arc<RwLock<ControllerModel>>,
    strict_membership: bool,
    signing_key: Option<Arc<SigningKey>>,
    signer: Option<NodeId>,
    raft: Option<Arc<Raft<TypeConfig, StateMachineStore>>>,
    raft_store: Option<StateMachineStore>,
    raft_id: Option<u64>,
    /// Last time each origin's LSA was written or first observed by this leader.
    lsa_seen: Arc<std::sync::Mutex<HashMap<NodeId, std::time::Instant>>>,
    raft_timing: Option<RaftTiming>,
    leader: Option<NodeId>,
    manifest_ttl: u64,
    lsa_ttl_secs: u64,
    credential_ttl: u64,
    pub epoch: u64,
    generation: Arc<AtomicU64>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Snapshot {
    pub network_id: String,
    pub epoch: u64,
    pub generation: u64,
    pub members: Vec<MemberView>,
    pub routes: Vec<RouteEntry>,
    /// Controller NodeId when the snapshot is Ed25519-signed.
    #[serde(default)]
    pub signer: Option<String>,
    /// HMAC-SHA256 over the snapshot payload when control.secret is set.
    #[serde(default)]
    pub signature: Option<String>,
    /// Ed25519 signature by the controller identity.
    #[serde(default)]
    pub ed25519_signature: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MemberView {
    pub node_id: String,
    pub zone: Option<String>,
    pub overlay_ip: Option<std::net::IpAddr>,
    pub addrs: Vec<SocketAddr>,
    pub prefixes: Vec<String>,
    pub allowed_prefixes: Vec<String>,
    pub capabilities: Vec<String>,
    pub links: Vec<String>,
    pub last_seq: u64,
    /// Per-node credential revision; bumped on every authorization change.
    #[serde(default)]
    pub revision: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MembershipManifest {
    pub network_id: String,
    pub epoch: u64,
    pub generation: u64,
    pub controller: Option<String>,
    pub issued_at: u64,
    pub expires_at: u64,
    pub members: Vec<MemberView>,
    #[serde(default)]
    pub signature: Option<String>,
}

#[derive(Serialize)]
struct ManifestPayload<'a> {
    network_id: &'a str,
    epoch: u64,
    generation: u64,
    controller: &'a Option<String>,
    issued_at: u64,
    expires_at: u64,
    members: &'a [MemberView],
}

pub fn manifest_payload_bytes(manifest: &MembershipManifest) -> Vec<u8> {
    let payload = ManifestPayload {
        network_id: &manifest.network_id,
        epoch: manifest.epoch,
        generation: manifest.generation,
        controller: &manifest.controller,
        issued_at: manifest.issued_at,
        expires_at: manifest.expires_at,
        members: &manifest.members,
    };
    serde_json::to_vec(&payload).unwrap_or_default()
}

#[derive(Serialize)]
struct ManifestAgreement<'a> {
    network_id: &'a str,
    epoch: u64,
    generation: u64,
    members: &'a [MemberView],
}

/// Controller-independent manifest content used for multi-controller threshold.
pub fn manifest_agreement_bytes(manifest: &MembershipManifest) -> Vec<u8> {
    let payload = ManifestAgreement {
        network_id: &manifest.network_id,
        epoch: manifest.epoch,
        generation: manifest.generation,
        members: &manifest.members,
    };
    serde_json::to_vec(&payload).unwrap_or_default()
}

#[derive(Serialize)]
struct SnapshotPayload<'a> {
    network_id: &'a str,
    epoch: u64,
    generation: u64,
    members: &'a [MemberView],
    routes: &'a [RouteEntry],
}

/// Canonical snapshot payload bytes used by HMAC and Ed25519 signatures.
pub fn snapshot_payload_bytes(
    network_id: &str,
    epoch: u64,
    generation: u64,
    members: &[MemberView],
    routes: &[RouteEntry],
) -> Vec<u8> {
    let payload = SnapshotPayload {
        network_id,
        epoch,
        generation,
        members,
        routes,
    };
    serde_json::to_vec(&payload).unwrap_or_default()
}

/// Sign a snapshot with the legacy shared HMAC secret.
#[allow(clippy::too_many_arguments)]
pub fn snapshot_signature(
    secret: &str,
    network_id: &str,
    epoch: u64,
    generation: u64,
    members: &[MemberView],
    routes: &[RouteEntry],
) -> String {
    let bytes = snapshot_payload_bytes(network_id, epoch, generation, members, routes);
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).expect("hmac key");
    mac.update(&bytes);
    hex::encode(mac.finalize().into_bytes())
}

/// Sign an arbitrary payload with a node's Ed25519 identity key.
pub fn sign_ed25519(secret: &[u8; 32], payload: &[u8]) -> String {
    let key = SigningKey::from_bytes(secret);
    hex::encode(key.sign(payload).to_bytes())
}

pub fn verify_ed25519(signer: NodeId, payload: &[u8], signature: &str) -> anyhow::Result<()> {
    let key = VerifyingKey::from_bytes(signer.as_bytes())?;
    let bytes = hex::decode(signature)?;
    let sig = Signature::from_slice(&bytes)?;
    key.verify(payload, &sig)?;
    Ok(())
}

impl ControllerState {
    pub fn from_config(config: &Config) -> anyhow::Result<Self> {
        if config.node.role != "controller" {
            bail!("node.role must be \"controller\" for stellaris-controller");
        }
        let network = config.network.id.unwrap_or_else(|| {
            NetworkId(Uuid::new_v5(
                &Uuid::NAMESPACE_DNS,
                config.network.name.as_bytes(),
            ))
        });
        let mut routes = Vec::new();
        for route in &config.routes {
            let peer = config.peer_by_name(&route.via).ok_or_else(|| {
                anyhow::anyhow!("route {} via unknown peer {}", route.prefix, route.via)
            })?;
            let via: NodeId = peer.endpoint_id.parse().context("peer endpoint_id")?;
            let mut entry = make_route(network, route.prefix, via, 10, 1);
            entry.attrs.zone = peer.zone.clone();
            entry.attrs.region = peer.zone.clone();
            routes.push(entry);
        }
        let state_dir = PathBuf::from(&config.node.state_dir);
        let acks_path = state_dir.join("controller-acks.json");
        let members_path = state_dir.join("controller-members.json");
        let lsas_path = state_dir.join("controller-lsas.json");
        let commands_path = state_dir.join("controller-commands.jsonl");
        let acks = load_acks(&acks_path);
        let persisted = load_members(&members_path);
        let persisted_lsas = load_lsas(&lsas_path);
        let mut link_state = LinkStateDb::new();
        if now_epoch().saturating_sub(persisted_lsas.saved_at) <= 30 {
            for lsa in persisted_lsas.lsas {
                link_state.apply(lsa);
            }
        }
        let loaded_lsas = link_state.len();
        // A replicated model must start deterministically: replicas only agree
        // once the leader publishes a wall-clock epoch through Raft.
        let epoch = match (config.control.raft_dir.is_some(), config.control.epoch) {
            (_, Some(epoch)) => epoch,
            (true, None) => 0,
            (false, None) => now_epoch(),
        };
        let mut grants = HashMap::new();
        for member in &config.control.members {
            let node: NodeId = member
                .node_id
                .parse()
                .context("controller member node_id")?;
            grants.insert(node, member.clone());
        }
        for member in &persisted.grants {
            let node: NodeId = member.node_id.parse().context("persisted member node_id")?;
            grants.insert(node, member.clone());
        }
        let strict_membership = !config.control.members.is_empty() || !grants.is_empty();
        let mut model = ControllerModel::new(network, epoch);
        let replay = load_commands(&commands_path);
        for command in replay {
            model.apply(command);
        }
        for pool in &config.control.ipam.pools {
            model.apply(ControllerCommand::CreatePool { pool: pool.clone() });
        }
        let mut seeded: Vec<(&NodeId, &ControllerMemberConfig)> = grants.iter().collect();
        seeded.sort_by(|a, b| a.0.cmp(b.0));
        for (node, grant) in seeded {
            let mut member = MemberRecord {
                overlay_ip: grant.overlay_ip,
                prefixes: grant.prefixes.iter().map(|p| p.to_string()).collect(),
                capabilities: grant.capabilities.clone(),
            };
            if member.overlay_ip.is_none() && !model.pools.is_empty() {
                match model.allocate_address(*node, None, None, 0) {
                    Ok((ip, _pool, _, _)) => member.overlay_ip = Some(ip),
                    Err(error) => {
                        tracing::warn!(%node, %error, "pre-registered member has no address")
                    }
                }
            }
            if member.overlay_ip.is_none() {
                model.apply(ControllerCommand::UpsertMember {
                    node: *node,
                    member,
                });
            } else {
                model.apply(ControllerCommand::ApproveAdmission {
                    node: *node,
                    member,
                    auto: false,
                    pool: None,
                    zone: None,
                    now: 0,
                });
            }
        }
        Ok(Self {
            network,
            cidr: config.network.cidr,
            secret: config.control.secret.clone(),
            admin_secret: config.control.admin_secret.clone(),
            routes: Arc::new(RwLock::new(routes)),
            link_state: Arc::new(RwLock::new(link_state)),
            acks: Arc::new(RwLock::new(acks)),
            acks_path,
            members_path,
            lsas_path,
            commands_path,
            previous_secrets: config.control.previous_secrets.clone(),
            grants: Arc::new(RwLock::new(grants)),
            model: Arc::new(RwLock::new(model)),
            strict_membership,
            signing_key: None,
            signer: None,
            raft: None,
            raft_store: None,
            raft_id: None,
            lsa_seen: Arc::new(std::sync::Mutex::new(HashMap::new())),
            raft_timing: None,
            leader: config
                .control
                .leader_id
                .as_deref()
                .map(str::parse)
                .transpose()
                .context("control.leader_id")?,
            manifest_ttl: config.control.manifest_ttl_secs,
            lsa_ttl_secs: config.control.lsa_ttl_secs,
            credential_ttl: config.control.credential_ttl_secs,
            epoch,
            generation: Arc::new(AtomicU64::new(if loaded_lsas > 0 { 2 } else { 1 })),
        })
    }

    pub fn set_raft(
        &mut self,
        raft: Arc<Raft<TypeConfig, StateMachineStore>>,
        store: StateMachineStore,
    ) {
        self.raft = Some(raft);
        self.raft_store = Some(store);
    }

    /// Decide an enrollment request: issue a credential, queue it, or refuse.
    async fn enroll(
        &self,
        node: NodeId,
        overlay: Option<std::net::IpAddr>,
        auto: bool,
        pool: Option<String>,
        zone: Option<String>,
    ) -> Result<EnrollOutcome, (u16, String)> {
        let now = crate::credential::now_secs();
        let model = self.model_current().await;
        if let Some(member) = model.members.get(&node).cloned() {
            if member.overlay_ip.is_none() {
                if !auto {
                    return Err((409, "member has no overlay address".into()));
                }
                let (ip, pool_id, _, _) = model
                    .allocate_address(node, pool.as_deref(), zone.as_deref(), now)
                    .map_err(|error| (409, error))?;
                let mut updated = member.clone();
                updated.overlay_ip = Some(ip);
                self.commit_command(ControllerCommand::ApproveAdmission {
                    node,
                    member: updated,
                    auto: false,
                    pool: Some(pool_id),
                    zone: zone.clone(),
                    now,
                })
                .await?;
                let model = self.model_current().await;
                let member = model
                    .members
                    .get(&node)
                    .cloned()
                    .ok_or((503, "member vanished during allocation".to_string()))?;
                let revision = model.member_revisions.get(&node).copied().unwrap_or(1);
                let credential = self.issue_credential(node, &member, revision)?;
                return Ok(EnrollOutcome::Credential(Box::new(credential)));
            }
            self.renew_lease_if_needed(&model, node, now).await;
            let revision = model.member_revisions.get(&node).copied().unwrap_or(1);
            let credential = self.issue_credential(node, &member, revision)?;
            return Ok(EnrollOutcome::Credential(Box::new(credential)));
        }
        if model.revoked.contains(&node) {
            return Ok(EnrollOutcome::Denied(
                "node was revoked by an administrator".into(),
            ));
        }
        if auto {
            if model.pools.is_empty() {
                return Err((
                    409,
                    "node.ipam = auto but no IPAM pools are configured".into(),
                ));
            }
        } else {
            let Some(ip) = overlay else {
                return Err((400, "overlay_ip is required unless node.ipam = auto".into()));
            };
            self.validate_overlay(&model, node, ip)?;
        }
        let command = ControllerCommand::RequestAdmission {
            node,
            overlay_ip: overlay,
            auto,
            pool,
            zone,
        };
        if let Some(raft) = &self.raft {
            raft.client_write(command)
                .await
                .map_err(|e| (503, format!("raft admission request failed: {e}")))?;
        } else {
            self.append_command(command.clone());
            self.model
                .write()
                .unwrap_or_else(|e| e.into_inner())
                .apply(command);
            self.generation.fetch_add(1, Ordering::Relaxed);
        }
        Ok(EnrollOutcome::Pending)
    }

    async fn renew_lease_if_needed(&self, model: &ControllerModel, node: NodeId, now: u64) {
        let Some(ip) = model.node_leases.get(&node).copied() else {
            return;
        };
        if !model
            .leases
            .get(&ip)
            .is_some_and(|lease| !lease.reserved && lease.expires_at > 0)
        {
            return;
        }
        let command = ControllerCommand::RenewLease { node, now };
        if let Some(raft) = &self.raft {
            let _ = raft.client_write(command).await;
        } else {
            self.append_command(command.clone());
            self.model
                .write()
                .unwrap_or_else(|e| e.into_inner())
                .apply(command);
        }
    }

    fn validate_overlay(
        &self,
        model: &ControllerModel,
        node: NodeId,
        ip: std::net::IpAddr,
    ) -> Result<(), (u16, String)> {
        if model.overlay_taken(ip, node) {
            return Err((409, format!("overlay address {ip} is already in use")));
        }
        if !model.pools.is_empty() && model.pool_of(ip).is_none() {
            return Err((
                409,
                format!("overlay address {ip} is outside the configured IPAM pools"),
            ));
        }
        Ok(())
    }

    fn issue_credential(
        &self,
        node: NodeId,
        member: &MemberRecord,
        revision: u64,
    ) -> Result<SignedCredential, (u16, String)> {
        let Some(key) = &self.signing_key else {
            return Err((503, "controller signing key is not configured".into()));
        };
        let credential = MembershipCredential {
            network: self.network.to_string(),
            node,
            overlay_ip: member.overlay_ip,
            prefixes: member
                .prefixes
                .iter()
                .filter_map(|prefix| prefix.parse().ok())
                .collect(),
            capabilities: member.capabilities.clone(),
            revision: revision.max(1),
            issued_at: crate::credential::now_secs(),
            not_after: crate::credential::now_secs().saturating_add(self.credential_ttl),
        };
        Ok(SignedCredential::sign(&key.to_bytes(), credential))
    }

    /// Write a command through Raft when enabled, otherwise apply it locally.
    async fn commit_command(&self, command: ControllerCommand) -> Result<(), (u16, String)> {
        if let Some(raft) = &self.raft {
            raft.client_write(command)
                .await
                .map(|_| ())
                .map_err(|e| (503, format!("raft write failed: {e}")))
        } else {
            self.append_command(command.clone());
            self.model
                .write()
                .unwrap_or_else(|e| e.into_inner())
                .apply(command.clone());
            self.mirror_member_command(&command);
            self.generation.fetch_add(1, Ordering::Relaxed);
            Ok(())
        }
    }

    fn insert_grant(&self, node: NodeId, member: MemberRecord) {
        self.grants
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .insert(
                node,
                ControllerMemberConfig {
                    node_id: node.to_string(),
                    overlay_ip: member.overlay_ip,
                    prefixes: member
                        .prefixes
                        .iter()
                        .filter_map(|prefix| prefix.parse().ok())
                        .collect(),
                    capabilities: member.capabilities.clone(),
                },
            );
    }

    /// Keep the legacy in-memory `grants` map in sync with membership commands
    /// applied without Raft (HTTP-only controller / tests).
    fn mirror_member_command(&self, command: &ControllerCommand) {
        let mut changed = false;
        match command {
            ControllerCommand::ApproveAdmission { node, member, .. }
            | ControllerCommand::UpsertMember { node, member } => {
                self.insert_grant(*node, member.clone());
                changed = true;
            }
            ControllerCommand::ReassignAddress { node, .. } => {
                let member = self
                    .model
                    .read()
                    .unwrap_or_else(|e| e.into_inner())
                    .members
                    .get(node)
                    .cloned();
                if let Some(member) = member {
                    self.insert_grant(*node, member);
                    changed = true;
                }
            }
            ControllerCommand::RevokeMember { node, .. }
            | ControllerCommand::DenyAdmission { node, .. } => {
                changed = self
                    .grants
                    .write()
                    .unwrap_or_else(|e| e.into_inner())
                    .remove(node)
                    .is_some();
            }
            _ => {}
        }
        if changed {
            self.persist_members();
        }
    }

    /// Record this controller's Raft node id (used for leader-only tasks).
    pub fn set_raft_identity(&mut self, id: u64) {
        self.raft_id = Some(id);
    }

    /// Record the Raft election timing this controller runs with, for status.
    pub fn set_raft_timing(&mut self, timing: RaftTiming) {
        self.raft_timing = Some(timing);
    }

    pub fn raft_timing(&self) -> Option<RaftTiming> {
        self.raft_timing
    }

    pub fn set_signing_key(&mut self, secret: [u8; 32]) {
        let key = SigningKey::from_bytes(&secret);
        self.signer = Some(NodeId::new(key.verifying_key().to_bytes()));
        self.signing_key = Some(Arc::new(key));
    }

    pub fn model(&self) -> ControllerModel {
        self.model.read().unwrap_or_else(|e| e.into_inner()).clone()
    }

    pub async fn model_current(&self) -> ControllerModel {
        match &self.raft_store {
            Some(store) => store.model().await,
            None => self.model(),
        }
    }

    pub async fn snapshot_current(&self, local: Option<NodeId>) -> Snapshot {
        match &self.raft_store {
            Some(store) => self.snapshot_from_model(store.model().await, local),
            None => self.snapshot(local),
        }
    }

    pub async fn leader_hint(&self) -> Option<u64> {
        match &self.raft {
            Some(raft) => raft.current_leader().await,
            None => None,
        }
    }

    pub async fn linearize(&self) -> Result<(), String> {
        if let Some(raft) = &self.raft {
            raft.ensure_linearizable(ReadPolicy::ReadIndex)
                .await
                .map_err(|e| format!("raft linearizable read failed: {e}"))?;
        }
        Ok(())
    }

    fn snapshot_from_model(&self, model: ControllerModel, local: Option<NodeId>) -> Snapshot {
        let mut routes = self
            .routes
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        if let Some(local) = local {
            routes.extend(model.routes(local));
        }
        routes.extend(model.route_entries());
        let members = self.members_from_model(&model);
        let network_id = self.network.to_string();
        let generation = model.generation;
        let epoch = model.epoch;
        let signature = self.secret.as_deref().map(|secret| {
            snapshot_signature(secret, &network_id, epoch, generation, &members, &routes)
        });
        let ed25519_signature = self.signing_key.as_ref().map(|key| {
            let bytes = snapshot_payload_bytes(&network_id, epoch, generation, &members, &routes);
            hex::encode(key.sign(&bytes).to_bytes())
        });
        Snapshot {
            network_id,
            epoch,
            generation,
            members,
            routes,
            signer: self.signer.map(|n| n.to_string()),
            signature,
            ed25519_signature,
        }
    }

    fn members_from_model(&self, model: &ControllerModel) -> Vec<MemberView> {
        let mut out: Vec<MemberView> = model
            .lsas
            .values()
            .map(|lsa| {
                let member = model.members.get(&lsa.origin);
                MemberView {
                    node_id: lsa.origin.to_string(),
                    zone: lsa.zone.clone(),
                    overlay_ip: lsa.overlay_ip,
                    addrs: lsa.addrs.clone(),
                    prefixes: lsa.prefixes.iter().map(|p| p.prefix.to_string()).collect(),
                    // Only an explicit grant authorizes a prefix; an LSA must
                    // never whitelist its own advertised prefixes.
                    allowed_prefixes: member.map(|m| m.prefixes.clone()).unwrap_or_default(),
                    capabilities: member.map(|m| m.capabilities.clone()).unwrap_or_default(),
                    links: lsa.links.iter().map(|l| l.to.to_string()).collect(),
                    last_seq: lsa.seq,
                    revision: model
                        .member_revisions
                        .get(&lsa.origin)
                        .copied()
                        .unwrap_or(1),
                }
            })
            .collect();
        for (node, member) in &model.members {
            if out.iter().any(|m| m.node_id == node.to_string()) {
                continue;
            }
            out.push(MemberView {
                node_id: node.to_string(),
                zone: None,
                overlay_ip: member.overlay_ip,
                addrs: Vec::new(),
                prefixes: Vec::new(),
                allowed_prefixes: member.prefixes.clone(),
                capabilities: member.capabilities.clone(),
                links: Vec::new(),
                last_seq: 0,
                revision: model.member_revisions.get(node).copied().unwrap_or(1),
            });
        }
        out.sort_by(|a, b| a.node_id.cmp(&b.node_id));
        out
    }

    async fn authorize_lsa_current(&self, lsa: &Lsa) -> Result<(), (u16, String)> {
        if self.raft.is_none() {
            // Non-Raft controllers keep the legacy grant-based check. Once a
            // member has been admitted the grant table is non-empty and the
            // check is enforced even if the process started without static
            // members (approval-only deployments).
            if !self.strict_membership
                && self
                    .grants
                    .read()
                    .unwrap_or_else(|e| e.into_inner())
                    .is_empty()
            {
                return Ok(());
            }
            return self.authorize_lsa(lsa);
        }
        let model = self.model_current().await;
        // A Raft controller that started without `[[control.members]]` (the
        // documented approval-only deployment) still has to enforce membership
        // once the first admission/revocation has been written. Otherwise a
        // dynamically approved member could advertise any prefix for the whole
        // lifetime of the process.
        if !self.strict_membership
            && model.members.is_empty()
            && model.revoked.is_empty()
            && model.pending_admissions.is_empty()
        {
            return Ok(());
        }
        let Some(member) = model.members.get(&lsa.origin) else {
            return Err((403, format!("member {} is not authorized", lsa.origin)));
        };
        if let Some(expected) = member.overlay_ip
            && lsa.overlay_ip != Some(expected)
        {
            return Err((403, "LSA overlay_ip does not match member grant".into()));
        }
        for prefix in &lsa.prefixes {
            let own = member
                .overlay_ip
                .is_some_and(|ip| stellaris_types::host_prefix(ip) == prefix.prefix);
            let allowed = member
                .prefixes
                .iter()
                .filter_map(|p| p.parse::<IpNet>().ok())
                .any(|p| p == prefix.prefix);
            if !own && !allowed {
                return Err((
                    403,
                    format!(
                        "prefix {} is not authorized for {}",
                        prefix.prefix, lsa.origin
                    ),
                ));
            }
        }
        for link in &lsa.links {
            if !model.members.contains_key(&link.to) {
                return Err((403, format!("link target {} is not authorized", link.to)));
            }
        }
        Ok(())
    }

    async fn apply_lsa_current(&self, lsa: Lsa) -> Result<bool, (u16, String)> {
        self.authorize_lsa_current(&lsa).await?;
        if let Some(raft) = &self.raft {
            let origin = lsa.origin;
            raft.client_write(ControllerCommand::ApplyLsa { lsa })
                .await
                .map(|_| {
                    self.note_lsa(origin);
                    true
                })
                .map_err(|e| (503, format!("raft write failed: {e}")))
        } else {
            self.apply_lsa(lsa)
        }
    }

    fn note_lsa(&self, origin: NodeId) {
        self.lsa_seen
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(origin, std::time::Instant::now());
    }

    async fn raft_is_leader(&self) -> bool {
        match (&self.raft, self.raft_id) {
            (Some(raft), Some(id)) => raft.current_leader().await == Some(id),
            _ => false,
        }
    }

    /// Leader-only maintenance: monotonic epoch and replicated LSA expiry.
    async fn raft_housekeeping(&self) {
        let Some(raft) = self.raft.clone() else {
            return;
        };
        let mut bumped = false;
        let ttl = std::time::Duration::from_secs(self.lsa_ttl_secs.max(1));
        let mut tick = tokio::time::interval(std::time::Duration::from_secs(5));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tick.tick().await;
            if !self.raft_is_leader().await {
                bumped = false;
                continue;
            }
            let model = self.model_current().await;
            if !bumped {
                let target = now_epoch().max(model.epoch.saturating_add(1));
                if target > model.epoch
                    && let Err(error) = raft
                        .client_write(ControllerCommand::SetEpoch { epoch: target })
                        .await
                {
                    tracing::debug!(%error, "raft epoch bump failed");
                }
                bumped = true;
            }
            let mut stale = Vec::new();
            {
                let mut seen = self.lsa_seen.lock().unwrap_or_else(|e| e.into_inner());
                for (origin, lsa) in &model.lsas {
                    match seen.get(origin) {
                        None => {
                            seen.insert(*origin, std::time::Instant::now());
                        }
                        Some(at) if at.elapsed() >= ttl => stale.push((*origin, lsa.seq)),
                        Some(_) => {}
                    }
                }
                let live: HashSet<NodeId> = model.lsas.keys().copied().collect();
                seen.retain(|origin, _| live.contains(origin));
            }
            if !stale.is_empty() {
                // One command per round keeps the log small even when a large
                // model expires at once.
                match raft
                    .client_write(ControllerCommand::ExpireLsas {
                        entries: stale.clone(),
                    })
                    .await
                {
                    Ok(_) => {
                        let mut seen = self.lsa_seen.lock().unwrap_or_else(|e| e.into_inner());
                        for (origin, _) in &stale {
                            seen.remove(origin);
                        }
                    }
                    Err(error) => {
                        tracing::debug!(%error, count = stale.len(), "raft LSA expiry batch failed")
                    }
                }
            }
            let now = crate::credential::now_secs();
            let model = self.model_current().await;
            if model
                .leases
                .values()
                .any(|lease| lease.expires_at > 0 && lease.expires_at <= now)
                && let Err(error) = raft
                    .client_write(ControllerCommand::ExpireLeases { now })
                    .await
            {
                tracing::debug!(%error, "raft lease expiry failed");
            }
        }
    }

    /// Expire leases on a controller without Raft.
    async fn expire_leases_local(&self) {
        let now = crate::credential::now_secs();
        let model = self.model_current().await;
        if !model
            .leases
            .values()
            .any(|lease| lease.expires_at > 0 && lease.expires_at <= now)
        {
            return;
        }
        let command = ControllerCommand::ExpireLeases { now };
        self.append_command(command.clone());
        self.model
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .apply(command);
    }

    pub fn manifest(&self) -> MembershipManifest {
        self.expire_lsas();
        let generation = self.generation.load(Ordering::Relaxed);
        let issued_at = now_epoch();
        let mut manifest = MembershipManifest {
            network_id: self.network.to_string(),
            epoch: self.epoch,
            generation,
            controller: self.signer.map(|n| n.to_string()),
            issued_at,
            expires_at: issued_at.saturating_add(self.manifest_ttl),
            members: self.members(),
            signature: None,
        };
        if let Some(key) = &self.signing_key {
            let bytes = manifest_payload_bytes(&manifest);
            manifest.signature = Some(hex::encode(key.sign(&bytes).to_bytes()));
        }
        manifest
    }

    pub async fn manifest_current(&self) -> MembershipManifest {
        match &self.raft_store {
            Some(store) => self.manifest_from_model(store.model().await),
            None => self.manifest(),
        }
    }

    fn manifest_from_model(&self, model: ControllerModel) -> MembershipManifest {
        let issued_at = now_epoch();
        let mut manifest = MembershipManifest {
            network_id: self.network.to_string(),
            epoch: model.epoch,
            generation: model.generation,
            controller: self.signer.map(|n| n.to_string()),
            issued_at,
            expires_at: issued_at.saturating_add(self.manifest_ttl),
            members: self.members_from_model(&model),
            signature: None,
        };
        if let Some(key) = &self.signing_key {
            let bytes = manifest_payload_bytes(&manifest);
            manifest.signature = Some(hex::encode(key.sign(&bytes).to_bytes()));
        }
        manifest
    }

    fn ensure_leader(&self) -> Result<(), (u16, String)> {
        match self.leader {
            Some(leader) if self.signer != Some(leader) => {
                Err((503, format!("controller is not leader (leader {leader})")))
            }
            _ => Ok(()),
        }
    }

    pub fn snapshot(&self, local: Option<NodeId>) -> Snapshot {
        self.expire_lsas();
        let mut routes = self
            .routes
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        if let Some(local) = local {
            let db = self.link_state.read().unwrap_or_else(|e| e.into_inner());
            routes.extend(db.compute_routes(local, self.network));
        }
        let generation = self.generation.load(Ordering::Relaxed);
        let network_id = self.network.to_string();
        let members = self.members();
        let signature = self.secret.as_deref().map(|secret| {
            snapshot_signature(
                secret,
                &network_id,
                self.epoch,
                generation,
                &members,
                &routes,
            )
        });
        let ed25519_signature = self.signing_key.as_ref().map(|key| {
            let bytes =
                snapshot_payload_bytes(&network_id, self.epoch, generation, &members, &routes);
            hex::encode(key.sign(&bytes).to_bytes())
        });
        Snapshot {
            network_id,
            epoch: self.epoch,
            generation,
            members,
            routes,
            signer: self.signer.map(|n| n.to_string()),
            signature,
            ed25519_signature,
        }
    }

    fn expire_lsas(&self) {
        let removed = self
            .link_state
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .expire(std::time::Duration::from_secs(30));
        if removed > 0 {
            self.generation.fetch_add(1, Ordering::Relaxed);
            let live: HashSet<NodeId> = self
                .link_state
                .read()
                .unwrap_or_else(|e| e.into_inner())
                .all()
                .map(|lsa| lsa.origin)
                .collect();
            let mut model = self.model.write().unwrap_or_else(|e| e.into_inner());
            let expired: Vec<NodeId> = model
                .lsas
                .keys()
                .filter(|node| !live.contains(node))
                .copied()
                .collect();
            for origin in expired {
                let command = ControllerCommand::ExpireLsa {
                    origin,
                    up_to_seq: u64::MAX,
                };
                self.append_command(command.clone());
                model.apply(command);
            }
            drop(model);
            self.persist_lsas();
        }
    }

    fn members(&self) -> Vec<MemberView> {
        let db = self.link_state.read().unwrap_or_else(|e| e.into_inner());
        let grants = self.grants.read().unwrap_or_else(|e| e.into_inner());
        let revisions: std::collections::BTreeMap<NodeId, u64> = self
            .model
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .member_revisions
            .clone();
        let mut out: Vec<MemberView> = db
            .all()
            .map(|lsa| {
                let grant = grants.get(&lsa.origin);
                MemberView {
                    node_id: lsa.origin.to_string(),
                    zone: lsa.zone.clone(),
                    overlay_ip: grant.and_then(|grant| grant.overlay_ip).or(lsa.overlay_ip),
                    addrs: lsa.addrs.clone(),
                    prefixes: lsa.prefixes.iter().map(|p| p.prefix.to_string()).collect(),
                    allowed_prefixes: grant
                        .map(|g| g.prefixes.iter().map(|p| p.to_string()).collect())
                        .unwrap_or_else(|| {
                            lsa.prefixes.iter().map(|p| p.prefix.to_string()).collect()
                        }),
                    capabilities: grant.map(|g| g.capabilities.clone()).unwrap_or_default(),
                    links: lsa.links.iter().map(|l| l.to.to_string()).collect(),
                    last_seq: lsa.seq,
                    revision: revisions.get(&lsa.origin).copied().unwrap_or(1),
                }
            })
            .collect();
        // Grants may exist before the first LSA; expose them for discovery/auth.
        for (node, grant) in grants.iter() {
            if out.iter().any(|m| m.node_id == node.to_string()) {
                continue;
            }
            out.push(MemberView {
                node_id: node.to_string(),
                zone: None,
                overlay_ip: grant.overlay_ip,
                addrs: Vec::new(),
                prefixes: Vec::new(),
                allowed_prefixes: grant.prefixes.iter().map(|p| p.to_string()).collect(),
                capabilities: grant.capabilities.clone(),
                links: Vec::new(),
                last_seq: 0,
                revision: revisions.get(node).copied().unwrap_or(1),
            });
        }
        out.sort_by(|a, b| a.node_id.cmp(&b.node_id));
        out
    }

    fn persist_acks(&self) {
        let acks = self.acks.read().unwrap_or_else(|e| e.into_inner());
        let map: HashMap<String, u64> = acks.iter().map(|(k, v)| (k.to_string(), *v)).collect();
        if let Ok(bytes) = serde_json::to_vec_pretty(&map) {
            if let Some(parent) = self.acks_path.parent()
                && let Err(e) = std::fs::create_dir_all(parent)
            {
                tracing::warn!(error = %e, "create controller state dir");
            }
            if let Err(e) = std::fs::write(&self.acks_path, bytes) {
                tracing::warn!(error = %e, "persist controller acknowledgements");
            }
        }
    }

    fn append_command(&self, command: ControllerCommand) {
        let bytes = match serde_json::to_vec(&command) {
            Ok(bytes) => bytes,
            Err(e) => {
                tracing::warn!(error = %e, "serialize controller command");
                return;
            }
        };
        if let Some(parent) = self.commands_path.parent()
            && let Err(e) = std::fs::create_dir_all(parent)
        {
            tracing::warn!(error = %e, "create controller command dir");
            return;
        }
        let result = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.commands_path)
            .and_then(|mut file| {
                use std::io::Write;
                file.write_all(&bytes)?;
                file.write_all(b"\n")?;
                file.sync_data()
            });
        if let Err(e) = result {
            tracing::warn!(error = %e, "append controller command");
        }
    }

    fn persist_members(&self) {
        let mut grants: Vec<ControllerMemberConfig> = self
            .grants
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .values()
            .cloned()
            .collect();
        grants.sort_by(|a, b| a.node_id.cmp(&b.node_id));
        let persisted = PersistedMembers { grants };
        let bytes = match serde_json::to_vec_pretty(&persisted) {
            Ok(bytes) => bytes,
            Err(e) => {
                tracing::warn!(error = %e, "serialize controller members");
                return;
            }
        };
        if let Some(parent) = self.members_path.parent()
            && let Err(e) = std::fs::create_dir_all(parent)
        {
            tracing::warn!(error = %e, "create controller members dir");
            return;
        }
        let tmp = self.members_path.with_extension("json.tmp");
        if let Err(e) =
            std::fs::write(&tmp, bytes).and_then(|_| std::fs::rename(&tmp, &self.members_path))
        {
            tracing::warn!(error = %e, "persist controller members");
        }
    }

    fn persist_lsas(&self) {
        let lsas = {
            let db = self.link_state.read().unwrap_or_else(|e| e.into_inner());
            db.all().cloned().collect::<Vec<_>>()
        };
        let persisted = PersistedLsas {
            saved_at: now_epoch(),
            lsas,
        };
        let bytes = match serde_json::to_vec_pretty(&persisted) {
            Ok(bytes) => bytes,
            Err(e) => {
                tracing::warn!(error = %e, "serialize controller LSAs");
                return;
            }
        };
        if let Some(parent) = self.lsas_path.parent()
            && let Err(e) = std::fs::create_dir_all(parent)
        {
            tracing::warn!(error = %e, "create controller LSA state dir");
            return;
        }
        let tmp = self.lsas_path.with_extension("json.tmp");
        if let Err(e) =
            std::fs::write(&tmp, bytes).and_then(|_| std::fs::rename(&tmp, &self.lsas_path))
        {
            tracing::warn!(error = %e, "persist controller LSAs");
        }
    }

    fn apply_lsa(&self, lsa: Lsa) -> Result<bool, (u16, String)> {
        self.ensure_leader()?;
        self.authorize_lsa(&lsa)?;
        self.note_lsa(lsa.origin);
        let model_lsa = lsa.clone();
        let changed = self
            .link_state
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .apply(lsa);
        if changed {
            self.generation.fetch_add(1, Ordering::Relaxed);
            self.append_command(ControllerCommand::ApplyLsa {
                lsa: model_lsa.clone(),
            });
            self.model
                .write()
                .unwrap_or_else(|e| e.into_inner())
                .apply(ControllerCommand::ApplyLsa { lsa: model_lsa });
            self.persist_lsas();
        }
        Ok(changed)
    }

    fn authorize_lsa(&self, lsa: &Lsa) -> Result<(), (u16, String)> {
        if !self.strict_membership {
            return Ok(());
        }
        let grants = self.grants.read().unwrap_or_else(|e| e.into_inner());
        let Some(grant) = grants.get(&lsa.origin) else {
            return Err((403, format!("member {} is not authorized", lsa.origin)));
        };
        if let Some(expected) = grant.overlay_ip
            && lsa.overlay_ip != Some(expected)
        {
            return Err((403, "LSA overlay_ip does not match member grant".into()));
        }
        for prefix in &lsa.prefixes {
            let own = grant
                .overlay_ip
                .is_some_and(|ip| stellaris_types::host_prefix(ip) == prefix.prefix);
            if !own && !grant.prefixes.contains(&prefix.prefix) {
                return Err((
                    403,
                    format!(
                        "prefix {} is not authorized for {}",
                        prefix.prefix, lsa.origin
                    ),
                ));
            }
        }
        for link in &lsa.links {
            if !grants.contains_key(&link.to) {
                return Err((403, format!("link target {} is not authorized", link.to)));
            }
        }
        Ok(())
    }

    async fn revoke_current(&self, node: NodeId) -> Result<(), (u16, String)> {
        if let Some(raft) = &self.raft {
            raft.client_write(ControllerCommand::RevokeMember {
                node,
                now: crate::credential::now_secs(),
            })
            .await
            .map(|_| ())
            .map_err(|e| (503, format!("raft revoke failed: {e}")))
        } else {
            self.revoke(node)
        }
    }

    fn revoke(&self, node: NodeId) -> Result<(), (u16, String)> {
        self.ensure_leader()?;
        let removed = self
            .grants
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&node)
            .is_some();
        if !removed {
            return Err((404, "member not found".into()));
        }
        self.link_state
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .remove(node);
        let now = crate::credential::now_secs();
        self.append_command(ControllerCommand::RevokeMember { node, now });
        self.model
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .apply(ControllerCommand::RevokeMember { node, now });
        self.persist_lsas();
        self.acks
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&node);
        self.persist_acks();
        self.persist_members();
        self.generation.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    /// Admin authority for revoke/route writes; falls back to the member
    /// secret when `control.admin_secret` is not configured.
    fn admin_authorized(&self, headers: &HeaderMap) -> bool {
        let provided = headers
            .get("x-stellaris-secret")
            .and_then(|v| v.to_str().ok());
        match (&self.admin_secret, &self.secret) {
            (Some(admin), _) => provided.is_some_and(|value| value == admin),
            (None, _) => self.authorized_secret(provided),
        }
    }

    fn authorized(&self, headers: &HeaderMap) -> bool {
        let provided = headers
            .get("x-stellaris-secret")
            .and_then(|v| v.to_str().ok());
        self.authorized_secret(provided)
    }

    pub fn authorized_secret(&self, provided: Option<&str>) -> bool {
        let Some(provided) = provided else {
            return self.secret.is_none() && self.previous_secrets.is_empty();
        };
        self.secret.as_deref() == Some(provided)
            || self.previous_secrets.iter().any(|s| s == provided)
    }

    fn record_ack(
        &self,
        node: NodeId,
        generation: u64,
        epoch: Option<u64>,
    ) -> Result<(), (u16, String)> {
        if let Some(epoch) = epoch
            && epoch != self.epoch
        {
            return Err((409, "controller epoch changed; refetch snapshot".into()));
        }
        let mut acks = self.acks.write().unwrap_or_else(|e| e.into_inner());
        let current = acks.entry(node).or_insert(0);
        if generation > *current {
            *current = generation;
        }
        drop(acks);
        let command = ControllerCommand::Ack {
            node,
            generation,
            epoch: self.epoch,
        };
        self.append_command(command.clone());
        self.model
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .apply(command);
        self.persist_acks();
        Ok(())
    }

    async fn record_ack_current(
        &self,
        node: NodeId,
        generation: u64,
        epoch: Option<u64>,
    ) -> Result<(), (u16, String)> {
        if let Some(raft) = &self.raft {
            let model = self.model_current().await;
            if let Some(epoch) = epoch
                && epoch != model.epoch
            {
                return Err((409, "controller epoch changed; refetch snapshot".into()));
            }
            return raft
                .client_write(ControllerCommand::Ack {
                    node,
                    generation,
                    epoch: model.epoch,
                })
                .await
                .map(|_| ())
                .map_err(|e| (503, format!("raft write failed: {e}")));
        }
        self.record_ack(node, generation, epoch)
    }

    async fn upsert_route_current(
        &self,
        prefix: IpNet,
        via: NodeId,
        metric: u32,
    ) -> Result<(), (u16, String)> {
        if let Some(raft) = &self.raft {
            raft.client_write(ControllerCommand::UpsertRoute {
                prefix: prefix.to_string(),
                via,
                metric,
            })
            .await
            .map(|_| ())
            .map_err(|e| (503, format!("raft write failed: {e}")))
        } else {
            self.add_route(prefix, via, metric);
            self.model.write().unwrap_or_else(|e| e.into_inner()).apply(
                ControllerCommand::UpsertRoute {
                    prefix: prefix.to_string(),
                    via,
                    metric,
                },
            );
            Ok(())
        }
    }

    fn add_route(&self, prefix: IpNet, via: NodeId, metric: u32) -> RouteEntry {
        let mut guard = self.routes.write().unwrap_or_else(|e| e.into_inner());
        guard.retain(|r| !(r.prefix == prefix && r.next_hop == via));
        let generation = self.generation.fetch_add(1, Ordering::Relaxed) + 1;
        let entry = make_route(self.network, prefix, via, metric, generation);
        guard.push(entry.clone());
        entry
    }
}

fn now_epoch() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(1)
}

fn load_commands(path: &std::path::Path) -> Vec<ControllerCommand> {
    let Ok(text) = std::fs::read_to_string(path) else {
        return Vec::new();
    };
    text.lines()
        .filter(|line| !line.trim().is_empty())
        .filter_map(|line| match serde_json::from_str(line) {
            Ok(command) => Some(command),
            Err(e) => {
                tracing::warn!(error = %e, "skip invalid controller command");
                None
            }
        })
        .collect()
}

fn load_lsas(path: &std::path::Path) -> PersistedLsas {
    let Ok(bytes) = std::fs::read(path) else {
        return PersistedLsas {
            saved_at: 0,
            lsas: Vec::new(),
        };
    };
    match serde_json::from_slice(&bytes) {
        Ok(lsas) => lsas,
        Err(e) => {
            tracing::warn!(error = %e, path = %path.display(), "load controller LSAs");
            PersistedLsas {
                saved_at: 0,
                lsas: Vec::new(),
            }
        }
    }
}

fn load_members(path: &std::path::Path) -> PersistedMembers {
    let Ok(bytes) = std::fs::read(path) else {
        return PersistedMembers::default();
    };
    match serde_json::from_slice(&bytes) {
        Ok(members) => members,
        Err(e) => {
            tracing::warn!(error = %e, path = %path.display(), "load controller members");
            PersistedMembers::default()
        }
    }
}

fn load_acks(path: &std::path::Path) -> HashMap<NodeId, u64> {
    let Ok(bytes) = std::fs::read(path) else {
        return HashMap::new();
    };
    let Ok(map) = serde_json::from_slice::<HashMap<String, u64>>(&bytes) else {
        return HashMap::new();
    };
    map.into_iter()
        .filter_map(|(k, v)| k.parse().ok().map(|node| (node, v)))
        .collect()
}

fn make_route(
    network: NetworkId,
    prefix: IpNet,
    via: NodeId,
    metric: u32,
    _generation: u64,
) -> RouteEntry {
    let mut entry = RouteEntry::new(
        network,
        prefix,
        RouteSource::Controller,
        NodeId::new([0; 32]),
        via,
    );
    entry.id = RouteId::new();
    entry.admin_distance = 20;
    entry.metric = metric;
    entry.state = RouteState::Active;
    entry
}

pub fn router(state: ControllerState) -> Router {
    Router::new()
        .route("/healthz", get(healthz))
        .route("/readyz", get(readyz))
        .route("/metrics", get(controller_metrics))
        .route("/v1/status", get(status))
        .route("/v1/snapshot", get(snapshot))
        .route("/v1/routes", post(add_route))
        .route("/v1/lsa", post(apply_lsa))
        .route("/v1/enroll", post(enroll))
        .route("/v1/members/{node}/grants", post(update_grants))
        .route("/v1/manifest", get(manifest))
        .route("/v1/model", get(model))
        .route("/v1/revoke", post(revoke))
        .route("/v1/ack", post(ack))
        .route("/v1/raft/learner", post(raft_add_learner))
        .route("/v1/raft/membership", post(raft_change_membership))
        .route("/v1/admissions", get(list_admissions))
        .route("/v1/admissions/{node}/approve", post(approve_admission))
        .route("/v1/admissions/{node}/deny", post(deny_admission))
        .route("/v1/ipam/pools", get(list_pools).post(create_pool))
        .route(
            "/v1/ipam/pools/{id}",
            patch(update_pool).delete(delete_pool),
        )
        .route("/v1/ipam/leases", get(list_leases))
        .route("/v1/ipam/leases/{node}/renew", post(renew_lease))
        .route("/v1/ipam/leases/{node}/release", post(release_lease))
        .route("/v1/ipam/leases/{node}/reassign", post(reassign_address))
        .route("/v1/ipam/reservations", post(reserve_address))
        .route("/v1/ipam/reservations/{node}", delete(remove_reservation))
        .route("/v1/ipam/allocate", post(allocate_address))
        .with_state(state)
}

fn validate_pool(
    pool: &AddressPool,
    network_cidr: IpNet,
    model: &ControllerModel,
) -> Result<(), (u16, String)> {
    if pool.id.trim().is_empty() {
        return Err((400, "pool id must not be empty".into()));
    }
    let same_family = matches!(
        (&pool.cidr, &network_cidr),
        (IpNet::V4(_), IpNet::V4(_)) | (IpNet::V6(_), IpNet::V6(_))
    );
    if !same_family {
        return Err((400, "pool address family differs from network.cidr".into()));
    }
    if pool.cidr.prefix_len() < network_cidr.prefix_len()
        || !network_cidr.contains(&pool.cidr.network())
    {
        return Err((
            400,
            format!("pool {} is outside network.cidr {network_cidr}", pool.cidr),
        ));
    }
    if pool.lease_secs == 0 {
        return Err((400, "pool lease_secs must be > 0".into()));
    }
    if let Some((start, end)) = pool.range
        && (!pool.cidr.contains(&start) || !pool.cidr.contains(&end))
    {
        return Err((400, "pool range is outside its cidr".into()));
    }
    for excluded in &pool.exclude {
        if !pool.cidr.contains(&excluded.network())
            || excluded.prefix_len() < pool.cidr.prefix_len()
        {
            return Err((400, format!("exclude {excluded} is outside {}", pool.cidr)));
        }
    }
    if let IpNet::V4(_) = pool.cidr
        && pool.range.is_none()
        && pool.cidr.prefix_len() < 16
    {
        return Err((
            400,
            "IPv4 pools larger than /16 require an explicit range".into(),
        ));
    }
    for other in model.pools.values().filter(|other| other.id != pool.id) {
        if other.cidr.contains(&pool.cidr.network()) || pool.cidr.contains(&other.cidr.network()) {
            return Err((409, format!("pool overlaps {}", other.id)));
        }
    }
    Ok(())
}

async fn list_pools(State(state): State<ControllerState>, headers: HeaderMap) -> Response {
    if !state.admin_authorized(&headers) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    let model = state.model_current().await;
    let pools: Vec<_> = model
        .pools
        .values()
        .map(|pool| {
            json!({
                "pool": pool,
                "allocated": model.leases.values().filter(|lease| lease.pool == pool.id).count(),
            })
        })
        .collect();
    Json(json!({
        "pools": pools,
        "leases": model.leases.len(),
        "quarantined": model.quarantine.len(),
    }))
    .into_response()
}

async fn create_pool(
    State(state): State<ControllerState>,
    headers: HeaderMap,
    Json(pool): Json<AddressPool>,
) -> Response {
    if !state.admin_authorized(&headers) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    let model = state.model_current().await;
    if let Err((code, message)) = validate_pool(&pool, state.cidr, &model) {
        return (
            StatusCode::from_u16(code).unwrap_or(StatusCode::BAD_REQUEST),
            message,
        )
            .into_response();
    }
    let id = pool.id.clone();
    match state
        .commit_command(ControllerCommand::CreatePool { pool })
        .await
    {
        Ok(()) => Json(json!({"created": id})).into_response(),
        Err((code, message)) => controller_error(&state, code, message).await,
    }
}

async fn update_pool(
    State(state): State<ControllerState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(mut pool): Json<AddressPool>,
) -> Response {
    if !state.admin_authorized(&headers) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    pool.id = id;
    let model = state.model_current().await;
    if let Err((code, message)) = validate_pool(&pool, state.cidr, &model) {
        return (
            StatusCode::from_u16(code).unwrap_or(StatusCode::BAD_REQUEST),
            message,
        )
            .into_response();
    }
    let pool_id = pool.id.clone();
    match state
        .commit_command(ControllerCommand::UpdatePool { pool })
        .await
    {
        Ok(()) => Json(json!({"updated": pool_id})).into_response(),
        Err((code, message)) => controller_error(&state, code, message).await,
    }
}

#[derive(Debug, Deserialize)]
struct DeletePoolQuery {
    #[serde(default)]
    force: bool,
}

async fn delete_pool(
    State(state): State<ControllerState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Query(query): Query<DeletePoolQuery>,
) -> Response {
    if !state.admin_authorized(&headers) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    match state
        .commit_command(ControllerCommand::DeletePool {
            id,
            force: query.force,
            now: crate::credential::now_secs(),
        })
        .await
    {
        Ok(()) => Json(json!({"deleted": true})).into_response(),
        Err((code, message)) => controller_error(&state, code, message).await,
    }
}

async fn list_leases(State(state): State<ControllerState>, headers: HeaderMap) -> Response {
    if !state.admin_authorized(&headers) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    let model = state.model_current().await;
    Json(json!({
        "leases": model.leases.values().collect::<Vec<_>>(),
        "reservations": model.reservations.values().collect::<Vec<_>>(),
        "quarantine": model
            .quarantine
            .iter()
            .map(|(ip, until)| json!({"ip": ip, "until": until}))
            .collect::<Vec<_>>(),
    }))
    .into_response()
}

async fn renew_lease(
    State(state): State<ControllerState>,
    headers: HeaderMap,
    Path(node): Path<String>,
) -> Response {
    if !state.admin_authorized(&headers) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    let Ok(node) = node.parse::<NodeId>() else {
        return (StatusCode::BAD_REQUEST, "invalid node").into_response();
    };
    match state
        .commit_command(ControllerCommand::RenewLease {
            node,
            now: crate::credential::now_secs(),
        })
        .await
    {
        Ok(()) => Json(json!({"renewed": node.to_string()})).into_response(),
        Err((code, message)) => controller_error(&state, code, message).await,
    }
}

async fn release_lease(
    State(state): State<ControllerState>,
    headers: HeaderMap,
    Path(node): Path<String>,
) -> Response {
    if !state.admin_authorized(&headers) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    let Ok(node) = node.parse::<NodeId>() else {
        return (StatusCode::BAD_REQUEST, "invalid node").into_response();
    };
    match state
        .commit_command(ControllerCommand::ReleaseAddress {
            node,
            now: crate::credential::now_secs(),
        })
        .await
    {
        Ok(()) => Json(json!({"released": node.to_string()})).into_response(),
        Err((code, message)) => controller_error(&state, code, message).await,
    }
}

#[derive(Debug, Deserialize)]
struct ReservationRequest {
    node: String,
    ip: String,
    #[serde(default)]
    pool: Option<String>,
    #[serde(default)]
    note: Option<String>,
}

async fn reserve_address(
    State(state): State<ControllerState>,
    headers: HeaderMap,
    Json(req): Json<ReservationRequest>,
) -> Response {
    if !state.admin_authorized(&headers) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    let node: NodeId = match req.node.parse() {
        Ok(node) => node,
        Err(e) => return (StatusCode::BAD_REQUEST, format!("invalid node: {e}")).into_response(),
    };
    let ip: std::net::IpAddr = match req.ip.parse() {
        Ok(ip) => ip,
        Err(e) => return (StatusCode::BAD_REQUEST, format!("invalid ip: {e}")).into_response(),
    };
    let model = state.model_current().await;
    if state.validate_overlay(&model, node, ip).is_err() {
        return (StatusCode::CONFLICT, "address is already in use").into_response();
    }
    if let Some(pool) = &req.pool
        && !model.pools.contains_key(pool)
    {
        return (StatusCode::BAD_REQUEST, "unknown pool").into_response();
    }
    match state
        .commit_command(ControllerCommand::ReserveAddress {
            node,
            ip,
            pool: req.pool,
            note: req.note,
        })
        .await
    {
        Ok(()) => Json(json!({"reserved": node.to_string(), "ip": ip.to_string()})).into_response(),
        Err((code, message)) => controller_error(&state, code, message).await,
    }
}

async fn remove_reservation(
    State(state): State<ControllerState>,
    headers: HeaderMap,
    Path(node): Path<String>,
) -> Response {
    if !state.admin_authorized(&headers) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    let Ok(node) = node.parse::<NodeId>() else {
        return (StatusCode::BAD_REQUEST, "invalid node").into_response();
    };
    match state
        .commit_command(ControllerCommand::ReleaseAddress {
            node,
            now: crate::credential::now_secs(),
        })
        .await
    {
        Ok(()) => Json(json!({"released": node.to_string()})).into_response(),
        Err((code, message)) => controller_error(&state, code, message).await,
    }
}

#[derive(Debug, Deserialize)]
struct AllocateRequest {
    node: String,
    #[serde(default)]
    pool: Option<String>,
    #[serde(default)]
    zone: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ReassignRequest {
    #[serde(default)]
    ip: Option<String>,
    #[serde(default)]
    pool: Option<String>,
    #[serde(default)]
    zone: Option<String>,
}

async fn reassign_address(
    State(state): State<ControllerState>,
    headers: HeaderMap,
    Path(node): Path<String>,
    Json(req): Json<ReassignRequest>,
) -> Response {
    if !state.admin_authorized(&headers) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    let node: NodeId = match node.parse() {
        Ok(node) => node,
        Err(e) => return (StatusCode::BAD_REQUEST, format!("invalid node: {e}")).into_response(),
    };
    let ip = match req.ip.as_deref() {
        Some(ip) => match ip.parse::<IpAddr>() {
            Ok(ip) => Some(ip),
            Err(e) => return (StatusCode::BAD_REQUEST, format!("invalid ip: {e}")).into_response(),
        },
        None => None,
    };
    let model = state.model_current().await;
    let Some(member) = model.members.get(&node) else {
        return (StatusCode::NOT_FOUND, "member not found").into_response();
    };
    let old = member.overlay_ip;
    let now = crate::credential::now_secs();
    let (target, pool_id) = match ip {
        Some(ip) => match model.validate_reassign(node, ip, req.pool.as_deref(), now) {
            Ok(pool) => (ip, pool),
            Err(error) => return (StatusCode::CONFLICT, error).into_response(),
        },
        None => match model.allocate_for_reassign(
            node,
            req.pool.as_deref(),
            req.zone.as_deref(),
            now,
            old,
        ) {
            Ok(allocation) => allocation,
            Err(error) => return (StatusCode::CONFLICT, error).into_response(),
        },
    };
    if old == Some(target) {
        return (
            StatusCode::CONFLICT,
            "address is already assigned to this member",
        )
            .into_response();
    }
    if let Err((code, message)) = state
        .commit_command(ControllerCommand::ReassignAddress {
            node,
            ip: Some(target),
            pool: Some(pool_id),
            zone: req.zone,
            now,
        })
        .await
    {
        return controller_error(&state, code, message).await;
    }
    let updated = state.model_current().await;
    let new = updated
        .members
        .get(&node)
        .and_then(|member| member.overlay_ip);
    if new != Some(target) {
        return (StatusCode::CONFLICT, "reassignment was not applied").into_response();
    }
    Json(json!({
        "node": node.to_string(),
        "old": old.map(|ip| ip.to_string()),
        "new": new.map(|ip| ip.to_string()),
        "revision": updated.member_revisions.get(&node).copied().unwrap_or(0),
    }))
    .into_response()
}

async fn allocate_address(
    State(state): State<ControllerState>,
    headers: HeaderMap,
    Json(req): Json<AllocateRequest>,
) -> Response {
    if !state.admin_authorized(&headers) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    let node: NodeId = match req.node.parse() {
        Ok(node) => node,
        Err(e) => return (StatusCode::BAD_REQUEST, format!("invalid node: {e}")).into_response(),
    };
    let model = state.model_current().await;
    let Some(member) = model.members.get(&node).cloned() else {
        return (StatusCode::NOT_FOUND, "member not found").into_response();
    };
    if member.overlay_ip.is_some() {
        return (StatusCode::CONFLICT, "member already has an address").into_response();
    }
    let now = crate::credential::now_secs();
    let (ip, pool_id, _, _) =
        match model.allocate_address(node, req.pool.as_deref(), req.zone.as_deref(), now) {
            Ok(allocation) => allocation,
            Err(error) => return (StatusCode::CONFLICT, error).into_response(),
        };
    let mut updated = member;
    updated.overlay_ip = Some(ip);
    match state
        .commit_command(ControllerCommand::ApproveAdmission {
            node,
            member: updated,
            auto: false,
            pool: Some(pool_id),
            zone: req.zone,
            now,
        })
        .await
    {
        Ok(()) => {
            Json(json!({"allocated": ip.to_string(), "node": node.to_string()})).into_response()
        }
        Err((code, message)) => controller_error(&state, code, message).await,
    }
}

async fn status(State(state): State<ControllerState>, headers: HeaderMap) -> Response {
    if !state.admin_authorized(&headers) && !state.authorized(&headers) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    let model = state.model_current().await;
    let local = state.signer.unwrap_or_else(|| NodeId::new([0u8; 32]));
    Json(json!({
        "network_id": model.network.to_string(),
        "epoch": model.epoch,
        "generation": model.generation,
        "routes": model.routes(local).len(),
        "acks": model.acks.len(),
        "leader": state.leader_hint().await,
        "raft": state.raft_timing().map(|timing| json!({
            "election_timeout_min_ms": timing.election_timeout_min_ms,
            "election_timeout_max_ms": timing.election_timeout_max_ms,
            "heartbeat_interval_ms": timing.heartbeat_interval_ms,
            "source": timing.source.as_str(),
        })),
    }))
    .into_response()
}

async fn healthz() -> &'static str {
    "ok"
}

async fn readyz(State(state): State<ControllerState>) -> Response {
    let ready = state
        .raft
        .as_ref()
        .map(|raft| {
            let watch = raft.metrics();
            let metrics = watch.borrow_watched();
            metrics.running_state.is_ok() && metrics.current_leader.is_some()
        })
        .unwrap_or(true);
    if ready {
        (StatusCode::OK, "ready").into_response()
    } else {
        (StatusCode::SERVICE_UNAVAILABLE, "not ready").into_response()
    }
}

async fn controller_metrics(State(state): State<ControllerState>, headers: HeaderMap) -> Response {
    if !state.authorized(&headers) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    let model = state.model_current().await;
    let raft = state
        .raft
        .as_ref()
        .map(|raft| (*raft.metrics().borrow_watched()).clone());
    let (raft_enabled, is_leader, term, last_log, last_applied) = match &raft {
        Some(metrics) => (
            1,
            u8::from(metrics.current_leader == state.raft_id),
            metrics.current_term,
            metrics.last_log_index.unwrap_or(0),
            metrics.last_applied.map(|id| id.index()).unwrap_or(0),
        ),
        None => (0, 0, 0, 0, 0),
    };
    let body = format!(
        "# HELP stellaris_controller_up Controller process is serving.\n\
# TYPE stellaris_controller_up gauge\n\
stellaris_controller_up 1\n\
# TYPE stellaris_controller_generation gauge\n\
stellaris_controller_generation {}\n\
# TYPE stellaris_controller_epoch gauge\n\
stellaris_controller_epoch {}\n\
# TYPE stellaris_controller_members gauge\n\
stellaris_controller_members {}\n\
# TYPE stellaris_controller_lsas gauge\n\
stellaris_controller_lsas {}\n\
# TYPE stellaris_controller_routes gauge\n\
stellaris_controller_routes {}\n\
# TYPE stellaris_controller_pools gauge\n\
stellaris_controller_pools {}\n\
# TYPE stellaris_controller_leases gauge\n\
stellaris_controller_leases {}\n\
# TYPE stellaris_controller_pending_admissions gauge\n\
stellaris_controller_pending_admissions {}\n\
# TYPE stellaris_controller_revoked gauge\n\
stellaris_controller_revoked {}\n\
# TYPE stellaris_controller_raft_enabled gauge\n\
stellaris_controller_raft_enabled {}\n\
# TYPE stellaris_controller_raft_is_leader gauge\n\
stellaris_controller_raft_is_leader {}\n\
# TYPE stellaris_controller_raft_term gauge\n\
stellaris_controller_raft_term {}\n\
# TYPE stellaris_controller_raft_last_log_index gauge\n\
stellaris_controller_raft_last_log_index {}\n\
# TYPE stellaris_controller_raft_last_applied gauge\n\
stellaris_controller_raft_last_applied {}\n",
        model.generation,
        model.epoch,
        model.members.len(),
        model.lsas.len(),
        model.routes.len(),
        model.pools.len(),
        model.leases.len(),
        model.pending_admissions.len(),
        model.revoked.len(),
        raft_enabled,
        is_leader,
        term,
        last_log,
        last_applied,
    );
    ([("content-type", "text/plain; version=0.0.4")], body).into_response()
}

#[derive(Debug, Deserialize)]
struct SnapshotQuery {
    node: Option<String>,
}

async fn controller_error(state: &ControllerState, code: u16, message: String) -> Response {
    let mut response = (
        StatusCode::from_u16(code).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
        message,
    )
        .into_response();
    if let Some(leader) = state.leader_hint().await
        && let Ok(value) = HeaderValue::from_str(&leader.to_string())
    {
        response
            .headers_mut()
            .insert("x-stellaris-raft-leader", value);
    }
    response
}

async fn snapshot(
    State(state): State<ControllerState>,
    headers: HeaderMap,
    Query(query): Query<SnapshotQuery>,
) -> Response {
    if !state.authorized(&headers) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    let local = match query.node.as_deref().map(str::parse::<NodeId>) {
        Some(Ok(node)) => Some(node),
        Some(Err(e)) => {
            return (StatusCode::BAD_REQUEST, format!("invalid node: {e}")).into_response();
        }
        None => None,
    };
    if let Err(e) = state.linearize().await {
        return (StatusCode::SERVICE_UNAVAILABLE, e).into_response();
    }
    Json(state.snapshot_current(local).await).into_response()
}

async fn model(State(state): State<ControllerState>, headers: HeaderMap) -> Response {
    if !state.admin_authorized(&headers) && !state.authorized(&headers) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    Json(state.model_current().await).into_response()
}

async fn manifest(State(state): State<ControllerState>, headers: HeaderMap) -> Response {
    if !state.admin_authorized(&headers) && !state.authorized(&headers) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    // Only the leader may sign a manifest: a stale follower would otherwise
    // hand members an old membership view.
    if let Err(error) = state.linearize().await {
        return controller_error(&state, 503, error).await;
    }
    Json(state.manifest_current().await).into_response()
}

async fn apply_lsa(
    State(state): State<ControllerState>,
    headers: HeaderMap,
    Json(lsa): Json<Lsa>,
) -> Response {
    if !state.authorized(&headers) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    match state.apply_lsa_current(lsa).await {
        Ok(changed) => {
            let model = state.model_current().await;
            Json(json!({
                "changed": changed,
                "generation": model.generation,
                "lsas": model.lsas.len(),
            }))
            .into_response()
        }
        Err((code, message)) => controller_error(&state, code, message).await,
    }
}

#[derive(Debug, Deserialize)]
struct EnrollRequest {
    node_id: String,
    #[serde(default)]
    overlay_ip: Option<String>,
    #[serde(default)]
    auto: bool,
    #[serde(default)]
    pool: Option<String>,
    #[serde(default)]
    zone: Option<String>,
    #[serde(default)]
    addrs: Vec<SocketAddr>,
    #[serde(default)]
    signature: String,
}

/// Canonical bytes a node signs for an HTTP enrollment request. The iroh
/// control channel does not need this: `conn.remote_id()` already proves the
/// node key.
pub fn enroll_payload_bytes(
    network: &str,
    node: &str,
    overlay: Option<&str>,
    zone: Option<&str>,
) -> Vec<u8> {
    format!(
        "stellaris-enroll-v1|{network}|{node}|{}|{}",
        overlay.unwrap_or(""),
        zone.unwrap_or("")
    )
    .into_bytes()
}

pub enum EnrollOutcome {
    Credential(Box<SignedCredential>),
    Pending,
    Denied(String),
}

async fn enroll(
    State(state): State<ControllerState>,
    headers: HeaderMap,
    Json(req): Json<EnrollRequest>,
) -> Response {
    if !state.authorized(&headers) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    let node: NodeId = match req.node_id.parse() {
        Ok(node) => node,
        Err(e) => {
            return (StatusCode::BAD_REQUEST, format!("invalid node_id: {e}")).into_response();
        }
    };
    let overlay: Option<std::net::IpAddr> =
        match req.overlay_ip.as_deref().map(str::parse).transpose() {
            Ok(overlay) => overlay,
            Err(e) => {
                return (StatusCode::BAD_REQUEST, format!("invalid overlay_ip: {e}"))
                    .into_response();
            }
        };
    let overlay_text = overlay.map(|ip| ip.to_string());
    let payload = enroll_payload_bytes(
        &state.network.to_string(),
        &node.to_string(),
        overlay_text.as_deref(),
        req.zone.as_deref(),
    );
    if let Err(error) = verify_ed25519(node, &payload, &req.signature) {
        return (
            StatusCode::FORBIDDEN,
            format!("invalid enroll signature: {error}"),
        )
            .into_response();
    }
    let _ = req.addrs;
    match state
        .enroll(node, overlay, req.auto, req.pool.clone(), req.zone.clone())
        .await
    {
        Ok(EnrollOutcome::Credential(credential)) => {
            Json(json!({"credential": credential})).into_response()
        }
        Ok(EnrollOutcome::Pending) => (
            StatusCode::ACCEPTED,
            Json(json!({"pending": true, "node": node.to_string()})),
        )
            .into_response(),
        Ok(EnrollOutcome::Denied(reason)) => (StatusCode::FORBIDDEN, reason).into_response(),
        Err((code, message)) => controller_error(&state, code, message).await,
    }
}

#[derive(Debug, Deserialize)]
struct UpdateGrantsRequest {
    #[serde(default)]
    overlay_ip: Option<String>,
    #[serde(default)]
    prefixes: Vec<String>,
    #[serde(default)]
    capabilities: Vec<String>,
}

async fn update_grants(
    State(state): State<ControllerState>,
    headers: HeaderMap,
    Path(node): Path<String>,
    Json(req): Json<UpdateGrantsRequest>,
) -> Response {
    if !state.admin_authorized(&headers) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    let node: NodeId = match node.parse() {
        Ok(node) => node,
        Err(e) => return (StatusCode::BAD_REQUEST, format!("invalid node: {e}")).into_response(),
    };
    let model = state.model_current().await;
    let Some(existing) = model.members.get(&node) else {
        return (StatusCode::NOT_FOUND, "member not found").into_response();
    };
    let overlay_ip = match req
        .overlay_ip
        .as_deref()
        .map(str::parse::<std::net::IpAddr>)
        .transpose()
    {
        Ok(overlay) => overlay.or(existing.overlay_ip),
        Err(e) => {
            return (StatusCode::BAD_REQUEST, format!("invalid overlay_ip: {e}")).into_response();
        }
    };
    for prefix in &req.prefixes {
        if prefix.parse::<IpNet>().is_err() {
            return (StatusCode::BAD_REQUEST, format!("invalid prefix: {prefix}")).into_response();
        }
    }
    let member = MemberRecord {
        overlay_ip,
        prefixes: req.prefixes,
        capabilities: req.capabilities,
    };
    match state
        .commit_command(ControllerCommand::UpsertMember { node, member })
        .await
    {
        Ok(()) => Json(json!({"updated": node.to_string()})).into_response(),
        Err((code, message)) => controller_error(&state, code, message).await,
    }
}

async fn list_admissions(State(state): State<ControllerState>, headers: HeaderMap) -> Response {
    if !state.admin_authorized(&headers) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    let model = state.model_current().await;
    let pending: Vec<_> = model
        .pending_admissions
        .iter()
        .map(|(node, admission)| {
            json!({
                "node": node.to_string(),
                "overlay_ip": admission.overlay_ip.map(|ip| ip.to_string()),
                "auto": admission.auto,
                "pool": admission.pool,
                "zone": admission.zone,
            })
        })
        .collect();
    Json(json!({"pending": pending})).into_response()
}

#[derive(Debug, Deserialize)]
struct ApproveAdmissionRequest {
    #[serde(default)]
    prefixes: Vec<String>,
    #[serde(default)]
    capabilities: Vec<String>,
}

async fn approve_admission(
    State(state): State<ControllerState>,
    headers: HeaderMap,
    Path(node): Path<String>,
    Json(req): Json<ApproveAdmissionRequest>,
) -> Response {
    if !state.admin_authorized(&headers) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    let node: NodeId = match node.parse() {
        Ok(node) => node,
        Err(e) => return (StatusCode::BAD_REQUEST, format!("invalid node: {e}")).into_response(),
    };
    let model = state.model_current().await;
    let Some(pending) = model.pending_admissions.get(&node) else {
        return (StatusCode::NOT_FOUND, "no pending admission for node").into_response();
    };
    for prefix in &req.prefixes {
        if prefix.parse::<IpNet>().is_err() {
            return (StatusCode::BAD_REQUEST, format!("invalid prefix: {prefix}")).into_response();
        }
    }
    let now = crate::credential::now_secs();
    let overlay = match pending.overlay_ip {
        Some(ip) => ip,
        None => match model.allocate_address(
            node,
            pending.pool.as_deref(),
            pending.zone.as_deref(),
            now,
        ) {
            Ok((ip, _, _, _)) => ip,
            Err(error) => {
                return (StatusCode::CONFLICT, error).into_response();
            }
        },
    };
    let member = crate::controller_model::MemberRecord {
        overlay_ip: Some(overlay),
        prefixes: req.prefixes.clone(),
        capabilities: req.capabilities.clone(),
    };
    match state
        .commit_command(ControllerCommand::ApproveAdmission {
            node,
            member,
            auto: false,
            pool: pending.pool.clone(),
            zone: pending.zone.clone(),
            now,
        })
        .await
    {
        Ok(()) => Json(json!({"approved": node.to_string()})).into_response(),
        Err((code, message)) => controller_error(&state, code, message).await,
    }
}

async fn deny_admission(
    State(state): State<ControllerState>,
    headers: HeaderMap,
    Path(node): Path<String>,
) -> Response {
    if !state.admin_authorized(&headers) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    let node: NodeId = match node.parse() {
        Ok(node) => node,
        Err(e) => return (StatusCode::BAD_REQUEST, format!("invalid node: {e}")).into_response(),
    };
    match state
        .commit_command(ControllerCommand::DenyAdmission {
            node,
            now: crate::credential::now_secs(),
        })
        .await
    {
        Ok(()) => Json(json!({"denied": node.to_string()})).into_response(),
        Err((code, message)) => controller_error(&state, code, message).await,
    }
}

#[derive(Debug, Deserialize)]
struct RevokeRequest {
    node_id: String,
}

async fn revoke(
    State(state): State<ControllerState>,
    headers: HeaderMap,
    Json(req): Json<RevokeRequest>,
) -> Response {
    if !state.admin_authorized(&headers) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    let node: NodeId = match req.node_id.parse() {
        Ok(node) => node,
        Err(e) => {
            return (StatusCode::BAD_REQUEST, format!("invalid node_id: {e}")).into_response();
        }
    };
    match state.revoke_current(node).await {
        Ok(()) => {
            let model = state.model_current().await;
            Json(json!({
                "revoked": node.to_string(),
                "generation": model.generation,
                "epoch": model.epoch,
            }))
            .into_response()
        }
        Err((code, message)) => controller_error(&state, code, message).await,
    }
}

#[derive(Debug, Deserialize)]
struct Ack {
    node: String,
    generation: u64,
    #[serde(default)]
    epoch: Option<u64>,
}

async fn ack(
    State(state): State<ControllerState>,
    headers: HeaderMap,
    Json(req): Json<Ack>,
) -> Response {
    if !state.authorized(&headers) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    let node: NodeId = match req.node.parse() {
        Ok(node) => node,
        Err(e) => return (StatusCode::BAD_REQUEST, format!("invalid node: {e}")).into_response(),
    };
    match state
        .record_ack_current(node, req.generation, req.epoch)
        .await
    {
        Ok(()) => Json(json!({"acked": req.generation, "node": node.to_string()})).into_response(),
        Err((code, message)) => controller_error(&state, code, message).await,
    }
}

#[derive(Debug, Deserialize)]
struct LearnerRequest {
    id: u64,
    addr: String,
}

#[derive(Debug, Deserialize)]
struct MembershipRequest {
    voters: Vec<LearnerRequest>,
}

async fn raft_add_learner(
    State(state): State<ControllerState>,
    headers: HeaderMap,
    Json(req): Json<LearnerRequest>,
) -> Response {
    if !state.admin_authorized(&headers) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    let Some(raft) = state.raft.clone() else {
        return (StatusCode::SERVICE_UNAVAILABLE, "raft is not enabled").into_response();
    };
    if req.id == 0 || req.addr.parse::<std::net::SocketAddr>().is_err() {
        return (
            StatusCode::BAD_REQUEST,
            "id must be non-zero and addr must be a socket address",
        )
            .into_response();
    }
    match raft
        .add_learner(req.id, BasicNode::new(req.addr.clone()), false)
        .await
    {
        Ok(_) => Json(json!({"learner": req.id, "addr": req.addr})).into_response(),
        Err(error) => {
            (StatusCode::CONFLICT, format!("add_learner failed: {error}")).into_response()
        }
    }
}

async fn raft_change_membership(
    State(state): State<ControllerState>,
    headers: HeaderMap,
    Json(req): Json<MembershipRequest>,
) -> Response {
    if !state.admin_authorized(&headers) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    let Some(raft) = state.raft.clone() else {
        return (StatusCode::SERVICE_UNAVAILABLE, "raft is not enabled").into_response();
    };
    let mut voters = std::collections::BTreeSet::new();
    for voter in &req.voters {
        if voter.id == 0 || voter.addr.parse::<std::net::SocketAddr>().is_err() {
            return (
                StatusCode::BAD_REQUEST,
                "voters need non-zero ids and socket addresses",
            )
                .into_response();
        }
        if !voters.insert(voter.id) {
            return (StatusCode::BAD_REQUEST, "duplicate voter id").into_response();
        }
    }
    if voters.is_empty() {
        return (StatusCode::BAD_REQUEST, "voters must not be empty").into_response();
    }
    // Register the addresses first so the membership edit can resolve each
    // voter to its Raft node, then replace the voter set in one joint step.
    for voter in &req.voters {
        if let Err(error) = raft
            .add_learner(voter.id, BasicNode::new(voter.addr.clone()), false)
            .await
        {
            tracing::debug!(%error, id = voter.id, "add_learner before membership change failed");
        }
    }
    match raft.change_membership(voters, false).await {
        Ok(_) => Json(json!({"voters": req.voters.len()})).into_response(),
        Err(error) => (
            StatusCode::CONFLICT,
            format!("change_membership failed: {error}"),
        )
            .into_response(),
    }
}

#[derive(Debug, Deserialize)]
struct AddRoute {
    prefix: String,
    via: String,
    #[serde(default = "default_metric")]
    metric: u32,
}

fn default_metric() -> u32 {
    10
}

async fn add_route(
    State(state): State<ControllerState>,
    headers: HeaderMap,
    Json(req): Json<AddRoute>,
) -> Response {
    if !state.admin_authorized(&headers) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    let prefix: IpNet = match req.prefix.parse() {
        Ok(p) => p,
        Err(e) => return (StatusCode::BAD_REQUEST, format!("invalid prefix: {e}")).into_response(),
    };
    let via: NodeId = match req.via.parse() {
        Ok(v) => v,
        Err(e) => return (StatusCode::BAD_REQUEST, format!("invalid via: {e}")).into_response(),
    };
    if let Err((code, message)) = state.upsert_route_current(prefix, via, req.metric).await {
        return controller_error(&state, code, message).await;
    }
    let model = state.model_current().await;
    let entry = model
        .route_entries()
        .into_iter()
        .find(|route| route.prefix == prefix && route.next_hop == via);
    Json(json!({"generation": model.generation, "route": entry})).into_response()
}

pub async fn run(config: Config) -> anyhow::Result<()> {
    let mut state = ControllerState::from_config(&config)?;
    let state_dir = PathBuf::from(&config.node.state_dir);
    std::fs::create_dir_all(&state_dir)?;
    let identity = crate::identity::load_or_create(&state_dir)?;
    state.set_signing_key(identity.secret);
    if let Some(leader) = state.leader
        && state.signer != Some(leader)
    {
        tracing::warn!(%leader, signer = ?state.signer, "controller is not the configured leader; writes will be rejected");
    }
    if let Some(raft_dir) = &config.control.raft_dir {
        let dir = PathBuf::from(raft_dir);
        std::fs::create_dir_all(&dir)?;
        let timing = crate::controller_raft::resolve_raft_timing(&config.control);
        // Seed Raft with the model already parsed from config/persisted state,
        // otherwise `[[control.members]]` never reaches the replicated state
        // machine and members cannot enroll.
        let model = state.model();
        let id = config.control.raft_id.unwrap_or(1);
        let bind: SocketAddr = config
            .control
            .raft_bind
            .as_deref()
            .unwrap_or("127.0.0.1:0")
            .parse()
            .context("control.raft_bind")?;
        let peers = config
            .control
            .raft_peers
            .iter()
            .map(|peer| (peer.id, peer.addr.clone()))
            .collect();
        let tls = config
            .control
            .raft_tls_cert
            .clone()
            .zip(config.control.raft_tls_key.clone())
            .map(|(cert, key)| crate::controller_raft::RaftTlsConfig {
                cert: PathBuf::from(cert),
                key: PathBuf::from(key),
                ca: config.control.raft_tls_ca.clone().map(PathBuf::from),
                insecure: config.control.raft_tls_insecure,
                client_cert: config
                    .control
                    .raft_tls_client_cert
                    .clone()
                    .map(PathBuf::from),
                client_key: config
                    .control
                    .raft_tls_client_key
                    .clone()
                    .map(PathBuf::from),
                require_client_cert: config.control.raft_tls_require_client_cert,
            });
        let node = if let Some(tls) = tls {
            crate::controller_raft::start_http_node_tls(
                model,
                id,
                bind,
                peers,
                Some(dir.clone()),
                config.control.raft_secret.clone(),
                config.control.raft_bootstrap,
                timing,
                tls,
            )
            .await?
        } else {
            crate::controller_raft::start_http_node(
                model,
                id,
                bind,
                peers,
                Some(dir.clone()),
                config.control.raft_secret.clone(),
                config.control.raft_bootstrap,
                timing,
            )
            .await?
        };
        tracing::info!(
            dir = %dir.display(),
            id,
            addr = %node.address,
            election_timeout_min_ms = timing.election_timeout_min_ms,
            election_timeout_max_ms = timing.election_timeout_max_ms,
            heartbeat_interval_ms = timing.heartbeat_interval_ms,
            timing_source = timing.source.as_str(),
            "controller raft enabled"
        );
        state.set_raft_timing(timing);
        state.set_raft_identity(id);
        state.set_raft(Arc::new(node.raft), node.store);
        let housekeeping = state.clone();
        tokio::spawn(async move {
            housekeeping.raft_housekeeping().await;
        });
        tokio::spawn(async move {
            let _ = node.server.await;
        });
    }
    if state.raft.is_none() {
        let expiry = state.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(std::time::Duration::from_secs(15));
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                tick.tick().await;
                expiry.expire_leases_local().await;
            }
        });
    }
    if config.control.iroh_port.is_some() {
        let state = state.clone();
        let config = config.clone();
        tokio::spawn(async move {
            if let Err(e) = run_iroh(state, config).await {
                tracing::warn!(error = %e, "controller iroh control stopped");
            }
        });
    }
    let bind = config
        .control
        .bind
        .clone()
        .unwrap_or_else(|| "127.0.0.1:7800".to_string());
    let addr: SocketAddr = bind
        .parse()
        .with_context(|| format!("control.bind {bind}"))?;
    tracing::info!(
        %addr,
        network = %state.network,
        tls = config.control.tls_cert.is_some(),
        "stellaris controller started"
    );
    let tls = config
        .control
        .tls_cert
        .clone()
        .zip(config.control.tls_key.clone());
    crate::serve::serve(addr, router(state), tls, "controller").await
}

async fn run_iroh(state: ControllerState, config: Config) -> anyhow::Result<()> {
    let state_dir = PathBuf::from(&config.node.state_dir);
    std::fs::create_dir_all(&state_dir)
        .with_context(|| format!("create controller state dir {}", state_dir.display()))?;
    let identity = crate::identity::load_or_create(&state_dir)?;
    let secret = SecretKey::from_bytes(&identity.secret);
    let mut builder = Endpoint::builder(presets::N0)
        .secret_key(secret)
        .alpns(vec![crate::control_wire::CONTROL_ALPN.to_vec()]);
    if let Some(port) = config.control.iroh_port {
        let addr = SocketAddr::from(([0, 0, 0, 0], port));
        builder = builder
            .bind_addr(addr)
            .with_context(|| format!("control bind {addr}"))?;
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
    let endpoint = builder
        .bind()
        .await
        .context("bind controller iroh endpoint")?;
    if !config.transport.disable_relay {
        endpoint.online().await;
    }
    tracing::info!(endpoint = %endpoint.id(), addr = ?endpoint.addr(), "controller iroh control ready");
    while let Some(incoming) = endpoint.accept().await {
        let Ok(accepting) = incoming.accept() else {
            continue;
        };
        let Ok(conn) = accepting.await else {
            continue;
        };
        let state = state.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_control_conn(state, conn).await {
                tracing::debug!(error = %e, "control connection ended");
            }
        });
    }
    Ok(())
}

async fn handle_control_conn(
    state: ControllerState,
    conn: iroh::endpoint::Connection,
) -> anyhow::Result<()> {
    while let Ok((mut send, mut recv)) = conn.accept_bi().await {
        let Some(request) = crate::control_wire::read_frame(&mut recv).await? else {
            break;
        };
        let remote = NodeId::new(*conn.remote_id().as_bytes());
        let response = dispatch_control(&state, remote, request).await;
        crate::control_wire::write_frame(&mut send, &response).await?;
        let _ = send.finish();
    }
    Ok(())
}

async fn dispatch_control(
    state: &ControllerState,
    remote: NodeId,
    request: crate::control_wire::Request,
) -> crate::control_wire::Response {
    use crate::control_wire::{Request, Response};
    match request {
        Request::Snapshot { node, secret } => {
            if !state.authorized_secret(secret.as_deref()) {
                return Response::Error {
                    code: 401,
                    message: "unauthorized".into(),
                };
            }
            let local = match node.as_deref().map(str::parse::<NodeId>) {
                Some(Ok(node)) => Some(node),
                Some(Err(e)) => {
                    return Response::Error {
                        code: 400,
                        message: format!("invalid node: {e}"),
                    };
                }
                None => None,
            };
            // Linearize before serving so an iroh member never reads a stale
            // snapshot from a follower (no-op when Raft is disabled).
            if let Err(error) = state.linearize().await {
                return Response::Error {
                    code: 503,
                    message: error,
                };
            }
            Response::Snapshot {
                snapshot: state.snapshot_current(local).await,
            }
        }
        Request::Lsa {
            lsa,
            signature,
            secret,
        } => {
            if !state.authorized_secret(secret.as_deref()) {
                return Response::Error {
                    code: 401,
                    message: "unauthorized".into(),
                };
            }
            if !crate::lsa_auth::verify(&lsa, &signature) {
                return Response::Error {
                    code: 403,
                    message: "LSA signature required or invalid".into(),
                };
            }
            match state.apply_lsa_current(lsa).await {
                Ok(changed) => {
                    let model = state.model_current().await;
                    Response::Ok {
                        changed,
                        generation: model.generation,
                        epoch: model.epoch,
                    }
                }
                Err((code, message)) => Response::Error { code, message },
            }
        }
        Request::Enroll {
            overlay_ip,
            auto,
            pool,
            zone,
            addrs,
            secret,
        } => {
            let _ = addrs;
            if !state.authorized_secret(secret.as_deref()) {
                return Response::Error {
                    code: 401,
                    message: "unauthorized".into(),
                };
            }
            match state.enroll(remote, overlay_ip, auto, pool, zone).await {
                Ok(EnrollOutcome::Credential(credential)) => Response::Credential {
                    credential: *credential,
                },
                Ok(EnrollOutcome::Pending) => Response::Pending {
                    node: remote.to_string(),
                },
                Ok(EnrollOutcome::Denied(reason)) => Response::Denied {
                    node: remote.to_string(),
                    reason,
                },
                Err((code, message)) => Response::Error { code, message },
            }
        }
        Request::Ack {
            node,
            generation,
            epoch,
            secret,
        } => {
            if !state.authorized_secret(secret.as_deref()) {
                return Response::Error {
                    code: 401,
                    message: "unauthorized".into(),
                };
            }
            let node = match node.parse::<NodeId>() {
                Ok(node) => node,
                Err(e) => {
                    return Response::Error {
                        code: 400,
                        message: format!("invalid node: {e}"),
                    };
                }
            };
            match state.record_ack_current(node, generation, epoch).await {
                Ok(()) => {
                    let model = state.model_current().await;
                    Response::Ok {
                        changed: true,
                        generation: model.generation,
                        epoch: model.epoch,
                    }
                }
                Err((code, message)) => Response::Error { code, message },
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    fn temp_state_dir() -> String {
        let dir = std::env::temp_dir().join(format!(
            "stellaris-controller-test-{}",
            uuid::Uuid::now_v7()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir.display().to_string()
    }

    fn state() -> ControllerState {
        let toml = format!(
            r#"
[node]
name = "ctrl"
role = "controller"
state_dir = "{}"

[network]
name = "demo"
cidr = "10.7.0.0/16"

[control]
bind = "127.0.0.1:0"
secret = "s3cret"

[[peers]]
name = "b"
endpoint_id = "0202020202020202020202020202020202020202020202020202020202020202"
overlay_ip = "10.7.0.2"

[[routes]]
prefix = "192.168.50.0/24"
via = "b"
"#,
            temp_state_dir()
        );
        ControllerState::from_config(&Config::from_toml(&toml).unwrap()).unwrap()
    }

    async fn json(response: axum::response::Response) -> serde_json::Value {
        let body = response.into_body().collect().await.unwrap().to_bytes();
        serde_json::from_slice(&body).unwrap()
    }

    #[tokio::test]
    async fn follower_cannot_sign_a_manifest() {
        let mut follower_state = state();
        let models = (0..3)
            .map(|_| ControllerModel::new(follower_state.network, follower_state.epoch))
            .collect();
        let (rafts, stores) = crate::controller_raft::start_cluster(models).await.unwrap();
        let mut leader = None;
        for _ in 0..50 {
            for (id, raft) in rafts.read().await.iter() {
                if raft.current_leader().await == Some(*id) {
                    leader = Some(*id);
                    break;
                }
            }
            if leader.is_some() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        let leader = leader.expect("leader");
        let follower = (1..=3).find(|id| *id != leader).unwrap();
        let raft = rafts.read().await.get(&follower).cloned().unwrap();
        follower_state.set_raft(Arc::new(raft), stores[(follower - 1) as usize].clone());
        let response = router(follower_state)
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/v1/manifest")
                    .header("x-stellaris-secret", "s3cret")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert!(response.headers().contains_key("x-stellaris-raft-leader"));
    }

    #[tokio::test]
    async fn raft_routes_replicate_with_deterministic_ids() {
        let mut leader_state = state();
        let models = (0..3)
            .map(|_| ControllerModel::new(leader_state.network, leader_state.epoch))
            .collect();
        let (rafts, stores) = crate::controller_raft::start_cluster(models).await.unwrap();
        let mut leader = None;
        for _ in 0..50 {
            for (id, raft) in rafts.read().await.iter() {
                if raft.current_leader().await == Some(*id) {
                    leader = Some(*id);
                    break;
                }
            }
            if leader.is_some() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        let leader = leader.expect("leader");
        let follower = (1..=3).find(|id| *id != leader).unwrap();
        let raft = rafts.read().await.get(&leader).cloned().unwrap();
        leader_state.set_raft(Arc::new(raft), stores[(leader - 1) as usize].clone());
        let app = router(leader_state);
        let via = NodeId::new([2u8; 32]);
        let body = json!({"prefix": "192.168.77.0/24", "via": via.to_string(), "metric": 3});
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/routes")
                    .header("x-stellaris-secret", "s3cret")
                    .header("content-type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        // All replicas must converge on the same route with the same id.
        let mut ids = Vec::new();
        for store in &stores {
            for _ in 0..50 {
                let model = store.model().await;
                let routes = model.route_entries();
                if let Some(route) = routes
                    .iter()
                    .find(|route| route.prefix.to_string() == "192.168.77.0/24")
                {
                    ids.push(route.id);
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            }
        }
        assert_eq!(ids.len(), 3, "route missing on a replica");
        assert!(ids.iter().all(|id| *id == ids[0]), "route ids diverged");

        // A follower cannot accept route writes.
        let follower_raft = rafts.read().await.get(&follower).cloned().unwrap();
        let mut follower_state = state();
        follower_state.set_raft(
            Arc::new(follower_raft),
            stores[(follower - 1) as usize].clone(),
        );
        let body = json!({"prefix": "192.168.78.0/24", "via": via.to_string(), "metric": 1});
        let response = router(follower_state)
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/routes")
                    .header("x-stellaris-secret", "s3cret")
                    .header("content-type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn follower_returns_leader_hint() {
        let mut state = state();
        let models = (0..3)
            .map(|_| ControllerModel::new(state.network, state.epoch))
            .collect();
        let (rafts, stores) = crate::controller_raft::start_cluster(models).await.unwrap();
        let mut leader = None;
        for _ in 0..50 {
            for (id, raft) in rafts.read().await.iter() {
                if raft.current_leader().await == Some(*id) {
                    leader = Some(*id);
                    break;
                }
            }
            if leader.is_some() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        let leader = leader.expect("leader");
        let follower = (1..=3).find(|id| *id != leader).unwrap();
        let raft = rafts.read().await.get(&follower).cloned().unwrap();
        state.set_raft(Arc::new(raft), stores[(follower - 1) as usize].clone());
        let app = router(state);
        let body = json!({
            "origin": NodeId::new([11u8; 32]).to_string(),
            "seq": 1,
            "zone": null,
            "links": [],
            "prefixes": [],
            "overlay_ip": "10.7.0.11",
            "addrs": []
        });
        let response = app
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri("/v1/lsa")
                    .header("x-stellaris-secret", "s3cret")
                    .header("content-type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(
            response
                .headers()
                .get("x-stellaris-raft-leader")
                .and_then(|v| v.to_str().ok()),
            Some(leader.to_string().as_str())
        );
        for raft in rafts.read().await.values() {
            let _ = raft.shutdown().await;
        }
    }

    #[tokio::test]
    async fn enrollment_is_queued_then_approved() {
        let dir = temp_state_dir();
        let toml = format!(
            r#"
[node]
name = "ctrl"
role = "controller"
state_dir = "{dir}"

[network]
name = "demo"
cidr = "10.7.0.0/16"

[control]
bind = "127.0.0.1:0"
secret = "s3cret"
raft_secret = "raft"
raft_dir = "{dir}/raft"
credential_ttl_secs = 600
"#
        );
        let config = Config::from_toml(&toml).unwrap();
        let mut state = ControllerState::from_config(&config).unwrap();
        state.set_signing_key([7u8; 32]);
        let network = state.network;
        let model = ControllerModel::new(network, state.epoch);
        let node = crate::controller_raft::start_single(model).await.unwrap();
        state.set_raft(Arc::new(node.raft), node.store);
        let app = router(state);
        let member = node_for([10u8; 32]);
        let payload = enroll_payload_bytes(
            &network.to_string(),
            &member.to_string(),
            Some("10.7.0.10"),
            None,
        );
        let signature = sign_ed25519(&[10u8; 32], &payload);
        let body = json!({
            "node_id": member.to_string(),
            "overlay_ip": "10.7.0.10",
            "signature": signature,
        });
        let enroll = || {
            app.clone().oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/enroll")
                    .header("x-stellaris-secret", "s3cret")
                    .header("content-type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
        };
        assert_eq!(enroll().await.unwrap().status(), StatusCode::ACCEPTED);
        // Approval grants prefixes explicitly and is admin-scoped.
        let approve = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/v1/admissions/{member}/approve"))
                    .header("x-stellaris-secret", "s3cret")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        json!({"prefixes": ["192.168.101.0/24"]}).to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(approve.status(), StatusCode::OK);
        let response = enroll().await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        let credential: SignedCredential =
            serde_json::from_value(value["credential"].clone()).unwrap();
        let issuer = NodeId::new(
            crate::credential::SignedCredential::sign(
                &[7u8; 32],
                MembershipCredential {
                    network: network.to_string(),
                    node: member,
                    overlay_ip: None,
                    prefixes: Vec::new(),
                    capabilities: Vec::new(),
                    revision: 0,
                    issued_at: 0,
                    not_after: 0,
                },
            )
            .issuer
            .into_bytes(),
        );
        let verified = credential
            .verify(
                &network,
                member,
                &[issuer],
                0,
                crate::credential::now_secs(),
            )
            .unwrap();
        assert_eq!(verified.prefixes, vec!["192.168.101.0/24".parse().unwrap()]);
    }

    #[tokio::test]
    async fn raft_backed_lsa_write_is_visible_in_snapshot() {
        let mut state = state();
        let model = crate::controller_model::ControllerModel::new(state.network, state.epoch);
        let node = crate::controller_raft::start_single(model).await.unwrap();
        state.set_raft(std::sync::Arc::new(node.raft), node.store);
        let app = router(state);
        let node_id = NodeId::new([7u8; 32]);
        let lsa = serde_json::json!({
            "origin": "0707070707070707070707070707070707070707070707070707070707070707",
            "seq": 1,
            "zone": null,
            "links": [],
            "prefixes": [{"prefix": "192.168.99.0/24", "metric": 0}],
            "overlay_ip": "10.7.0.7",
            "addrs": []
        });
        let response = app
            .clone()
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri("/v1/lsa")
                    .header("x-stellaris-secret", "s3cret")
                    .header("content-type", "application/json")
                    .body(Body::from(lsa.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let response = app
            .oneshot(
                axum::http::Request::builder()
                    .uri("/v1/snapshot?node=0707070707070707070707070707070707070707070707070707070707070707")
                    .header("x-stellaris-secret", "s3cret")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let json = json(response).await;
        assert!(
            json["members"]
                .as_array()
                .unwrap()
                .iter()
                .any(|m| m["node_id"] == node_id.to_string())
        );
    }

    #[tokio::test]
    async fn snapshot_requires_secret() {
        let app = router(state());
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/v1/snapshot")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/v1/snapshot")
                    .header("x-stellaris-secret", "s3cret")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let value = json(response).await;
        assert_eq!(value["routes"].as_array().unwrap().len(), 1);
        assert_eq!(value["routes"][0]["prefix"], "192.168.50.0/24");
    }

    #[tokio::test]
    async fn ack_epoch_and_persistence() {
        let dir = std::env::temp_dir().join(format!(
            "stellaris-controller-acks-{}",
            uuid::Uuid::now_v7()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let toml = format!(
            r#"
[node]
name = "ctrl"
role = "controller"
state_dir = "{}"

[network]
name = "demo"
cidr = "10.7.0.0/16"

[control]
bind = "127.0.0.1:0"
secret = "s3cret"
epoch = 7

[api]
bind = "127.0.0.1:0"
"#,
            dir.display()
        );
        let config = Config::from_toml(&toml).unwrap();
        let state = ControllerState::from_config(&config).unwrap();
        assert_eq!(state.epoch, 7);
        let app = router(state);
        let body = serde_json::json!({
            "node": "0101010101010101010101010101010101010101010101010101010101010101",
            "generation": 3,
            "epoch": 7
        });
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/ack")
                    .header("x-stellaris-secret", "s3cret")
                    .header("content-type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let reloaded = ControllerState::from_config(&config).unwrap();
        let acked = {
            let acks = reloaded.acks.read().unwrap();
            acks.get(
                &"0101010101010101010101010101010101010101010101010101010101010101"
                    .parse()
                    .unwrap(),
            )
            .copied()
        };
        assert_eq!(acked, Some(3));

        let app = router(reloaded);
        let body = serde_json::json!({
            "node": "0101010101010101010101010101010101010101010101010101010101010101",
            "generation": 4,
            "epoch": 6
        });
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/ack")
                    .header("x-stellaris-secret", "s3cret")
                    .header("content-type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::CONFLICT);
    }

    #[test]
    fn snapshot_is_signed() {
        let state = state();
        let snapshot = state.snapshot(None);
        let expected = snapshot_signature(
            "s3cret",
            &snapshot.network_id,
            snapshot.epoch,
            snapshot.generation,
            &snapshot.members,
            &snapshot.routes,
        );
        assert_eq!(snapshot.signature.as_deref(), Some(expected.as_str()));
        let mut tampered = snapshot.routes.clone();
        if let Some(route) = tampered.first_mut() {
            route.metric = route.metric.saturating_add(1);
        }
        let bad = snapshot_signature(
            "s3cret",
            &snapshot.network_id,
            snapshot.epoch,
            snapshot.generation,
            &snapshot.members,
            &tampered,
        );
        assert_ne!(expected, bad);
    }

    #[test]
    fn ed25519_snapshot_is_verifiable() {
        let mut state = state();
        state.set_signing_key([7u8; 32]);
        let snapshot = state.snapshot(None);
        let signer: NodeId = snapshot.signer.as_deref().unwrap().parse().unwrap();
        let payload = snapshot_payload_bytes(
            &snapshot.network_id,
            snapshot.epoch,
            snapshot.generation,
            &snapshot.members,
            &snapshot.routes,
        );
        verify_ed25519(
            signer,
            &payload,
            snapshot.ed25519_signature.as_deref().unwrap(),
        )
        .unwrap();
    }

    fn node_for(secret: [u8; 32]) -> NodeId {
        NodeId::new(SigningKey::from_bytes(&secret).verifying_key().to_bytes())
    }

    #[tokio::test]
    async fn pre_registered_member_receives_credential() {
        let member = node_for([1u8; 32]);
        let toml = format!(
            r#"
[node]
name = "ctrl"
role = "controller"
state_dir = "{}"

[network]
name = "demo"
cidr = "10.7.0.0/16"

[control]
secret = "s3cret"
credential_ttl_secs = 600

[[control.members]]
node_id = "{member}"
overlay_ip = "10.7.0.1"
prefixes = ["192.168.80.0/24"]
capabilities = ["member"]
"#,
            temp_state_dir()
        );
        let config = Config::from_toml(&toml).unwrap();
        let mut state = ControllerState::from_config(&config).unwrap();
        state.set_signing_key([7u8; 32]);
        let network = state.network;
        let app = router(state);
        let payload = enroll_payload_bytes(
            &network.to_string(),
            &member.to_string(),
            Some("10.7.0.1"),
            None,
        );
        let signature = sign_ed25519(&[1u8; 32], &payload);
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/enroll")
                    .header("x-stellaris-secret", "s3cret")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        json!({
                            "node_id": member.to_string(),
                            "overlay_ip": "10.7.0.1",
                            "signature": signature,
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        let credential: SignedCredential =
            serde_json::from_value(value["credential"].clone()).unwrap();
        let issuer = NodeId::new(
            SigningKey::from_bytes(&[7u8; 32])
                .verifying_key()
                .to_bytes(),
        );
        let verified = credential
            .verify(
                &network,
                member,
                &[issuer],
                0,
                crate::credential::now_secs(),
            )
            .unwrap();
        assert_eq!(verified.overlay_ip, Some("10.7.0.1".parse().unwrap()));
        assert_eq!(verified.prefixes, vec!["192.168.80.0/24".parse().unwrap()]);
    }

    #[test]
    fn member_grants_survive_restart() {
        let dir = temp_state_dir();
        let toml = format!(
            r#"
[node]
name = "ctrl"
role = "controller"
state_dir = "{}"

[network]
name = "demo"
cidr = "10.7.0.0/16"

[control]
secret = "s3cret"
epoch = 1
"#,
            dir
        );
        let config = Config::from_toml(&toml).unwrap();
        let state = ControllerState::from_config(&config).unwrap();
        let node = NodeId::new([1u8; 32]);
        let member = MemberRecord {
            overlay_ip: Some("10.7.0.1".parse().unwrap()),
            prefixes: vec!["192.168.80.0/24".into()],
            capabilities: vec!["member".into()],
        };
        state
            .model
            .write()
            .unwrap()
            .apply(ControllerCommand::UpsertMember {
                node,
                member: member.clone(),
            });
        state.grants.write().unwrap().insert(
            node,
            ControllerMemberConfig {
                node_id: node.to_string(),
                overlay_ip: member.overlay_ip,
                prefixes: member.prefixes.iter().map(|p| p.parse().unwrap()).collect(),
                capabilities: member.capabilities.clone(),
            },
        );
        state.persist_members();
        drop(state);

        let restarted = ControllerState::from_config(&config).unwrap();
        assert!(restarted.grants.read().unwrap().contains_key(&node));
        assert!(restarted.model().members.contains_key(&node));
    }

    #[tokio::test]
    async fn revoke_removes_member_lsa_and_manifest_entry() {
        let toml = format!(
            r#"
[node]
name = "ctrl"
role = "controller"
state_dir = "{}"

[network]
name = "demo"
cidr = "10.7.0.0/16"

[control]
secret = "s3cret"
epoch = 1

[[control.members]]
node_id = "0101010101010101010101010101010101010101010101010101010101010101"
overlay_ip = "10.7.0.1"
prefixes = ["192.168.70.0/24"]
"#,
            temp_state_dir()
        );
        let state = ControllerState::from_config(&Config::from_toml(&toml).unwrap()).unwrap();
        let app = router(state);
        let node = "0101010101010101010101010101010101010101010101010101010101010101";
        let lsa = serde_json::json!({
            "origin": node, "seq": 1, "zone": null, "links": [],
            "prefixes": [{"prefix":"10.7.0.1/32","metric":0}],
            "overlay_ip": "10.7.0.1", "addrs": []
        });
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/lsa")
                    .header("x-stellaris-secret", "s3cret")
                    .header("content-type", "application/json")
                    .body(Body::from(lsa.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let revoke = serde_json::json!({"node_id": node});
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/revoke")
                    .header("x-stellaris-secret", "s3cret")
                    .header("content-type", "application/json")
                    .body(Body::from(revoke.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/lsa")
                    .header("x-stellaris-secret", "s3cret")
                    .header("content-type", "application/json")
                    .body(Body::from(lsa.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[test]
    fn command_log_replays_deterministic_model() {
        let dir = temp_state_dir();
        let toml = format!(
            r#"
[node]
name = "ctrl"
role = "controller"
state_dir = "{}"

[network]
name = "demo"
cidr = "10.7.0.0/16"

[control]
secret = "s3cret"
epoch = 3

[[control.members]]
node_id = "0101010101010101010101010101010101010101010101010101010101010101"
overlay_ip = "10.7.0.1"
prefixes = ["192.168.92.0/24"]
"#,
            dir
        );
        let config = Config::from_toml(&toml).unwrap();
        let state = ControllerState::from_config(&config).unwrap();
        let node = NodeId::new([1u8; 32]);
        state
            .apply_lsa(Lsa {
                origin: node,
                seq: 1,
                zone: None,
                links: vec![],
                prefixes: vec![stellaris_linkstate::Prefix {
                    prefix: "192.168.92.0/24".parse().unwrap(),
                    metric: 0,
                }],
                overlay_ip: Some("10.7.0.1".parse().unwrap()),
                addrs: vec![],
            })
            .unwrap();
        state.record_ack(node, 3, Some(state.epoch)).unwrap();
        let before = state.model().snapshot_bytes();
        drop(state);

        let restarted = ControllerState::from_config(&config).unwrap();
        let after = restarted.model().snapshot_bytes();
        assert_eq!(before, after);
        assert!(restarted.model().lsas.contains_key(&node));
        assert!(restarted.model().members.contains_key(&node));
    }

    #[test]
    fn controller_lsas_survive_restart() {
        let dir = temp_state_dir();
        let toml = format!(
            r#"
[node]
name = "ctrl"
role = "controller"
state_dir = "{}"

[network]
name = "demo"
cidr = "10.7.0.0/16"

[control]
secret = "s3cret"
epoch = 1
"#,
            dir
        );
        let config = Config::from_toml(&toml).unwrap();
        let state = ControllerState::from_config(&config).unwrap();
        let node = NodeId::new([1u8; 32]);
        state
            .apply_lsa(Lsa {
                origin: node,
                seq: 1,
                zone: None,
                links: vec![],
                prefixes: vec![stellaris_linkstate::Prefix {
                    prefix: "192.168.90.0/24".parse().unwrap(),
                    metric: 0,
                }],
                overlay_ip: Some("10.7.0.1".parse().unwrap()),
                addrs: vec![],
            })
            .unwrap();
        drop(state);

        let restarted = ControllerState::from_config(&config).unwrap();
        let snapshot = restarted.snapshot(None);
        assert!(
            snapshot
                .members
                .iter()
                .any(|m| m.node_id == node.to_string())
        );
    }

    #[tokio::test]
    async fn raft_membership_endpoints_are_admin_only_and_validated() {
        let state = state();
        let app = router(state);
        let learner = serde_json::json!({"id": 4, "addr": "127.0.0.1:5999"});
        // No admin/member secret at all is unauthorized.
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/raft/learner")
                    .header("content-type", "application/json")
                    .body(Body::from(learner.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        // Authenticated but no Raft instance in this state.
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/raft/learner")
                    .header("x-stellaris-secret", "s3cret")
                    .header("content-type", "application/json")
                    .body(Body::from(learner.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        let bad = serde_json::json!({"id": 0, "addr": "nope"});
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/raft/membership")
                    .header("x-stellaris-secret", "s3cret")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::json!({"voters": [bad]}).to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn raft_learner_endpoint_accepts_a_dead_node_without_blocking() {
        let mut leader_state = state();
        let models = (0..3)
            .map(|_| ControllerModel::new(leader_state.network, leader_state.epoch))
            .collect();
        let (rafts, stores) = crate::controller_raft::start_cluster(models).await.unwrap();
        let mut leader = None;
        for _ in 0..50 {
            for (id, raft) in rafts.read().await.iter() {
                if raft.current_leader().await == Some(*id) {
                    leader = Some(*id);
                    break;
                }
            }
            if leader.is_some() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        let leader = leader.expect("leader");
        let raft = rafts.read().await.get(&leader).cloned().unwrap();
        leader_state.set_raft(
            Arc::new(raft.clone()),
            stores[(leader - 1) as usize].clone(),
        );
        // The leader must commit a log of its own term before membership edits.
        raft.client_write(ControllerCommand::SetEpoch { epoch: 1_000_000 })
            .await
            .unwrap();
        let response = router(leader_state)
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/raft/learner")
                    .header("x-stellaris-secret", "s3cret")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::json!({"id": 4, "addr": "127.0.0.1:5999"}).to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = response.status();
        if status != StatusCode::OK {
            eprintln!(
                "learner status={status} body={:?}",
                response
                    .into_body()
                    .collect()
                    .await
                    .map(|b| String::from_utf8_lossy(&b.to_bytes()).to_string())
            );
            panic!("learner endpoint failed");
        }
    }

    #[tokio::test]
    async fn enrollment_is_signed_admin_scoped_and_revocable() {
        let dir = temp_state_dir();
        let toml = format!(
            r#"
[node]
name = "ctrl"
role = "controller"
state_dir = "{dir}"

[network]
name = "admission"
cidr = "10.7.0.0/16"

[control]
bind = "127.0.0.1:0"
secret = "member-secret"
admin_secret = "admin-secret"
raft_secret = "raft"
raft_dir = "{dir}/raft"
credential_ttl_secs = 600
"#
        );
        let config = Config::from_toml(&toml).unwrap();
        let mut state = ControllerState::from_config(&config).unwrap();
        state.set_signing_key([7u8; 32]);
        let network = state.network;
        let model = ControllerModel::new(network, state.epoch);
        let node = crate::controller_raft::start_single(model).await.unwrap();
        state.set_raft(Arc::new(node.raft), node.store);
        let app = router(state);
        let member = node_for([10u8; 32]);
        let payload = enroll_payload_bytes(
            &network.to_string(),
            &member.to_string(),
            Some("10.7.0.10"),
            None,
        );
        let signature = sign_ed25519(&[10u8; 32], &payload);
        let enroll = |signature: String, secret: &'static str, overlay: &'static str| {
            let body = json!({
                "node_id": member.to_string(),
                "overlay_ip": overlay,
                "signature": signature,
            });
            app.clone().oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/enroll")
                    .header("x-stellaris-secret", secret)
                    .header("content-type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
        };
        // Enrollment always requires a signature by the node key.
        assert_eq!(
            enroll(String::new(), "member-secret", "10.7.0.10")
                .await
                .unwrap()
                .status(),
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            enroll(signature.clone(), "member-secret", "10.7.0.10")
                .await
                .unwrap()
                .status(),
            StatusCode::ACCEPTED
        );
        // The pending queue is admin-only.
        let admins = |secret: &'static str| {
            app.clone().oneshot(
                Request::builder()
                    .uri("/v1/admissions")
                    .header("x-stellaris-secret", secret)
                    .body(Body::empty())
                    .unwrap(),
            )
        };
        assert_eq!(
            admins("member-secret").await.unwrap().status(),
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            admins("admin-secret").await.unwrap().status(),
            StatusCode::OK
        );
        let approve = |secret: &'static str| {
            app.clone().oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/v1/admissions/{member}/approve"))
                    .header("x-stellaris-secret", secret)
                    .header("content-type", "application/json")
                    .body(Body::from(json!({"prefixes": []}).to_string()))
                    .unwrap(),
            )
        };
        assert_eq!(
            approve("member-secret").await.unwrap().status(),
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            approve("admin-secret").await.unwrap().status(),
            StatusCode::OK
        );
        assert_eq!(
            enroll(signature.clone(), "member-secret", "10.7.0.10")
                .await
                .unwrap()
                .status(),
            StatusCode::OK
        );
        // Denied nodes are tombstoned and cannot re-enroll.
        let other = node_for([11u8; 32]);
        let other_payload = enroll_payload_bytes(
            &network.to_string(),
            &other.to_string(),
            Some("10.7.0.11"),
            None,
        );
        let other_signature = sign_ed25519(&[11u8; 32], &other_payload);
        let other_body = json!({
            "node_id": other.to_string(),
            "overlay_ip": "10.7.0.11",
            "signature": other_signature,
        });
        let request = |uri: String, body: serde_json::Value| {
            app.clone().oneshot(
                Request::builder()
                    .method("POST")
                    .uri(uri)
                    .header("x-stellaris-secret", "admin-secret")
                    .header("content-type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
        };
        let enroll_other = app.clone().oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/enroll")
                .header("x-stellaris-secret", "member-secret")
                .header("content-type", "application/json")
                .body(Body::from(other_body.clone().to_string()))
                .unwrap(),
        );
        assert_eq!(enroll_other.await.unwrap().status(), StatusCode::ACCEPTED);
        assert_eq!(
            request(format!("/v1/admissions/{other}/deny"), json!({}))
                .await
                .unwrap()
                .status(),
            StatusCode::OK
        );
        let enroll_other_again = app.clone().oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/enroll")
                .header("x-stellaris-secret", "member-secret")
                .header("content-type", "application/json")
                .body(Body::from(other_body.to_string()))
                .unwrap(),
        );
        assert_eq!(
            enroll_other_again.await.unwrap().status(),
            StatusCode::FORBIDDEN
        );
    }

    #[tokio::test]
    async fn enrollment_rejects_a_signature_from_another_key() {
        let member = node_for([1u8; 32]);
        let toml = format!(
            r#"
[node]
name = "ctrl"
role = "controller"
state_dir = "{}"

[network]
name = "demo"
cidr = "10.7.0.0/16"

[control]
secret = "s3cret"

[[control.members]]
node_id = "{member}"
overlay_ip = "10.7.0.1"
"#,
            temp_state_dir()
        );
        let config = Config::from_toml(&toml).unwrap();
        let mut state = ControllerState::from_config(&config).unwrap();
        state.set_signing_key([7u8; 32]);
        let network = state.network;
        let app = router(state);
        let payload = enroll_payload_bytes(
            &network.to_string(),
            &member.to_string(),
            Some("10.7.0.1"),
            None,
        );
        let wrong = sign_ed25519(&[2u8; 32], &payload);
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/enroll")
                    .header("x-stellaris-secret", "s3cret")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        json!({
                            "node_id": member.to_string(),
                            "overlay_ip": "10.7.0.1",
                            "signature": wrong,
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn admin_secret_separates_member_and_admin_writes() {
        let toml = format!(
            r#"
[node]
name = "ctrl"
role = "controller"
state_dir = "{}"

[network]
name = "demo"
cidr = "10.7.0.0/16"

[control]
secret = "member-secret"
admin_secret = "admin-secret"

[[control.members]]
node_id = "0101010101010101010101010101010101010101010101010101010101010101"
overlay_ip = "10.7.0.2"
prefixes = ["192.168.60.0/24"]
"#,
            temp_state_dir()
        );
        let state = ControllerState::from_config(&Config::from_toml(&toml).unwrap()).unwrap();
        let app = router(state);
        let node = "0101010101010101010101010101010101010101010101010101010101010101";

        let revoke = serde_json::json!({"node_id": node});
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/revoke")
                    .header("x-stellaris-secret", "member-secret")
                    .header("content-type", "application/json")
                    .body(Body::from(revoke.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/revoke")
                    .header("x-stellaris-secret", "admin-secret")
                    .header("content-type", "application/json")
                    .body(Body::from(revoke.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let route = serde_json::json!({
            "prefix": "192.168.61.0/24",
            "via": node,
            "metric": 1
        });
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/routes")
                    .header("x-stellaris-secret", "member-secret")
                    .header("content-type", "application/json")
                    .body(Body::from(route.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/routes")
                    .header("x-stellaris-secret", "admin-secret")
                    .header("content-type", "application/json")
                    .body(Body::from(route.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[test]
    fn previous_controller_secret_is_accepted() {
        let dir = temp_state_dir();
        let toml = format!(
            r#"
[node]
name = "ctrl"
role = "controller"
state_dir = "{}"

[network]
name = "demo"
cidr = "10.7.0.0/16"

[control]
secret = "new"
previous_secrets = ["old"]
"#,
            dir
        );
        let state = ControllerState::from_config(&Config::from_toml(&toml).unwrap()).unwrap();
        assert!(state.authorized_secret(Some("old")));
        assert!(state.authorized_secret(Some("new")));
        assert!(!state.authorized_secret(Some("bad")));
    }

    #[test]
    fn nonleader_controller_rejects_writes() {
        let dir = temp_state_dir();
        let leader = NodeId::new(
            SigningKey::from_bytes(&[1u8; 32])
                .verifying_key()
                .to_bytes(),
        );
        let toml = format!(
            r#"
[node]
name = "ctrl"
role = "controller"
state_dir = "{}"

[network]
name = "demo"
cidr = "10.7.0.0/16"

[control]
secret = "s3cret"
leader_id = "{}"
"#,
            dir, leader
        );
        let mut state = ControllerState::from_config(&Config::from_toml(&toml).unwrap()).unwrap();
        state.set_signing_key([2u8; 32]);
        assert!(state.ensure_leader().is_err());
        let credential =
            state.issue_credential(NodeId::new([3u8; 32]), &MemberRecord::default(), 1);
        assert!(credential.is_ok(), "signing does not require leadership");
        state.set_signing_key([1u8; 32]);
        assert!(state.ensure_leader().is_ok());
    }

    #[test]
    fn model_shadow_tracks_lsa() {
        let state = state();
        let node = NodeId::new([1u8; 32]);
        state
            .apply_lsa(Lsa {
                origin: node,
                seq: 1,
                zone: None,
                links: vec![],
                prefixes: vec![stellaris_linkstate::Prefix {
                    prefix: "192.168.91.0/24".parse().unwrap(),
                    metric: 0,
                }],
                overlay_ip: Some("10.7.0.1".parse().unwrap()),
                addrs: vec![],
            })
            .unwrap();
        let model = state.model();
        assert!(model.lsas.contains_key(&node));
        assert!(model.generation >= 2);
    }

    #[test]
    fn unauthorized_lsa_is_rejected() {
        let toml = format!(
            r#"
[node]
name = "ctrl"
role = "controller"
state_dir = "{}"

[network]
name = "demo"
cidr = "10.7.0.0/16"

[control]
secret = "s3cret"
epoch = 1

[[control.members]]
node_id = "0101010101010101010101010101010101010101010101010101010101010101"
overlay_ip = "10.7.0.1"
prefixes = ["192.168.50.0/24"]
"#,
            temp_state_dir()
        );
        let state = ControllerState::from_config(&Config::from_toml(&toml).unwrap()).unwrap();
        let unknown = Lsa {
            origin: NodeId::new([2u8; 32]),
            seq: 1,
            zone: None,
            links: vec![],
            prefixes: vec![],
            overlay_ip: None,
            addrs: vec![],
        };
        assert!(state.apply_lsa(unknown).is_err());

        let allowed = Lsa {
            origin: NodeId::new([1u8; 32]),
            seq: 1,
            zone: None,
            links: vec![],
            prefixes: vec![stellaris_linkstate::Prefix {
                prefix: "192.168.50.0/24".parse().unwrap(),
                metric: 0,
            }],
            overlay_ip: Some("10.7.0.1".parse().unwrap()),
            addrs: vec![],
        };
        assert!(state.apply_lsa(allowed).unwrap());

        let bad_prefix = Lsa {
            origin: NodeId::new([1u8; 32]),
            seq: 2,
            zone: None,
            links: vec![],
            prefixes: vec![stellaris_linkstate::Prefix {
                prefix: "0.0.0.0/0".parse().unwrap(),
                metric: 0,
            }],
            overlay_ip: Some("10.7.0.1".parse().unwrap()),
            addrs: vec![],
        };
        assert!(state.apply_lsa(bad_prefix).is_err());
    }

    #[test]
    fn signed_membership_manifest_is_verifiable() {
        let mut state = state();
        state.set_signing_key([9u8; 32]);
        let manifest = state.manifest();
        let signer: NodeId = manifest.controller.as_deref().unwrap().parse().unwrap();
        let payload = manifest_payload_bytes(&manifest);
        verify_ed25519(signer, &payload, manifest.signature.as_deref().unwrap()).unwrap();
        assert!(manifest.expires_at > manifest.issued_at);
    }

    #[test]
    fn manifest_agreement_ignores_controller_identity() {
        let mut a = state();
        a.set_signing_key([1u8; 32]);
        let mut b = state();
        b.set_signing_key([2u8; 32]);
        let ma = a.manifest();
        let mb = b.manifest();
        assert_ne!(ma.controller, mb.controller);
        assert_eq!(manifest_agreement_bytes(&ma), manifest_agreement_bytes(&mb));
    }

    #[test]
    fn link_state_snapshot_computes_routes() {
        let state = state();
        let a = stellaris_types::NodeId::new([1u8; 32]);
        let b = stellaris_types::NodeId::new([2u8; 32]);
        state
            .apply_lsa(Lsa {
                origin: a,
                seq: 1,
                zone: Some("az-a".into()),
                links: vec![stellaris_linkstate::Link {
                    to: b,
                    metric: 1,
                    zone: Some("az-a".into()),
                }],
                prefixes: vec![],
                overlay_ip: None,
                addrs: Vec::new(),
            })
            .unwrap();
        state
            .apply_lsa(Lsa {
                origin: b,
                seq: 1,
                zone: Some("az-a".into()),
                links: vec![],
                prefixes: vec![stellaris_linkstate::Prefix {
                    prefix: "192.168.50.0/24".parse().unwrap(),
                    metric: 0,
                }],
                overlay_ip: None,
                addrs: Vec::new(),
            })
            .unwrap();
        let snapshot = state.snapshot(Some(a));
        let route = snapshot
            .routes
            .iter()
            .find(|r| {
                r.prefix.to_string() == "192.168.50.0/24" && r.source == RouteSource::LinkState
            })
            .expect("link-state route");
        assert_eq!(route.next_hop, b);
        assert_eq!(route.metric, 1);
    }

    #[tokio::test]
    async fn add_route_bumps_generation() {
        let app = router(state());
        let body = serde_json::json!({
            "prefix": "10.9.0.0/16",
            "via": "0202020202020202020202020202020202020202020202020202020202020202",
            "metric": 7
        });
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/routes")
                    .header("x-stellaris-secret", "s3cret")
                    .header("content-type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let value = json(response).await;
        assert_eq!(value["generation"], 2);
        assert_eq!(value["route"]["prefix"], "10.9.0.0/16");
    }

    fn ipam_config(state_dir: &str, pools: &str, members: &str) -> Config {
        let toml = format!(
            r#"
[node]
name = "ctrl"
role = "controller"
state_dir = "{}"

[network]
name = "ipam-demo"
cidr = "10.20.0.0/16"

[control]
secret = "s3cret"
admin_secret = "admin-secret"

[control.ipam]
{pools}
{members}
"#,
            state_dir
        );
        Config::from_toml(&toml).unwrap()
    }

    async fn post_enroll(
        app: &Router,
        network: &NetworkId,
        secret: [u8; 32],
        auto: bool,
        overlay: Option<&str>,
    ) -> (StatusCode, serde_json::Value) {
        let node = node_for(secret);
        let payload = enroll_payload_bytes(&network.to_string(), &node.to_string(), overlay, None);
        let signature = sign_ed25519(&secret, &payload);
        let body = json!({
            "node_id": node.to_string(),
            "overlay_ip": overlay,
            "auto": auto,
            "signature": signature,
        });
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/enroll")
                    .header("x-stellaris-secret", "s3cret")
                    .header("content-type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        (
            status,
            serde_json::from_slice(&bytes).unwrap_or(json!(null)),
        )
    }

    async fn get_json(app: &Router, uri: &str) -> (StatusCode, serde_json::Value) {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(uri)
                    .header("x-stellaris-secret", "admin-secret")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        (
            status,
            serde_json::from_slice(&bytes).unwrap_or(json!(null)),
        )
    }

    #[test]
    fn ipam_pre_registered_member_gets_a_deterministic_address() {
        let dir = temp_state_dir();
        let config = ipam_config(
            &dir,
            r#"[[control.ipam.pools]]
id = "p"
cidr = "10.20.0.0/24"
lease_secs = 600"#,
            r#"[[control.members]]
node_id = "0101010101010101010101010101010101010101010101010101010101010101""#,
        );
        let state = ControllerState::from_config(&config).unwrap();
        let model = state.model();
        let node = NodeId::new([1u8; 32]);
        assert_eq!(
            model.members[&node].overlay_ip,
            Some("10.20.0.1".parse().unwrap())
        );
        assert_eq!(model.leases[&"10.20.0.1".parse().unwrap()].node, node);
    }

    #[tokio::test]
    async fn ipam_auto_enrollment_allocates_and_issues_credentials() {
        let dir = temp_state_dir();
        let config = ipam_config(
            &dir,
            r#"[[control.ipam.pools]]
id = "p"
cidr = "10.20.0.0/24"
lease_secs = 600
quarantine_secs = 30"#,
            "",
        );
        let mut state = ControllerState::from_config(&config).unwrap();
        state.set_signing_key([7u8; 32]);
        let network = state.network;
        let app = router(state);
        let a = [1u8; 32];
        let b = [2u8; 32];
        assert_eq!(
            post_enroll(&app, &network, a, true, None).await.0,
            StatusCode::ACCEPTED
        );
        assert_eq!(
            post_enroll(&app, &network, b, true, None).await.0,
            StatusCode::ACCEPTED
        );
        let (status, pending) = get_json(&app, "/v1/admissions").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(pending["pending"].as_array().unwrap().len(), 2);

        for (index, secret) in [a, b].into_iter().enumerate() {
            let node = node_for(secret);
            let approve = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri(format!("/v1/admissions/{node}/approve"))
                        .header("x-stellaris-secret", "admin-secret")
                        .header("content-type", "application/json")
                        .body(Body::from(json!({"prefixes": []}).to_string()))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(approve.status(), StatusCode::OK);
            let (status, body) = post_enroll(&app, &network, secret, true, None).await;
            assert_eq!(status, StatusCode::OK);
            let credential: SignedCredential =
                serde_json::from_value(body["credential"].clone()).unwrap();
            let expected: std::net::IpAddr = format!("10.20.0.{}", index + 1).parse().unwrap();
            assert_eq!(credential.credential.overlay_ip, Some(expected));
        }

        let (status, leases) = get_json(&app, "/v1/ipam/leases").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(leases["leases"].as_array().unwrap().len(), 2);

        // Pool CRUD is admin-scoped and validates membership in the CIDR.
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/ipam/pools")
                    .header("x-stellaris-secret", "member-only")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        json!({"id": "x", "cidr": "10.20.1.0/24"}).to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert!(response.status().is_client_error());
        let (status, pools) = get_json(&app, "/v1/ipam/pools").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(pools["pools"].as_array().unwrap().len(), 1);
        let (status, _) = get_json(&app, "/v1/ipam/pools").await;
        assert_eq!(status, StatusCode::OK);
    }

    #[tokio::test]
    async fn ipam_rejects_out_of_pool_and_duplicate_static_overlays() {
        let dir = temp_state_dir();
        let config = ipam_config(
            &dir,
            r#"[[control.ipam.pools]]
id = "p"
cidr = "10.20.0.0/24"
lease_secs = 600"#,
            "",
        );
        let mut state = ControllerState::from_config(&config).unwrap();
        state.set_signing_key([7u8; 32]);
        let network = state.network;
        let app = router(state);
        assert_eq!(
            post_enroll(&app, &network, [3u8; 32], false, Some("10.99.0.5"))
                .await
                .0,
            StatusCode::CONFLICT
        );
        assert_eq!(
            post_enroll(&app, &network, [4u8; 32], false, Some("10.20.0.5"))
                .await
                .0,
            StatusCode::ACCEPTED
        );
        let node = node_for([4u8; 32]);
        let approve = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/v1/admissions/{node}/approve"))
                    .header("x-stellaris-secret", "admin-secret")
                    .header("content-type", "application/json")
                    .body(Body::from(json!({"prefixes": []}).to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(approve.status(), StatusCode::OK);
        // Another node cannot claim the same static address.
        assert_eq!(
            post_enroll(&app, &network, [5u8; 32], false, Some("10.20.0.5"))
                .await
                .0,
            StatusCode::CONFLICT
        );
    }

    #[tokio::test]
    async fn health_ready_and_metrics_endpoints() {
        let app = router(state());
        for uri in ["/healthz", "/readyz"] {
            let response = app
                .clone()
                .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK, "{uri}");
        }
        let unauthorized = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/metrics")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(unauthorized.status(), StatusCode::UNAUTHORIZED);
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/metrics")
                    .header("x-stellaris-secret", "s3cret")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let text = String::from_utf8(body.to_vec()).unwrap();
        for needle in [
            "stellaris_controller_up 1",
            "stellaris_controller_generation",
            "stellaris_controller_members",
            "stellaris_controller_raft_enabled",
        ] {
            assert!(text.contains(needle), "missing {needle}:\n{text}");
        }
    }

    #[tokio::test]
    async fn ipam_reassign_moves_the_member_and_rejects_out_of_pool() {
        let dir = temp_state_dir();
        let config = ipam_config(
            &dir,
            r#"[[control.ipam.pools]]
id = "p"
cidr = "10.20.0.0/24"
lease_secs = 600
quarantine_secs = 30"#,
            r#"[[control.members]]
node_id = "0101010101010101010101010101010101010101010101010101010101010101""#,
        );
        let state = ControllerState::from_config(&config).unwrap();
        let node = NodeId::new([1u8; 32]);
        let app = router(state);
        let body = json!({"ip": "10.20.0.9"}).to_string();
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/v1/ipam/leases/{node}/reassign"))
                    .header("x-stellaris-secret", "admin-secret")
                    .header("content-type", "application/json")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = response.status();
        let raw = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        assert_eq!(
            status,
            StatusCode::OK,
            "body={}",
            String::from_utf8_lossy(&raw)
        );
        let body: serde_json::Value = serde_json::from_slice(&raw).unwrap();
        assert_eq!(body["old"], "10.20.0.1");
        assert_eq!(body["new"], "10.20.0.9");
        // Reassigning the current address is a no-op and must not report OK.
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/v1/ipam/leases/{node}/reassign"))
                    .header("x-stellaris-secret", "admin-secret")
                    .header("content-type", "application/json")
                    .body(Body::from(json!({"ip": "10.20.0.9"}).to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::CONFLICT);
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/v1/model")
                    .header("x-stellaris-secret", "s3cret")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let model = json(response).await;
        assert_eq!(
            model["members"][node.to_string()]["overlay_ip"],
            "10.20.0.9"
        );
        // Out-of-pool targets are rejected and leave the member unchanged.
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/v1/ipam/leases/{node}/reassign"))
                    .header("x-stellaris-secret", "admin-secret")
                    .header("content-type", "application/json")
                    .body(Body::from(json!({"ip": "10.99.0.1"}).to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::CONFLICT);
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/v1/model")
                    .header("x-stellaris-secret", "s3cret")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let model = json(response).await;
        assert_eq!(
            model["members"][node.to_string()]["overlay_ip"],
            "10.20.0.9"
        );
    }
}
