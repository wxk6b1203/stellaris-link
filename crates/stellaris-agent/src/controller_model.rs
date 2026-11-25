//! Deterministic controller state model (openraft H0).
//!
//! This module is intentionally independent of wall-clock time and the
//! existing HTTP controller. The same command log must produce identical
//! state on every replica; openraft can later drive `apply()`.

use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use stellaris_linkstate::{LinkStateDb, Lsa};
use stellaris_types::{AddressPool, NetworkId, NodeId, RouteEntry};

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct MemberRecord {
    pub overlay_ip: Option<IpAddr>,
    pub prefixes: Vec<String>,
    pub capabilities: Vec<String>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct PendingAdmission {
    /// Requested address; `None` means the controller allocates one.
    #[serde(default)]
    pub overlay_ip: Option<IpAddr>,
    #[serde(default)]
    pub auto: bool,
    #[serde(default)]
    pub pool: Option<String>,
    #[serde(default)]
    pub zone: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Lease {
    pub node: NodeId,
    pub ip: IpAddr,
    pub pool: String,
    pub issued_at: u64,
    /// 0 for a reserved address, otherwise unix seconds.
    pub expires_at: u64,
    pub reserved: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Reservation {
    pub node: NodeId,
    pub ip: IpAddr,
    pub pool: String,
    #[serde(default)]
    pub note: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct AckRecord {
    pub generation: u64,
    pub epoch: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum ControllerCommand {
    SetEpoch {
        epoch: u64,
    },
    ApplyLsa {
        lsa: Lsa,
    },
    ExpireLsa {
        origin: NodeId,
        up_to_seq: u64,
    },
    /// Batch form used by the leader housekeeping task: one Raft write can
    /// retire many stale LSAs instead of one entry per origin.
    ExpireLsas {
        entries: Vec<(NodeId, u64)>,
    },
    /// Signed join request waiting for an administrator decision.
    RequestAdmission {
        node: NodeId,
        #[serde(default)]
        overlay_ip: Option<IpAddr>,
        #[serde(default)]
        auto: bool,
        #[serde(default)]
        pool: Option<String>,
        #[serde(default)]
        zone: Option<String>,
    },
    /// Administrator approval: grants exactly the supplied member record.
    /// When `auto` is set and `member.overlay_ip` is `None`, `apply` allocates
    /// a free address from the pools (deterministically across replicas).
    ApproveAdmission {
        node: NodeId,
        member: MemberRecord,
        #[serde(default)]
        auto: bool,
        #[serde(default)]
        pool: Option<String>,
        #[serde(default)]
        zone: Option<String>,
        #[serde(default)]
        now: u64,
    },
    DenyAdmission {
        node: NodeId,
        #[serde(default)]
        now: u64,
    },
    UpsertMember {
        node: NodeId,
        member: MemberRecord,
    },
    CreatePool {
        pool: AddressPool,
    },
    UpdatePool {
        pool: AddressPool,
    },
    DeletePool {
        id: String,
        force: bool,
        now: u64,
    },
    ReserveAddress {
        node: NodeId,
        ip: IpAddr,
        pool: Option<String>,
        note: Option<String>,
    },
    ReleaseAddress {
        node: NodeId,
        now: u64,
    },
    /// Move a member to a new overlay address without restarting its agent.
    /// `ip = None` allocates the next free address (excluding the old one).
    ReassignAddress {
        node: NodeId,
        #[serde(default)]
        ip: Option<IpAddr>,
        #[serde(default)]
        pool: Option<String>,
        #[serde(default)]
        zone: Option<String>,
        #[serde(default)]
        now: u64,
    },
    RenewLease {
        node: NodeId,
        now: u64,
    },
    ExpireLeases {
        now: u64,
    },
    RevokeMember {
        node: NodeId,
        #[serde(default)]
        now: u64,
    },
    Ack {
        node: NodeId,
        generation: u64,
        epoch: u64,
    },
    /// Add or update a network-scope controller route.
    UpsertRoute {
        prefix: String,
        via: NodeId,
        metric: u32,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ControllerModel {
    pub network: NetworkId,
    pub epoch: u64,
    pub generation: u64,
    pub lsas: BTreeMap<NodeId, Lsa>,
    pub members: BTreeMap<NodeId, MemberRecord>,
    pub acks: BTreeMap<NodeId, AckRecord>,
    /// Monotonic per-node credential revision. Bumped on every authorization
    /// change so a replayed old credential sorts below the current revision.
    #[serde(default)]
    pub member_revisions: BTreeMap<NodeId, u64>,
    /// Nodes explicitly revoked/denied; they cannot re-enroll until an
    /// administrator admits them again.
    #[serde(default)]
    pub revoked: BTreeSet<NodeId>,
    #[serde(default)]
    pub pools: BTreeMap<String, AddressPool>,
    /// address -> lease (a single index enforces uniqueness).
    #[serde(default)]
    pub leases: BTreeMap<IpAddr, Lease>,
    #[serde(default)]
    pub node_leases: BTreeMap<NodeId, IpAddr>,
    #[serde(default)]
    pub reservations: BTreeMap<NodeId, Reservation>,
    /// Released addresses stay unusable until this timestamp.
    #[serde(default)]
    pub quarantine: BTreeMap<IpAddr, u64>,
    /// Controller-pushed routes: prefix -> next hop -> metric.
    #[serde(default)]
    pub routes: BTreeMap<String, BTreeMap<NodeId, u32>>,
    /// Signed join requests awaiting an admin decision.
    #[serde(default)]
    pub pending_admissions: BTreeMap<NodeId, PendingAdmission>,
}

impl ControllerModel {
    pub fn new(network: NetworkId, epoch: u64) -> Self {
        Self {
            network,
            epoch,
            generation: 1,
            lsas: BTreeMap::new(),
            members: BTreeMap::new(),
            acks: BTreeMap::new(),
            member_revisions: BTreeMap::new(),
            revoked: BTreeSet::new(),
            pools: BTreeMap::new(),
            leases: BTreeMap::new(),
            node_leases: BTreeMap::new(),
            reservations: BTreeMap::new(),
            quarantine: BTreeMap::new(),
            routes: BTreeMap::new(),
            pending_admissions: BTreeMap::new(),
        }
    }

    /// Apply a command deterministically. Returns true if state changed.
    pub fn apply(&mut self, command: ControllerCommand) -> bool {
        let changed = match command {
            ControllerCommand::SetEpoch { epoch } => {
                if epoch > self.epoch {
                    self.epoch = epoch;
                    true
                } else {
                    false
                }
            }
            ControllerCommand::ApplyLsa { lsa } => {
                let newer = self
                    .lsas
                    .get(&lsa.origin)
                    .is_none_or(|current| lsa.seq > current.seq);
                if newer {
                    self.lsas.insert(lsa.origin, lsa);
                }
                newer
            }
            ControllerCommand::ExpireLsas { entries } => {
                let mut removed = false;
                for (origin, up_to_seq) in entries {
                    if self
                        .lsas
                        .get(&origin)
                        .is_some_and(|lsa| lsa.seq <= up_to_seq)
                    {
                        self.lsas.remove(&origin);
                        removed = true;
                    }
                }
                removed
            }
            ControllerCommand::ExpireLsa { origin, up_to_seq } => {
                if self
                    .lsas
                    .get(&origin)
                    .is_some_and(|lsa| lsa.seq <= up_to_seq)
                {
                    self.lsas.remove(&origin);
                    true
                } else {
                    false
                }
            }
            ControllerCommand::UpsertMember { node, member } => {
                self.bump_revision(node);
                self.members.insert(node, member);
                self.revoked.remove(&node);
                true
            }
            ControllerCommand::RevokeMember { node, now } => {
                let removed = self.members.remove(&node).is_some();
                let lsa_removed = self.lsas.remove(&node).is_some();
                self.release_lease(node, now);
                self.revoked.insert(node);
                self.bump_revision(node);
                if removed || lsa_removed {
                    // A revocation invalidates manifests signed under the old
                    // epoch; bump it so stale manifest copies are fenced.
                    self.epoch = self.epoch.saturating_add(1);
                }
                true
            }
            ControllerCommand::Ack {
                node,
                generation,
                epoch,
            } => {
                let record = AckRecord { generation, epoch };
                let changed = self.acks.get(&node) != Some(&record);
                if changed {
                    self.acks.insert(node, record);
                }
                changed
            }
            ControllerCommand::RequestAdmission {
                node,
                overlay_ip,
                auto,
                pool,
                zone,
            } => {
                if self.members.contains_key(&node)
                    || self.pending_admissions.contains_key(&node)
                    || self.revoked.contains(&node)
                {
                    false
                } else {
                    self.pending_admissions.insert(
                        node,
                        PendingAdmission {
                            overlay_ip,
                            auto,
                            pool,
                            zone,
                        },
                    );
                    true
                }
            }
            ControllerCommand::ApproveAdmission {
                node,
                mut member,
                auto,
                pool,
                zone,
                now,
            } => {
                if member.overlay_ip.is_none() {
                    if !auto {
                        return false;
                    }
                    match self.allocate_address(node, pool.as_deref(), zone.as_deref(), now) {
                        Ok((ip, pool_id, _, reserved)) => {
                            member.overlay_ip = Some(ip);
                            self.assign_lease(node, ip, &pool_id, now, reserved);
                        }
                        Err(_) => return false,
                    }
                } else if let Some(ip) = member.overlay_ip {
                    if self.overlay_taken(ip, node) {
                        return false;
                    }
                    if let Some(old) = self.node_leases.get(&node).copied()
                        && old != ip
                    {
                        self.release_lease(node, now);
                    }
                    let pool_id = self
                        .pool_of(ip)
                        .map(|pool| pool.id.clone())
                        .or_else(|| self.leases.get(&ip).map(|lease| lease.pool.clone()))
                        .unwrap_or_default();
                    let reserved = self.reservations.get(&node).map(|r| r.ip) == Some(ip);
                    if !pool_id.is_empty() {
                        self.assign_lease(node, ip, &pool_id, now, reserved);
                    }
                }
                self.bump_revision(node);
                self.members.insert(node, member);
                self.revoked.remove(&node);
                self.pending_admissions.remove(&node);
                true
            }
            ControllerCommand::DenyAdmission { node, now } => {
                let changed = self.pending_admissions.remove(&node).is_some();
                self.release_lease(node, now);
                self.revoked.insert(node);
                self.bump_revision(node);
                changed
            }
            ControllerCommand::CreatePool { pool } => {
                if pool.id.trim().is_empty() || self.pools.contains_key(&pool.id) {
                    false
                } else {
                    self.pools.insert(pool.id.clone(), pool);
                    true
                }
            }
            ControllerCommand::UpdatePool { pool } => {
                if self.pools.contains_key(&pool.id) {
                    self.pools.insert(pool.id.clone(), pool);
                    true
                } else {
                    false
                }
            }
            ControllerCommand::DeletePool { id, force, now } => {
                if !self.pools.contains_key(&id) {
                    return false;
                }
                let has_leases = self.leases.values().any(|lease| lease.pool == id);
                if has_leases && !force {
                    return false;
                }
                self.pools.remove(&id);
                self.release_pool(&id, now);
                true
            }
            ControllerCommand::ReserveAddress {
                node,
                ip,
                pool,
                note,
            } => {
                let Some(pool) = pool.or_else(|| self.pool_of(ip).map(|p| p.id.clone())) else {
                    return false;
                };
                if !self.pools.contains_key(&pool) || self.overlay_taken(ip, node) {
                    return false;
                }
                self.release_lease(node, 0);
                self.reservations.insert(
                    node,
                    Reservation {
                        node,
                        ip,
                        pool: pool.clone(),
                        note,
                    },
                );
                self.node_leases.insert(node, ip);
                self.leases.insert(
                    ip,
                    Lease {
                        node,
                        ip,
                        pool,
                        issued_at: 0,
                        expires_at: 0,
                        reserved: true,
                    },
                );
                true
            }
            ControllerCommand::ReleaseAddress { node, now } => {
                let had =
                    self.node_leases.contains_key(&node) || self.reservations.contains_key(&node);
                self.release_lease(node, now);
                had
            }
            ControllerCommand::ReassignAddress {
                node,
                ip,
                pool,
                zone,
                now,
            } => {
                let Some(member) = self.members.get(&node).cloned() else {
                    return false;
                };
                let old = member.overlay_ip;
                let (target, pool_id) = match ip {
                    Some(ip) => match self.validate_reassign(node, ip, pool.as_deref(), now) {
                        Ok(pool) => (ip, pool),
                        Err(_) => return false,
                    },
                    None => match self.allocate_for_reassign(
                        node,
                        pool.as_deref(),
                        zone.as_deref(),
                        now,
                        old,
                    ) {
                        Ok(allocation) => allocation,
                        Err(_) => return false,
                    },
                };
                if old == Some(target) {
                    return false;
                }
                self.release_lease(node, now);
                self.assign_lease(node, target, &pool_id, now, false);
                if let Some(member) = self.members.get_mut(&node) {
                    member.overlay_ip = Some(target);
                }
                self.bump_revision(node);
                true
            }
            ControllerCommand::RenewLease { node, now } => {
                let Some(ip) = self.node_leases.get(&node).copied() else {
                    return false;
                };
                let Some(lease) = self.leases.get(&ip).cloned() else {
                    return false;
                };
                if lease.reserved || lease.expires_at == 0 {
                    return false;
                }
                let lease_secs = self
                    .pools
                    .get(&lease.pool)
                    .map(|pool| pool.lease_secs)
                    .unwrap_or(3600);
                let mut renewed = lease;
                renewed.expires_at = now.saturating_add(lease_secs);
                self.leases.insert(ip, renewed);
                true
            }
            ControllerCommand::ExpireLeases { now } => {
                let expired: Vec<IpAddr> = self
                    .leases
                    .iter()
                    .filter(|(_, lease)| lease.expires_at > 0 && lease.expires_at <= now)
                    .map(|(ip, _)| *ip)
                    .collect();
                let changed = !expired.is_empty();
                for ip in expired {
                    if let Some(lease) = self.leases.remove(&ip) {
                        self.node_leases.remove(&lease.node);
                        self.members.remove(&lease.node);
                        self.lsas.remove(&lease.node);
                        self.bump_revision(lease.node);
                        let quarantine = self
                            .pools
                            .get(&lease.pool)
                            .map(|pool| pool.quarantine_secs)
                            .unwrap_or(60);
                        if quarantine > 0 {
                            self.quarantine.insert(ip, now.saturating_add(quarantine));
                        }
                    }
                }
                changed
            }
            ControllerCommand::UpsertRoute {
                prefix,
                via,
                metric,
            } => {
                if prefix.parse::<ipnet::IpNet>().is_err() {
                    false
                } else {
                    let entry = self.routes.entry(prefix).or_default();
                    let changed = entry.get(&via) != Some(&metric);
                    if changed {
                        entry.insert(via, metric);
                    }
                    changed
                }
            }
        };
        if changed {
            self.generation = self.generation.saturating_add(1);
        }
        changed
    }

    pub fn apply_all(&mut self, commands: impl IntoIterator<Item = ControllerCommand>) {
        for command in commands {
            self.apply(command);
        }
    }

    pub fn pool_of(&self, ip: IpAddr) -> Option<&AddressPool> {
        self.pools.values().find(|pool| pool.cidr.contains(&ip))
    }

    /// True when another node already owns or reserved `ip`.
    pub fn overlay_taken(&self, ip: IpAddr, node: NodeId) -> bool {
        self.leases.get(&ip).is_some_and(|lease| lease.node != node)
            || self
                .members
                .iter()
                .any(|(other, member)| *other != node && member.overlay_ip == Some(ip))
            || self
                .reservations
                .iter()
                .any(|(other, reservation)| *other != node && reservation.ip == ip)
    }

    fn assign_lease(&mut self, node: NodeId, ip: IpAddr, pool: &str, now: u64, reserved: bool) {
        let lease_secs = self
            .pools
            .get(pool)
            .map(|pool| pool.lease_secs)
            .unwrap_or(3600);
        // `now == 0` marks config-time pre-registration: the lease never
        // expires until an administrator changes it.
        let expires_at = if reserved || now == 0 {
            0
        } else {
            now.saturating_add(lease_secs)
        };
        self.quarantine.remove(&ip);
        self.node_leases.insert(node, ip);
        self.leases.insert(
            ip,
            Lease {
                node,
                ip,
                pool: pool.to_string(),
                issued_at: now,
                expires_at,
                reserved,
            },
        );
    }

    fn release_lease(&mut self, node: NodeId, now: u64) {
        self.reservations.remove(&node);
        let Some(ip) = self.node_leases.remove(&node) else {
            return;
        };
        let lease = self.leases.remove(&ip);
        let quarantine = lease
            .as_ref()
            .and_then(|lease| self.pools.get(&lease.pool))
            .map(|pool| pool.quarantine_secs)
            .unwrap_or(60);
        if quarantine > 0 {
            self.quarantine.insert(ip, now.saturating_add(quarantine));
        }
    }

    fn release_pool(&mut self, id: &str, now: u64) {
        let ips: Vec<IpAddr> = self
            .leases
            .iter()
            .filter(|(_, lease)| lease.pool == id)
            .map(|(ip, _)| *ip)
            .collect();
        for ip in ips {
            if let Some(lease) = self.leases.remove(&ip) {
                self.node_leases.remove(&lease.node);
                let quarantine = self
                    .pools
                    .get(id)
                    .map(|pool| pool.quarantine_secs)
                    .unwrap_or(60);
                if quarantine > 0 {
                    self.quarantine.insert(ip, now.saturating_add(quarantine));
                }
            }
        }
        self.reservations
            .retain(|_, reservation| reservation.pool != id);
    }

    /// Deterministically allocate or reuse an address for `node`.
    ///
    /// Returns `(ip, pool_id, expires_at, reserved)`. The algorithm only reads
    /// model state plus command fields, so every Raft replica computes the same
    /// answer.
    pub fn allocate_address(
        &self,
        node: NodeId,
        pool_hint: Option<&str>,
        zone: Option<&str>,
        now: u64,
    ) -> Result<(IpAddr, String, u64, bool), String> {
        if let Some(reservation) = self.reservations.get(&node) {
            return Ok((reservation.ip, reservation.pool.clone(), 0, true));
        }
        if let Some(ip) = self.node_leases.get(&node).copied()
            && let Some(lease) = self.leases.get(&ip)
            && (lease.reserved || lease.expires_at == 0 || lease.expires_at > now)
        {
            return Ok((ip, lease.pool.clone(), lease.expires_at, lease.reserved));
        }
        let mut pools: Vec<&AddressPool> = self
            .pools
            .values()
            .filter(|pool| pool_hint.is_none_or(|hint| hint == pool.id))
            .collect();
        pools.sort_by(|a, b| {
            let affinity = |pool: &AddressPool| (pool.zone.as_deref() != zone) as u8;
            affinity(a).cmp(&affinity(b)).then_with(|| a.id.cmp(&b.id))
        });
        for pool in pools {
            if let Some(ip) = self.find_free(pool, node, now, None) {
                let expires_at = if now == 0 {
                    0
                } else {
                    now.saturating_add(pool.lease_secs)
                };
                return Ok((ip, pool.id.clone(), expires_at, false));
            }
        }
        Err("no free address in configured IPAM pools".into())
    }

    /// Validate an explicit reassignment target.
    pub fn validate_reassign(
        &self,
        node: NodeId,
        ip: IpAddr,
        pool_hint: Option<&str>,
        now: u64,
    ) -> Result<String, String> {
        let Some(pool) = self.pool_of(ip) else {
            return Err("address is outside every configured pool".into());
        };
        if pool_hint.is_some_and(|hint| hint != pool.id) {
            return Err("address is not in the requested pool".into());
        }
        if !pool.cidr.contains(&ip) {
            return Err("address is outside the pool CIDR".into());
        }
        if let Some((start, end)) = pool.range {
            let inside = match (start, end, ip) {
                (IpAddr::V4(start), IpAddr::V4(end), IpAddr::V4(ip)) => {
                    u32::from(start) <= u32::from(ip) && u32::from(ip) <= u32::from(end)
                }
                (IpAddr::V6(start), IpAddr::V6(end), IpAddr::V6(ip)) => {
                    u128::from(start) <= u128::from(ip) && u128::from(ip) <= u128::from(end)
                }
                _ => false,
            };
            if !inside {
                return Err("address is outside the pool range".into());
            }
        }
        if pool.exclude.iter().any(|exclude| exclude.contains(&ip)) {
            return Err("address is excluded".into());
        }
        if self.overlay_taken(ip, node) {
            return Err("address is already in use".into());
        }
        if self.quarantine.get(&ip).is_some_and(|until| *until > now) {
            return Err("address is quarantined".into());
        }
        Ok(pool.id.clone())
    }

    /// Allocate a reassignment target, excluding the member's current address.
    pub fn allocate_for_reassign(
        &self,
        node: NodeId,
        pool_hint: Option<&str>,
        zone: Option<&str>,
        now: u64,
        exclude: Option<IpAddr>,
    ) -> Result<(IpAddr, String), String> {
        let mut pools: Vec<&AddressPool> = self
            .pools
            .values()
            .filter(|pool| pool_hint.is_none_or(|hint| hint == pool.id))
            .collect();
        pools.sort_by(|a, b| {
            let affinity = |pool: &AddressPool| (pool.zone.as_deref() != zone) as u8;
            affinity(a).cmp(&affinity(b)).then_with(|| a.id.cmp(&b.id))
        });
        for pool in pools {
            if let Some(ip) = self.find_free(pool, node, now, exclude) {
                return Ok((ip, pool.id.clone()));
            }
        }
        Err("no free address for reassignment".into())
    }

    fn find_free(
        &self,
        pool: &AddressPool,
        node: NodeId,
        now: u64,
        exclude: Option<IpAddr>,
    ) -> Option<IpAddr> {
        let free = |ip: IpAddr| -> bool {
            if exclude == Some(ip) {
                return false;
            }
            if pool.exclude.iter().any(|exclude| exclude.contains(&ip)) {
                return false;
            }
            if self.leases.contains_key(&ip) {
                return false;
            }
            if self
                .reservations
                .values()
                .any(|reservation| reservation.ip == ip)
            {
                return false;
            }
            if self.quarantine.get(&ip).is_some_and(|until| *until > now) {
                return false;
            }
            !self
                .members
                .iter()
                .any(|(other, member)| *other != node && member.overlay_ip == Some(ip))
        };
        match pool.cidr {
            IpNet::V4(net) => {
                let (start, end) = match pool.range {
                    Some((IpAddr::V4(start), IpAddr::V4(end))) => {
                        (u32::from(start), u32::from(end))
                    }
                    _ => {
                        let prefix = net.prefix_len();
                        let network = u32::from(net.network());
                        let broadcast = u32::from(net.broadcast());
                        if prefix < 31 {
                            (network + 1, broadcast.saturating_sub(1))
                        } else {
                            (network, broadcast)
                        }
                    }
                };
                if start > end {
                    return None;
                }
                // Validation keeps IPv4 pools at /16 or smaller.
                for value in start..=end {
                    let ip = IpAddr::V4(Ipv4Addr::from(value));
                    if free(ip) {
                        return Some(ip);
                    }
                }
                None
            }
            IpNet::V6(net) => {
                let (start, end) = match pool.range {
                    Some((IpAddr::V6(start), IpAddr::V6(end))) => {
                        (u128::from(start), u128::from(end))
                    }
                    _ => {
                        let prefix = net.prefix_len();
                        let base = u128::from(net.network());
                        let host_bits = 128u32.saturating_sub(prefix as u32);
                        if host_bits == 0 {
                            let ip = IpAddr::V6(net.network());
                            return free(ip).then_some(ip);
                        }
                        let mask = u128::MAX >> (128 - host_bits);
                        let mut hasher = Sha256::new();
                        hasher.update(self.network.to_string().as_bytes());
                        hasher.update(pool.id.as_bytes());
                        hasher.update(node.as_bytes());
                        let digest = hasher.finalize();
                        let mut seed = [0u8; 16];
                        seed.copy_from_slice(&digest[..16]);
                        (base | (u128::from_be_bytes(seed) & mask), base | mask)
                    }
                };
                if start > end {
                    return None;
                }
                let span = end - start;
                if span > 4096 {
                    for offset in 0..4096u128 {
                        let value = start.wrapping_add(offset);
                        if value > end {
                            break;
                        }
                        let ip = IpAddr::V6(Ipv6Addr::from(value));
                        if free(ip) {
                            return Some(ip);
                        }
                    }
                } else {
                    for value in start..=end {
                        let ip = IpAddr::V6(Ipv6Addr::from(value));
                        if free(ip) {
                            return Some(ip);
                        }
                    }
                }
                None
            }
        }
    }

    fn bump_revision(&mut self, node: NodeId) {
        let entry = self.member_revisions.entry(node).or_insert(0);
        *entry = entry.saturating_add(1);
    }

    /// Deterministic snapshot bytes used by openraft snapshot / signing.
    pub fn snapshot_bytes(&self) -> Vec<u8> {
        #[derive(Serialize)]
        struct Snapshot<'a> {
            network: &'a NetworkId,
            epoch: u64,
            generation: u64,
            lsas: Vec<&'a Lsa>,
            members: Vec<(&'a NodeId, &'a MemberRecord)>,
            acks: Vec<(&'a NodeId, &'a AckRecord)>,
            member_revisions: Vec<(&'a NodeId, &'a u64)>,
            revoked: Vec<&'a NodeId>,
            pools: Vec<(&'a String, &'a AddressPool)>,
            leases: Vec<(&'a IpAddr, &'a Lease)>,
            node_leases: Vec<(&'a NodeId, &'a IpAddr)>,
            reservations: Vec<(&'a NodeId, &'a Reservation)>,
            quarantine: Vec<(&'a IpAddr, &'a u64)>,
            routes: Vec<(&'a String, Vec<(&'a NodeId, &'a u32)>)>,
            pending_admissions: Vec<(&'a NodeId, &'a PendingAdmission)>,
        }
        let snapshot = Snapshot {
            network: &self.network,
            epoch: self.epoch,
            generation: self.generation,
            lsas: self.lsas.values().collect(),
            members: self.members.iter().collect(),
            acks: self.acks.iter().collect(),
            member_revisions: self.member_revisions.iter().collect(),
            revoked: self.revoked.iter().collect(),
            pools: self.pools.iter().collect(),
            leases: self.leases.iter().collect(),
            node_leases: self.node_leases.iter().collect(),
            reservations: self.reservations.iter().collect(),
            quarantine: self.quarantine.iter().collect(),
            routes: self
                .routes
                .iter()
                .map(|(prefix, vias)| (prefix, vias.iter().collect()))
                .collect(),
            pending_admissions: self.pending_admissions.iter().collect(),
        };
        serde_json::to_vec(&snapshot).unwrap_or_default()
    }

    /// Deterministic route entries for controller-pushed routes.
    ///
    /// The RouteId is derived from (network, prefix, next hop) so every replica
    /// produces the same id for the same route, unlike the legacy random ids.
    pub fn route_entries(&self) -> Vec<RouteEntry> {
        let mut out = Vec::new();
        for (prefix_text, vias) in &self.routes {
            let Ok(prefix) = prefix_text.parse::<ipnet::IpNet>() else {
                continue;
            };
            for (via, metric) in vias {
                let mut entry = RouteEntry::new(
                    self.network,
                    prefix,
                    stellaris_types::RouteSource::Controller,
                    NodeId::new([0u8; 32]),
                    *via,
                );
                entry.id = stellaris_types::RouteId(uuid::Uuid::new_v5(
                    &uuid::Uuid::NAMESPACE_OID,
                    format!("stellaris-route|{}|{prefix}|{via}", self.network).as_bytes(),
                ));
                entry.metric = *metric;
                entry.admin_distance = 20;
                entry.generation = self.generation;
                out.push(entry);
            }
        }
        out
    }

    pub fn routes(&self, local: NodeId) -> Vec<RouteEntry> {
        let mut db = LinkStateDb::new();
        for lsa in self.lsas.values() {
            db.apply(lsa.clone());
        }
        db.compute_routes(local, self.network)
    }
}

impl std::fmt::Display for ControllerCommand {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;
    use stellaris_linkstate::Prefix;

    fn lsa(origin: u8, seq: u64, prefix: &str) -> Lsa {
        Lsa {
            origin: NodeId::new([origin; 32]),
            seq,
            zone: None,
            links: Vec::new(),
            prefixes: vec![Prefix {
                prefix: prefix.parse().unwrap(),
                metric: 0,
            }],
            overlay_ip: None,
            addrs: Vec::<SocketAddr>::new(),
        }
    }

    fn commands() -> Vec<ControllerCommand> {
        vec![
            ControllerCommand::SetEpoch { epoch: 2 },
            ControllerCommand::ApplyLsa {
                lsa: lsa(1, 1, "10.0.0.1/32"),
            },
            ControllerCommand::ApplyLsa {
                lsa: lsa(1, 1, "10.0.0.1/32"),
            },
            ControllerCommand::UpsertMember {
                node: NodeId::new([1u8; 32]),
                member: MemberRecord {
                    overlay_ip: Some("10.0.0.1".parse().unwrap()),
                    prefixes: vec!["192.168.50.0/24".into()],
                    capabilities: vec!["member".into()],
                },
            },
            ControllerCommand::Ack {
                node: NodeId::new([1u8; 32]),
                generation: 3,
                epoch: 2,
            },
        ]
    }

    #[test]
    fn replay_is_deterministic_and_idempotent_for_lsa() {
        let network = NetworkId::new();
        let mut a = ControllerModel::new(network, 1);
        a.apply_all(commands());
        let mut b = ControllerModel::new(network, 1);
        b.apply_all(commands());
        assert_eq!(a.snapshot_bytes(), b.snapshot_bytes());
        assert_eq!(a.lsas.len(), 1);
        assert_eq!(a.generation, 5);
    }

    #[test]
    fn stale_lsa_and_lower_epoch_are_ignored() {
        let mut model = ControllerModel::new(NetworkId::new(), 5);
        model.apply(ControllerCommand::SetEpoch { epoch: 4 });
        assert_eq!(model.epoch, 5);
        model.apply(ControllerCommand::ApplyLsa {
            lsa: lsa(1, 2, "10.0.0.1/32"),
        });
        model.apply(ControllerCommand::ApplyLsa {
            lsa: lsa(1, 1, "10.0.0.2/32"),
        });
        assert_eq!(model.lsas[&NodeId::new([1u8; 32])].seq, 2);
    }

    #[test]
    fn expire_lsas_batch_retires_only_matching_sequences() {
        let a = NodeId::new([1u8; 32]);
        let b = NodeId::new([2u8; 32]);
        let mut model = ControllerModel::new(NetworkId::new(), 1);
        model.apply(ControllerCommand::ApplyLsa {
            lsa: lsa(1, 5, "10.0.0.1/32"),
        });
        model.apply(ControllerCommand::ApplyLsa {
            lsa: lsa(2, 9, "10.0.0.2/32"),
        });
        assert!(model.apply(ControllerCommand::ExpireLsas {
            entries: vec![(a, 5), (b, 8)],
        }));
        assert!(!model.lsas.contains_key(&a));
        // b's LSA is newer than the requested sequence and must survive.
        assert!(model.lsas.contains_key(&b));
    }

    #[test]
    fn admission_requests_are_queued_and_approved_deterministically() {
        let node = NodeId::new([9u8; 32]);
        let mut a = ControllerModel::new(NetworkId::new(), 1);
        let mut b = ControllerModel::new(a.network, 1);
        let request = ControllerCommand::RequestAdmission {
            node,
            overlay_ip: Some("10.7.0.9".parse().unwrap()),
            auto: false,
            pool: None,
            zone: None,
        };
        assert!(a.apply(request.clone()));
        assert!(b.apply(request));
        assert_eq!(a.pending_admissions.len(), 1);
        assert!(a.pending_admissions.contains_key(&node));
        let member = MemberRecord {
            overlay_ip: Some("10.7.0.9".parse().unwrap()),
            prefixes: vec!["192.168.77.0/24".into()],
            capabilities: vec!["member".into()],
        };
        assert!(a.apply(ControllerCommand::ApproveAdmission {
            node,
            member: member.clone(),
            auto: false,
            pool: None,
            zone: None,
            now: 0,
        }));
        b.apply(ControllerCommand::ApproveAdmission {
            node,
            member: member.clone(),
            auto: false,
            pool: None,
            zone: None,
            now: 0,
        });
        assert!(a.members.contains_key(&node));
        assert!(a.pending_admissions.is_empty());
        assert_eq!(a.snapshot_bytes(), b.snapshot_bytes());
        // Approving again is idempotent but still changes authorization state.
        assert!(a.apply(ControllerCommand::ApproveAdmission {
            node,
            member,
            auto: false,
            pool: None,
            zone: None,
            now: 0,
        }));
        // Deny removes a pending request only.
        let other = NodeId::new([10u8; 32]);
        a.apply(ControllerCommand::RequestAdmission {
            node: other,
            overlay_ip: Some("10.7.0.10".parse().unwrap()),
            auto: false,
            pool: None,
            zone: None,
        });
        assert!(a.apply(ControllerCommand::DenyAdmission {
            node: other,
            now: 0,
        }));
        assert!(!a.pending_admissions.contains_key(&other));
    }

    #[test]
    fn routes_are_deterministic_across_replicas() {
        let network = NetworkId::new();
        let via = NodeId::new([7u8; 32]);
        let mut a = ControllerModel::new(network, 1);
        let mut b = ControllerModel::new(network, 1);
        let command = ControllerCommand::UpsertRoute {
            prefix: "192.168.44.0/24".into(),
            via,
            metric: 5,
        };
        assert!(a.apply(command.clone()));
        assert!(b.apply(command));
        assert_eq!(a.snapshot_bytes(), b.snapshot_bytes());
        let ra = a.route_entries();
        let rb = b.route_entries();
        assert_eq!(ra.len(), 1);
        assert_eq!(ra[0].id, rb[0].id);
        assert_eq!(ra[0].next_hop, via);
        assert_eq!(ra[0].metric, 5);
        // Re-applying the same route is a no-op.
        assert!(!a.apply(ControllerCommand::UpsertRoute {
            prefix: "192.168.44.0/24".into(),
            via,
            metric: 5,
        }));
        // Invalid prefixes are ignored instead of poisoning the model.
        assert!(!a.apply(ControllerCommand::UpsertRoute {
            prefix: "not-a-prefix".into(),
            via,
            metric: 1,
        }));
    }

    #[test]
    fn revoke_bumps_the_epoch() {
        let node = NodeId::new([1u8; 32]);
        let mut model = ControllerModel::new(NetworkId::new(), 10);
        model.apply(ControllerCommand::UpsertMember {
            node,
            member: MemberRecord::default(),
        });
        assert_eq!(model.epoch, 10);
        assert!(model.apply(ControllerCommand::RevokeMember { node, now: 0 }));
        assert!(model.epoch > 10, "revoke must fence old manifests");
        assert!(!model.members.contains_key(&node));
    }

    #[test]
    fn expire_lsa_only_removes_older_sequences() {
        let origin = NodeId::new([1u8; 32]);
        let mut model = ControllerModel::new(NetworkId::new(), 1);
        model.apply(ControllerCommand::ApplyLsa {
            lsa: lsa(1, 7, "10.0.0.1/32"),
        });
        // Expiring up to a lower sequence must keep a newer LSA.
        assert!(!model.apply(ControllerCommand::ExpireLsa {
            origin,
            up_to_seq: 6
        }));
        assert!(model.lsas.contains_key(&origin));
        // Expiring through the observed sequence removes it.
        assert!(model.apply(ControllerCommand::ExpireLsa {
            origin,
            up_to_seq: 7
        }));
        assert!(!model.lsas.contains_key(&origin));
    }

    #[test]
    fn revoke_removes_member_and_lsa() {
        let node = NodeId::new([1u8; 32]);
        let mut model = ControllerModel::new(NetworkId::new(), 1);
        model.apply(ControllerCommand::ApplyLsa {
            lsa: lsa(1, 1, "10.0.0.1/32"),
        });
        model.apply(ControllerCommand::UpsertMember {
            node,
            member: MemberRecord::default(),
        });
        assert!(model.apply(ControllerCommand::RevokeMember { node, now: 0 }));
        assert!(!model.lsas.contains_key(&node));
        assert!(!model.members.contains_key(&node));
    }

    fn test_pool(id: &str, cidr: &str, lease_secs: u64, quarantine_secs: u64) -> AddressPool {
        AddressPool {
            id: id.into(),
            cidr: cidr.parse().unwrap(),
            range: None,
            exclude: Vec::new(),
            lease_secs,
            quarantine_secs,
            strategy: stellaris_types::AllocStrategy::LowestFree,
            zone: None,
            description: None,
        }
    }

    fn approve_auto(
        model: &mut ControllerModel,
        node: NodeId,
        now: u64,
    ) -> Option<std::net::IpAddr> {
        let applied = model.apply(ControllerCommand::ApproveAdmission {
            node,
            member: MemberRecord::default(),
            auto: true,
            pool: None,
            zone: None,
            now,
        });
        assert!(applied, "allocation should succeed");
        model
            .members
            .get(&node)
            .and_then(|member| member.overlay_ip)
    }

    #[test]
    fn lowest_free_allocation_skips_excludes_and_reservations() {
        let mut model = ControllerModel::new(NetworkId::new(), 1);
        let mut pool = test_pool("p", "10.9.0.0/24", 60, 30);
        pool.range = Some(("10.9.0.10".parse().unwrap(), "10.9.0.20".parse().unwrap()));
        pool.exclude = vec!["10.9.0.12/32".parse().unwrap()];
        model.apply(ControllerCommand::CreatePool { pool });
        let a = NodeId::new([1u8; 32]);
        let b = NodeId::new([2u8; 32]);
        let c = NodeId::new([3u8; 32]);
        let d = NodeId::new([4u8; 32]);
        assert_eq!(
            approve_auto(&mut model, a, 100),
            Some("10.9.0.10".parse().unwrap())
        );
        assert_eq!(
            approve_auto(&mut model, b, 100),
            Some("10.9.0.11".parse().unwrap())
        );
        assert!(model.apply(ControllerCommand::ReserveAddress {
            node: c,
            ip: "10.9.0.15".parse().unwrap(),
            pool: None,
            note: Some("vip".into()),
        }));
        assert_eq!(
            approve_auto(&mut model, d, 100),
            Some("10.9.0.13".parse().unwrap())
        );
        assert_eq!(model.leases.len(), 4);
    }

    #[test]
    fn expired_leases_are_quarantined_then_reused() {
        let mut model = ControllerModel::new(NetworkId::new(), 1);
        model.apply(ControllerCommand::CreatePool {
            pool: test_pool("p", "10.10.0.0/24", 10, 30),
        });
        let a = NodeId::new([1u8; 32]);
        let b = NodeId::new([2u8; 32]);
        let c = NodeId::new([3u8; 32]);
        assert_eq!(
            approve_auto(&mut model, a, 1000),
            Some("10.10.0.1".parse().unwrap())
        );
        assert!(!model.apply(ControllerCommand::ExpireLeases { now: 1005 }));
        assert!(model.apply(ControllerCommand::ExpireLeases { now: 1010 }));
        assert!(model.leases.is_empty());
        assert_eq!(
            model.quarantine.get(&"10.10.0.1".parse().unwrap()).copied(),
            Some(1040)
        );
        // Still quarantined: the next node gets a different address.
        assert_eq!(
            approve_auto(&mut model, b, 1010),
            Some("10.10.0.2".parse().unwrap())
        );
        // Once the quarantine ends the address is reusable.
        assert_eq!(
            approve_auto(&mut model, c, 1041),
            Some("10.10.0.1".parse().unwrap())
        );
    }

    #[test]
    fn ipv6_hash_probe_is_deterministic() {
        let network = NetworkId::new();
        let node = NodeId::new([7u8; 32]);
        let mut a = ControllerModel::new(network, 1);
        let mut b = ControllerModel::new(network, 1);
        let mut pool = test_pool("v6", "fd00:9::/120", 60, 30);
        pool.strategy = stellaris_types::AllocStrategy::HashProbe;
        a.apply(ControllerCommand::CreatePool { pool: pool.clone() });
        b.apply(ControllerCommand::CreatePool { pool });
        let ip_a = approve_auto(&mut a, node, 100);
        let ip_b = approve_auto(&mut b, node, 100);
        assert!(ip_a.is_some(), "ipv6 pool must allocate");
        assert_eq!(ip_a, ip_b);
        assert_eq!(a.snapshot_bytes(), b.snapshot_bytes());
    }

    #[test]
    fn revoke_releases_the_lease() {
        let mut model = ControllerModel::new(NetworkId::new(), 1);
        model.apply(ControllerCommand::CreatePool {
            pool: test_pool("p", "10.11.0.0/24", 60, 30),
        });
        let a = NodeId::new([1u8; 32]);
        let ip = approve_auto(&mut model, a, 100).unwrap();
        assert!(model.apply(ControllerCommand::RevokeMember { node: a, now: 200 }));
        assert!(model.leases.is_empty());
        assert!(model.node_leases.is_empty());
        assert_eq!(model.quarantine.get(&ip).copied(), Some(230));
    }

    #[test]
    fn deleting_a_pool_requires_force_when_leases_exist() {
        let mut model = ControllerModel::new(NetworkId::new(), 1);
        model.apply(ControllerCommand::CreatePool {
            pool: test_pool("p", "10.12.0.0/24", 60, 30),
        });
        approve_auto(&mut model, NodeId::new([1u8; 32]), 100);
        assert!(!model.apply(ControllerCommand::DeletePool {
            id: "p".into(),
            force: false,
            now: 200,
        }));
        assert!(model.apply(ControllerCommand::DeletePool {
            id: "p".into(),
            force: true,
            now: 200,
        }));
        assert!(model.pools.is_empty());
        assert!(model.leases.is_empty());
    }

    #[test]
    fn reassign_address_moves_lease_and_quarantines_old() {
        let mut model = ControllerModel::new(NetworkId::new(), 1);
        model.apply(ControllerCommand::CreatePool {
            pool: test_pool("p", "10.11.0.0/24", 60, 30),
        });
        let node = NodeId::new([7u8; 32]);
        assert_eq!(
            approve_auto(&mut model, node, 100),
            Some("10.11.0.1".parse().unwrap())
        );
        assert!(model.apply(ControllerCommand::ReassignAddress {
            node,
            ip: Some("10.11.0.5".parse().unwrap()),
            pool: None,
            zone: None,
            now: 110,
        }));
        assert_eq!(
            model
                .members
                .get(&node)
                .and_then(|member| member.overlay_ip),
            Some("10.11.0.5".parse().unwrap())
        );
        assert_eq!(
            model.node_leases.get(&node),
            Some(&"10.11.0.5".parse().unwrap())
        );
        assert!(!model.leases.contains_key(&"10.11.0.1".parse().unwrap()));
        assert!(
            model
                .quarantine
                .get(&"10.11.0.1".parse().unwrap())
                .is_some_and(|until| *until == 140)
        );
        assert_eq!(model.member_revisions.get(&node), Some(&2));
        // Auto reassignment picks a new address, never the old one or a
        // quarantined address.
        assert!(model.apply(ControllerCommand::ReassignAddress {
            node,
            ip: None,
            pool: Some("p".into()),
            zone: None,
            now: 120,
        }));
        assert_eq!(
            model
                .members
                .get(&node)
                .and_then(|member| member.overlay_ip),
            Some("10.11.0.2".parse().unwrap())
        );
        assert!(!model.apply(ControllerCommand::ReassignAddress {
            node,
            ip: Some("10.99.0.1".parse().unwrap()),
            pool: None,
            zone: None,
            now: 120,
        }));
    }
}
