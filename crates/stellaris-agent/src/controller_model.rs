//! Deterministic controller state model (openraft H0).
//!
//! This module is intentionally independent of wall-clock time and the
//! existing HTTP controller. The same command log must produce identical
//! state on every replica; openraft can later drive `apply()`.

use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;

use serde::{Deserialize, Serialize};
use stellaris_linkstate::{LinkStateDb, Lsa};
use stellaris_types::{NetworkId, NodeId, RouteEntry};

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct MemberRecord {
    pub overlay_ip: Option<IpAddr>,
    pub prefixes: Vec<String>,
    pub capabilities: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PendingAdmission {
    pub overlay_ip: IpAddr,
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
        overlay_ip: IpAddr,
    },
    /// Administrator approval: grants exactly the supplied member record.
    ApproveAdmission {
        node: NodeId,
        member: MemberRecord,
    },
    DenyAdmission {
        node: NodeId,
    },
    UpsertMember {
        node: NodeId,
        member: MemberRecord,
    },
    Join {
        node: NodeId,
        member: MemberRecord,
        token: String,
    },
    SetJoinConfigHash {
        hash: String,
    },
    RevokeMember {
        node: NodeId,
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
    pub consumed_join_tokens: BTreeSet<String>,
    #[serde(default)]
    pub join_config_hash: Option<String>,
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
            consumed_join_tokens: BTreeSet::new(),
            join_config_hash: None,
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
                let changed = self.members.get(&node) != Some(&member);
                if changed {
                    self.members.insert(node, member);
                }
                changed
            }
            ControllerCommand::Join {
                node,
                member,
                token,
            } => {
                if self.consumed_join_tokens.contains(&token) {
                    false
                } else {
                    self.consumed_join_tokens.insert(token);
                    self.members.insert(node, member);
                    true
                }
            }
            ControllerCommand::SetJoinConfigHash { hash } => {
                if self.join_config_hash.is_none() {
                    self.join_config_hash = Some(hash);
                    true
                } else {
                    false
                }
            }
            ControllerCommand::RevokeMember { node } => {
                let removed = self.members.remove(&node).is_some();
                let lsa_removed = self.lsas.remove(&node).is_some();
                if removed || lsa_removed {
                    // A revocation invalidates manifests signed under the old
                    // epoch; bump it so stale manifest copies are fenced.
                    self.epoch = self.epoch.saturating_add(1);
                }
                removed || lsa_removed
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
            ControllerCommand::RequestAdmission { node, overlay_ip } => {
                if self.members.contains_key(&node) || self.pending_admissions.contains_key(&node) {
                    false
                } else {
                    self.pending_admissions
                        .insert(node, PendingAdmission { overlay_ip });
                    true
                }
            }
            ControllerCommand::ApproveAdmission { node, member } => {
                let changed = self.members.get(&node) != Some(&member);
                self.members.insert(node, member);
                self.pending_admissions.remove(&node);
                // Approvals always change authorization, even when the member
                // record is unchanged (idempotent re-approval still bumps generation).
                let _ = changed;
                true
            }
            ControllerCommand::DenyAdmission { node } => {
                self.pending_admissions.remove(&node).is_some()
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
            consumed_join_tokens: Vec<&'a String>,
            join_config_hash: Option<&'a String>,
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
            consumed_join_tokens: self.consumed_join_tokens.iter().collect(),
            join_config_hash: self.join_config_hash.as_ref(),
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
            overlay_ip: "10.7.0.9".parse().unwrap(),
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
        }));
        b.apply(ControllerCommand::ApproveAdmission { node, member });
        assert!(a.members.contains_key(&node));
        assert!(a.pending_admissions.is_empty());
        assert_eq!(a.snapshot_bytes(), b.snapshot_bytes());
        // Approving again is idempotent but still changes authorization state.
        assert!(a.apply(ControllerCommand::ApproveAdmission {
            node,
            member: MemberRecord::default(),
        }));
        // Deny removes a pending request only.
        let other = NodeId::new([10u8; 32]);
        a.apply(ControllerCommand::RequestAdmission {
            node: other,
            overlay_ip: "10.7.0.10".parse().unwrap(),
        });
        assert!(a.apply(ControllerCommand::DenyAdmission { node: other }));
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
        assert!(model.apply(ControllerCommand::RevokeMember { node }));
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
        assert!(model.apply(ControllerCommand::RevokeMember { node }));
        assert!(!model.lsas.contains_key(&node));
        assert!(!model.members.contains_key(&node));
    }
}
