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
        };
        serde_json::to_vec(&snapshot).unwrap_or_default()
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
