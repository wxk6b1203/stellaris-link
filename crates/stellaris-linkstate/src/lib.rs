//! Link-state database, LSA flooding model, and SPF route computation.
//!
//! The wire protocol is intentionally separate: this crate is transport-agnostic
//! and is used by both the controller and (later) the peer-to-peer LSA stream.

use std::cmp::Ordering;
use std::collections::{BinaryHeap, HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};

use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use stellaris_types::{NetworkId, NodeId, RouteAttributes, RouteEntry, RouteSource};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Link {
    pub to: NodeId,
    /// Link metric (lower is better); usually integer RTT ms or hop cost.
    pub metric: u32,
    #[serde(default)]
    pub zone: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Prefix {
    pub prefix: IpNet,
    #[serde(default)]
    pub metric: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Lsa {
    pub origin: NodeId,
    /// Monotonic per-origin sequence; higher is newer.
    pub seq: u64,
    #[serde(default)]
    pub zone: Option<String>,
    #[serde(default)]
    pub links: Vec<Link>,
    #[serde(default)]
    pub prefixes: Vec<Prefix>,
    /// Underlay overlay IP for auto-discovery.
    #[serde(default)]
    pub overlay_ip: Option<IpAddr>,
    /// Underlay reachable addresses for auto-discovery.
    #[serde(default)]
    pub addrs: Vec<SocketAddr>,
}

#[derive(Clone, Debug)]
struct LsaEntry {
    lsa: Lsa,
    seen: std::time::Instant,
}

#[derive(Clone, Debug, Default)]
pub struct LinkStateDb {
    lsas: HashMap<NodeId, LsaEntry>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RouteNextHop {
    pub via: NodeId,
    pub metric: u32,
}

impl LinkStateDb {
    pub fn new() -> Self {
        Self::default()
    }

    /// Apply an LSA. Returns true if it replaced an older/unknown LSA.
    pub fn apply(&mut self, lsa: Lsa) -> bool {
        let newer = match self.lsas.get(&lsa.origin) {
            Some(existing) => existing.lsa.seq < lsa.seq,
            None => true,
        };
        if newer {
            self.lsas.insert(
                lsa.origin,
                LsaEntry {
                    lsa,
                    seen: std::time::Instant::now(),
                },
            );
        }
        newer
    }

    /// Remove LSAs not refreshed within `max_age`.
    pub fn expire(&mut self, max_age: std::time::Duration) -> usize {
        let before = self.lsas.len();
        let now = std::time::Instant::now();
        self.lsas
            .retain(|_, entry| now.duration_since(entry.seen) <= max_age);
        before - self.lsas.len()
    }

    pub fn remove(&mut self, origin: NodeId) -> bool {
        self.lsas.remove(&origin).is_some()
    }

    pub fn get(&self, origin: &NodeId) -> Option<&Lsa> {
        self.lsas.get(origin).map(|entry| &entry.lsa)
    }

    pub fn len(&self) -> usize {
        self.lsas.len()
    }

    pub fn is_empty(&self) -> bool {
        self.lsas.is_empty()
    }

    pub fn all(&self) -> impl Iterator<Item = &Lsa> {
        self.lsas.values().map(|entry| &entry.lsa)
    }

    /// Compute SPF next hops from `local` to every other origin.
    pub fn shortest_paths(&self, local: NodeId) -> HashMap<NodeId, RouteNextHop> {
        let mut dist: HashMap<NodeId, u32> = HashMap::new();
        let mut first: HashMap<NodeId, NodeId> = HashMap::new();
        let mut heap = BinaryHeap::new();
        dist.insert(local, 0);

        for link in self
            .lsas
            .get(&local)
            .map(|l| l.lsa.links.as_slice())
            .unwrap_or_default()
        {
            let entry = dist.entry(link.to).or_insert(u32::MAX);
            if link.metric < *entry {
                *entry = link.metric;
                first.insert(link.to, link.to);
                heap.push(ReverseCost {
                    cost: link.metric,
                    node: link.to,
                });
            }
        }

        let mut settled = HashSet::new();
        while let Some(ReverseCost { cost, node }) = heap.pop() {
            if !settled.insert(node) {
                continue;
            }
            let Some(lsa) = self.lsas.get(&node) else {
                continue;
            };
            for link in &lsa.lsa.links {
                let next_cost = cost.saturating_add(link.metric);
                let known = dist.get(&link.to).copied().unwrap_or(u32::MAX);
                if next_cost < known {
                    dist.insert(link.to, next_cost);
                    let hop = *first.get(&node).unwrap_or(&node);
                    first.insert(link.to, hop);
                    heap.push(ReverseCost {
                        cost: next_cost,
                        node: link.to,
                    });
                }
            }
        }

        dist.into_iter()
            .filter_map(|(node, metric)| {
                if node == local {
                    return None;
                }
                first
                    .get(&node)
                    .map(|via| (node, RouteNextHop { via: *via, metric }))
            })
            .collect()
    }

    /// All equal-cost first hops from `local` to each destination.
    pub fn shortest_paths_ecmp(&self, local: NodeId) -> HashMap<NodeId, Vec<RouteNextHop>> {
        let dist = self.distances(local);
        let Some(local_lsa) = self.get(&local) else {
            return HashMap::new();
        };
        let mut out = HashMap::new();
        for (dest, metric) in &dist {
            if *dest == local {
                continue;
            }
            let mut vias = HashSet::new();
            for link in &local_lsa.links {
                let direct = link.to == *dest && link.metric == *metric;
                let via_neighbor = link.metric < *metric
                    && dist
                        .get(&link.to)
                        .is_some_and(|d| d.saturating_add(link.metric) == *metric);
                if direct || via_neighbor {
                    vias.insert(link.to);
                }
            }
            if !vias.is_empty() {
                let mut vias: Vec<NodeId> = vias.into_iter().collect();
                vias.sort();
                out.insert(
                    *dest,
                    vias.into_iter()
                        .map(|via| RouteNextHop {
                            via,
                            metric: *metric,
                        })
                        .collect(),
                );
            }
        }
        out
    }

    fn distances(&self, local: NodeId) -> HashMap<NodeId, u32> {
        let mut dist: HashMap<NodeId, u32> = HashMap::new();
        let mut heap = BinaryHeap::new();
        dist.insert(local, 0);
        for link in self
            .get(&local)
            .map(|lsa| lsa.links.as_slice())
            .unwrap_or_default()
        {
            let entry = dist.entry(link.to).or_insert(u32::MAX);
            if link.metric < *entry {
                *entry = link.metric;
                heap.push(ReverseCost {
                    cost: link.metric,
                    node: link.to,
                });
            }
        }
        let mut settled = HashSet::new();
        while let Some(ReverseCost { cost, node }) = heap.pop() {
            if !settled.insert(node) {
                continue;
            }
            let Some(lsa) = self.get(&node) else {
                continue;
            };
            for link in &lsa.links {
                let next_cost = cost.saturating_add(link.metric);
                let known = dist.get(&link.to).copied().unwrap_or(u32::MAX);
                if next_cost < known {
                    dist.insert(link.to, next_cost);
                    heap.push(ReverseCost {
                        cost: next_cost,
                        node: link.to,
                    });
                }
            }
        }
        dist
    }

    /// Compute link-state routes for all advertised prefixes.
    ///
    /// The caller inserts these into the RIB with `RouteSource::LinkState`.
    /// Local prefixes are skipped (the kernel/agent owns the local route).
    pub fn compute_routes(&self, local: NodeId, network: NetworkId) -> Vec<RouteEntry> {
        let paths = self.shortest_paths_ecmp(local);
        let mut out = Vec::new();
        for entry in self.lsas.values() {
            let lsa = &entry.lsa;
            if lsa.origin == local {
                continue;
            }
            let Some(next_hops) = paths.get(&lsa.origin) else {
                continue;
            };
            for prefix in &lsa.prefixes {
                for path in next_hops {
                    let mut route = RouteEntry::new(
                        network,
                        prefix.prefix,
                        RouteSource::LinkState,
                        lsa.origin,
                        path.via,
                    );
                    route.metric = path.metric.saturating_add(prefix.metric);
                    route.attrs = RouteAttributes {
                        zone: lsa.zone.clone(),
                        ..Default::default()
                    };
                    out.push(route);
                }
            }
        }
        out.sort_by(|a, b| {
            a.prefix
                .to_string()
                .cmp(&b.prefix.to_string())
                .then_with(|| a.metric.cmp(&b.metric))
                .then_with(|| a.next_hop.cmp(&b.next_hop))
        });
        out
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ReverseCost {
    cost: u32,
    node: NodeId,
}

impl Ord for ReverseCost {
    fn cmp(&self, other: &Self) -> Ordering {
        // BinaryHeap is max-heap; reverse cost to make it a min-heap.
        other
            .cost
            .cmp(&self.cost)
            .then_with(|| other.node.cmp(&self.node))
    }
}

impl PartialOrd for ReverseCost {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node(n: u8) -> NodeId {
        NodeId::new([n; 32])
    }

    fn net() -> NetworkId {
        NetworkId::new()
    }

    fn lsa(origin: u8, seq: u64, links: &[(u8, u32)], prefixes: &[&str]) -> Lsa {
        Lsa {
            origin: node(origin),
            seq,
            zone: None,
            links: links
                .iter()
                .map(|(to, metric)| Link {
                    to: node(*to),
                    metric: *metric,
                    zone: None,
                })
                .collect(),
            prefixes: prefixes
                .iter()
                .map(|p| Prefix {
                    prefix: p.parse().unwrap(),
                    metric: 0,
                })
                .collect(),
            overlay_ip: None,
            addrs: Vec::new(),
        }
    }

    #[test]
    fn spf_three_nodes() {
        let mut db = LinkStateDb::new();
        db.apply(lsa(1, 1, &[(2, 1)], &["10.0.0.1/32"]));
        db.apply(lsa(2, 1, &[(1, 1), (3, 1)], &["10.0.0.2/32"]));
        db.apply(lsa(3, 1, &[(2, 1)], &["192.168.50.0/24"]));
        let paths = db.shortest_paths(node(1));
        assert_eq!(paths[&node(2)].metric, 1);
        assert_eq!(paths[&node(3)].metric, 2);
        assert_eq!(paths[&node(3)].via, node(2));

        let routes = db.compute_routes(node(1), net());
        let c = routes
            .iter()
            .find(|r| r.prefix.to_string() == "192.168.50.0/24")
            .unwrap();
        assert_eq!(c.next_hop, node(2));
        assert_eq!(c.metric, 2);
        assert_eq!(c.source, RouteSource::LinkState);
    }

    #[test]
    fn expired_lsa_is_removed() {
        let mut db = LinkStateDb::new();
        db.apply(lsa(1, 1, &[(2, 1)], &["10.0.0.1/32"]));
        assert_eq!(db.expire(std::time::Duration::ZERO), 1);
        assert!(db.is_empty());
    }

    #[test]
    fn stale_lsa_is_ignored() {
        let mut db = LinkStateDb::new();
        assert!(db.apply(lsa(1, 2, &[(2, 1)], &["10.0.0.1/32"])));
        assert!(!db.apply(lsa(1, 1, &[(2, 9)], &["10.0.0.1/32"])));
        assert_eq!(db.get(&node(1)).unwrap().seq, 2);
    }

    #[test]
    fn equal_cost_paths_are_ecmp() {
        let mut db = LinkStateDb::new();
        db.apply(lsa(1, 1, &[(2, 1), (3, 2)], &[]));
        db.apply(lsa(2, 1, &[(1, 1), (3, 2)], &[]));
        db.apply(lsa(3, 1, &[(1, 2), (2, 2)], &["10.0.0.3/32"]));
        let paths = db.shortest_paths_ecmp(node(1));
        let hops = paths.get(&node(3)).unwrap();
        assert_eq!(hops.len(), 2);
        assert_eq!(hops[0].metric, 2);
    }

    #[test]
    fn direct_better_than_detour() {
        let mut db = LinkStateDb::new();
        db.apply(lsa(1, 1, &[(2, 10), (3, 1)], &[]));
        db.apply(lsa(2, 1, &[(1, 10), (3, 1)], &["10.0.0.2/32"]));
        db.apply(lsa(3, 1, &[(1, 1), (2, 1)], &[]));
        let paths = db.shortest_paths(node(1));
        assert_eq!(paths[&node(2)].metric, 2);
        assert_eq!(paths[&node(2)].via, node(3));
    }
}
