//! Forwarding information base: LPM + ECMP.

use std::collections::BTreeMap;
use std::net::IpAddr;

use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use prefix_trie::PrefixMap;
use serde::Serialize;
use smallvec::SmallVec;
use stellaris_types::{NodeId, PathHint, RouteEntry, RouteSource, RouteState};

#[derive(Clone, Debug, Serialize)]
pub struct FibNextHop {
    pub node: NodeId,
    pub weight: u16,
    pub path_hint: PathHint,
}

#[derive(Clone, Debug, Serialize)]
pub struct FibEntry {
    pub next_hops: SmallVec<[FibNextHop; 4]>,
    pub source: RouteSource,
}

impl FibEntry {
    pub fn select(&self, flow_hash: u32) -> Option<&FibNextHop> {
        self.select_where(flow_hash, |_| true)
    }

    /// ECMP selection restricted to next hops accepted by `usable`. This keeps
    /// traffic away from peers whose transport link is currently down instead
    /// of handing it to `transport.send` for a silent drop.
    pub fn select_where<F>(&self, flow_hash: u32, mut usable: F) -> Option<&FibNextHop>
    where
        F: FnMut(NodeId) -> bool,
    {
        let mut total: u32 = 0;
        let mut candidates = 0usize;
        for nh in &self.next_hops {
            if usable(nh.node) {
                candidates += 1;
                total = total.saturating_add(nh.weight.max(1) as u32);
            }
        }
        if candidates == 0 {
            return None;
        }
        if candidates == 1 {
            return self.next_hops.iter().find(|nh| usable(nh.node));
        }
        let mut slot = flow_hash % total;
        for nh in &self.next_hops {
            if !usable(nh.node) {
                continue;
            }
            let w = nh.weight.max(1) as u32;
            if slot < w {
                return Some(nh);
            }
            slot -= w;
        }
        self.next_hops.iter().rev().find(|nh| usable(nh.node))
    }
}

#[derive(Clone, Debug, Default)]
pub struct Fib {
    v4: PrefixMap<Ipv4Net, FibEntry>,
    v6: PrefixMap<Ipv6Net, FibEntry>,
    generation: u64,
}

impl Fib {
    pub fn generation(&self) -> u64 {
        self.generation
    }

    pub fn len(&self) -> usize {
        self.v4.len() + self.v6.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn lookup(&self, dst: IpAddr) -> Option<&FibEntry> {
        match dst {
            IpAddr::V4(ip) => self.v4.get_lpm(&Ipv4Net::from(ip)).map(|(_, e)| e),
            IpAddr::V6(ip) => self.v6.get_lpm(&Ipv6Net::from(ip)).map(|(_, e)| e),
        }
    }

    pub fn lookup_hash(&self, dst: IpAddr, flow_hash: u32) -> Option<&FibNextHop> {
        self.lookup(dst).and_then(|e| e.select(flow_hash))
    }

    /// Build a FIB from a set of candidate routes.
    ///
    /// Selection: longest prefix is implicit in the map; for the same prefix:
    /// pin > admin_distance asc > local_pref desc > metric asc > ECMP.
    pub fn compile(
        routes: &[RouteEntry],
        ecmp_max: usize,
        generation: u64,
        now: time::OffsetDateTime,
    ) -> Self {
        let mut grouped: BTreeMap<IpNet, Vec<&RouteEntry>> = BTreeMap::new();
        for route in routes {
            if !route.is_active_at(now) || route.state != RouteState::Active {
                continue;
            }
            if route.expires_at.is_some_and(|t| t <= now) {
                continue;
            }
            grouped.entry(route.prefix).or_default().push(route);
        }

        let mut fib = Self {
            v4: PrefixMap::new(),
            v6: PrefixMap::new(),
            generation,
        };

        for (prefix, mut candidates) in grouped {
            let pinned = candidates.iter().any(|r| r.pin);
            if pinned {
                candidates.retain(|r| r.pin);
            }
            candidates.sort_by(|a, b| {
                a.admin_distance
                    .cmp(&b.admin_distance)
                    .then_with(|| b.local_pref.cmp(&a.local_pref))
                    .then_with(|| a.metric.cmp(&b.metric))
                    .then_with(|| a.id.cmp(&b.id))
            });
            let Some(best) = candidates.first().copied() else {
                continue;
            };
            let best_key = (best.admin_distance, best.local_pref, best.metric);
            let mut next_hops: SmallVec<[FibNextHop; 4]> = SmallVec::new();
            for candidate in candidates {
                let key = (
                    candidate.admin_distance,
                    candidate.local_pref,
                    candidate.metric,
                );
                if key != best_key {
                    break;
                }
                if next_hops.len() >= ecmp_max {
                    break;
                }
                next_hops.push(FibNextHop {
                    node: candidate.next_hop,
                    weight: candidate.weight.max(1),
                    path_hint: PathHint::Auto,
                });
            }
            if next_hops.is_empty() {
                continue;
            }
            let entry = FibEntry {
                next_hops,
                source: best.source,
            };
            match prefix {
                IpNet::V4(p) => {
                    fib.v4.insert(p, entry);
                }
                IpNet::V6(p) => {
                    fib.v6.insert(p, entry);
                }
            }
        }

        fib
    }
}

impl Fib {
    pub fn entries(&self) -> Vec<(IpNet, FibEntry)> {
        let mut out = Vec::new();
        for (p, e) in self.v4.iter() {
            out.push((IpNet::V4(p), e.clone()));
        }
        for (p, e) in self.v6.iter() {
            out.push((IpNet::V6(p), e.clone()));
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use stellaris_types::{NetworkId, NodeId, RouteSource};

    fn node(n: u8) -> NodeId {
        NodeId::new([n; 32])
    }

    fn net() -> NetworkId {
        NetworkId::new()
    }

    fn route(prefix: &str, next: NodeId, metric: u32) -> RouteEntry {
        let mut r = RouteEntry::new(
            net(),
            prefix.parse().unwrap(),
            RouteSource::Static,
            node(1),
            next,
        );
        r.metric = metric;
        r
    }

    #[test]
    fn longest_prefix_wins() {
        let routes = vec![
            route("10.0.0.0/8", node(2), 10),
            route("10.1.0.0/16", node(3), 20),
        ];
        let fib = Fib::compile(&routes, 8, 1, time::OffsetDateTime::now_utc());
        assert_eq!(
            fib.lookup("10.1.2.3".parse().unwrap()).unwrap().next_hops[0].node,
            node(3)
        );
        assert_eq!(
            fib.lookup("10.2.2.3".parse().unwrap()).unwrap().next_hops[0].node,
            node(2)
        );
    }

    #[test]
    fn admin_distance_and_metric() {
        let mut a = route("10.0.0.0/16", node(2), 100);
        a.admin_distance = 100;
        let mut b = route("10.0.0.0/16", node(3), 10);
        b.admin_distance = 1;
        let fib = Fib::compile(&[a, b], 8, 1, time::OffsetDateTime::now_utc());
        assert_eq!(
            fib.lookup("10.0.0.1".parse().unwrap()).unwrap().next_hops[0].node,
            node(3)
        );
    }

    #[test]
    fn pin_restricts_candidates() {
        let mut a = route("10.0.0.0/16", node(2), 1);
        a.pin = false;
        let mut b = route("10.0.0.0/16", node(3), 50);
        b.pin = true;
        let fib = Fib::compile(&[a, b], 8, 1, time::OffsetDateTime::now_utc());
        assert_eq!(
            fib.lookup("10.0.0.1".parse().unwrap()).unwrap().next_hops[0].node,
            node(3)
        );
    }

    #[test]
    fn ecmp_has_multiple_next_hops() {
        let a = route("10.0.0.0/16", node(2), 10);
        let b = route("10.0.0.0/16", node(3), 10);
        let fib = Fib::compile(&[a, b], 8, 1, time::OffsetDateTime::now_utc());
        let entry = fib.lookup("10.0.0.1".parse().unwrap()).unwrap();
        assert_eq!(entry.next_hops.len(), 2);
        let selected: std::collections::HashSet<_> =
            (0..32).map(|i| entry.select(i).unwrap().node).collect();
        assert_eq!(selected.len(), 2);
    }

    #[test]
    fn expired_route_ignored() {
        let mut a = route("10.0.0.0/16", node(2), 10);
        a.expires_at = Some(time::OffsetDateTime::now_utc() - time::Duration::seconds(1));
        let fib = Fib::compile(&[a], 8, 1, time::OffsetDateTime::now_utc());
        assert!(fib.lookup("10.0.0.1".parse().unwrap()).is_none());
    }

    #[test]
    fn v6_lookup() {
        let r = route("fd00::/64", node(2), 10);
        let fib = Fib::compile(&[r], 8, 1, time::OffsetDateTime::now_utc());
        assert_eq!(
            fib.lookup("fd00::1".parse().unwrap()).unwrap().next_hops[0].node,
            node(2)
        );
    }
}
