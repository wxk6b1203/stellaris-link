//! Intent / RIB / FIB route engine.

use std::collections::BTreeSet;
use std::net::IpAddr;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};

use arc_swap::ArcSwap;
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use stellaris_fib::{Fib, FibEntry};
use stellaris_types::{
    Action, Match, NetworkId, NodeId, PathHint, RouteAttributes, RouteChange, RouteEntry, RouteId,
    RoutePolicy, RouteSource, RouteState, Scope, UpsertStatic,
};
use thiserror::Error;
use tokio::sync::watch;

#[derive(Debug, Error)]
pub enum RoutingError {
    #[error("route not found: {0}")]
    NotFound(RouteId),
    #[error("no route to {0}")]
    NoRoute(IpAddr),
    #[error("route limit exceeded: {0}")]
    Limit(usize),
    #[error("invalid route: {0}")]
    Invalid(String),
    #[error("io: {0}")]
    Io(String),
    #[error("json: {0}")]
    Json(String),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IntentRecord {
    pub entry: RouteEntry,
    pub scope: Scope,
    pub reason: String,
    pub created_by: String,
    pub created_at: time::OffsetDateTime,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ApplyResult {
    pub generation: u64,
    pub added: Vec<IpNet>,
    pub removed: Vec<IpNet>,
    pub warnings: Vec<String>,
    pub dry_run: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ExplainCandidate {
    pub route: RouteEntry,
    pub eligible: bool,
    pub reason: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Explain {
    pub dst: IpAddr,
    pub selected: Option<RouteEntry>,
    pub candidates: Vec<ExplainCandidate>,
    pub generation: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FibViewEntry {
    pub prefix: IpNet,
    pub next_hops: Vec<FibViewHop>,
    pub source: RouteSource,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FibViewHop {
    pub node: NodeId,
    pub weight: u16,
    pub path_hint: PathHint,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RouteView {
    Intent,
    Rib,
    Fib,
}

#[derive(Clone, Debug)]
struct Inner {
    intents: Vec<IntentRecord>,
    routes: Vec<RouteEntry>,
    policies: Vec<RoutePolicy>,
}

impl Inner {
    fn rebuild_routes(&mut self, now: time::OffsetDateTime) {
        self.intents
            .retain(|i| i.entry.expires_at.map(|t| t > now).unwrap_or(true));
        let routes: Vec<RouteEntry> = self
            .intents
            .iter()
            .filter(|i| i.entry.is_active_at(now))
            .map(|i| i.entry.clone())
            .collect();
        self.routes = apply_policies(routes, &self.policies);
    }

    fn rebuild_fib(
        &mut self,
        ecmp_max: usize,
        generation: u64,
        now: time::OffsetDateTime,
    ) -> Arc<Fib> {
        self.rebuild_routes(now);
        Arc::new(Fib::compile(&self.routes, ecmp_max, generation, now))
    }
}

pub struct RouteEngine {
    network: NetworkId,
    local: NodeId,
    ecmp_max: usize,
    max_routes: usize,
    generation: AtomicU64,
    inner: RwLock<Inner>,
    fib: ArcSwap<Fib>,
    changed: watch::Sender<u64>,
}

impl RouteEngine {
    pub fn new(network: NetworkId, local: NodeId, ecmp_max: usize, max_routes: usize) -> Self {
        let generation = 1u64;
        let fib = Arc::new(Fib::default());
        Self {
            network,
            local,
            ecmp_max: ecmp_max.max(1),
            max_routes: max_routes.max(1),
            generation: AtomicU64::new(generation),
            inner: RwLock::new(Inner {
                intents: Vec::new(),
                routes: Vec::new(),
                policies: Vec::new(),
            }),
            fib: ArcSwap::from(fib),
            changed: watch::channel(generation).0,
        }
    }

    /// Subscribe to generation changes for event-driven reconciliation.
    pub fn subscribe(&self) -> watch::Receiver<u64> {
        self.changed.subscribe()
    }

    pub fn set_policies(&self, policies: Vec<RoutePolicy>) -> Result<u64, RoutingError> {
        let now = time::OffsetDateTime::now_utc();
        let mut guard = self.inner.write().unwrap_or_else(|e| e.into_inner());
        guard.policies = policies;
        let generation = self.generation() + 1;
        let fib = guard.rebuild_fib(self.ecmp_max, generation, now);
        self.generation.store(generation, Ordering::Relaxed);
        self.fib.store(fib);
        let _ = self.changed.send(generation);
        Ok(generation)
    }

    pub fn generation(&self) -> u64 {
        self.generation.load(Ordering::Relaxed)
    }

    pub fn fib(&self) -> Arc<Fib> {
        self.fib.load_full()
    }

    pub fn network(&self) -> NetworkId {
        self.network
    }

    pub fn local(&self) -> NodeId {
        self.local
    }

    #[allow(clippy::too_many_arguments)]
    pub fn add_static(
        &self,
        prefix: IpNet,
        via: NodeId,
        admin_distance: Option<u8>,
        metric: Option<u32>,
        weight: Option<u16>,
        pin: bool,
        expires_at: Option<time::OffsetDateTime>,
        reason: impl Into<String>,
    ) -> Result<ApplyResult, RoutingError> {
        self.add_static_with_attrs(
            prefix,
            via,
            admin_distance,
            None,
            metric,
            weight,
            pin,
            expires_at,
            RouteAttributes::default(),
            reason,
        )
    }

    /// Static route with explicit local_pref / attributes (AZ, QoS metadata, ...).
    #[allow(clippy::too_many_arguments)]
    pub fn add_static_with_attrs(
        &self,
        prefix: IpNet,
        via: NodeId,
        admin_distance: Option<u8>,
        local_pref: Option<u32>,
        metric: Option<u32>,
        weight: Option<u16>,
        pin: bool,
        expires_at: Option<time::OffsetDateTime>,
        attrs: RouteAttributes,
        reason: impl Into<String>,
    ) -> Result<ApplyResult, RoutingError> {
        let change = RouteChange::UpsertStatic(UpsertStatic {
            prefix,
            via,
            admin_distance,
            local_pref,
            metric,
            weight,
            pin,
            expires_at,
            attrs,
        });
        self.apply(change, Scope::Local, reason.into(), "local".into(), false)
    }

    pub fn apply(
        &self,
        change: RouteChange,
        scope: Scope,
        reason: String,
        actor: String,
        dry_run: bool,
    ) -> Result<ApplyResult, RoutingError> {
        let now = time::OffsetDateTime::now_utc();
        let mut guard = self.inner.write().unwrap_or_else(|e| e.into_inner());
        let before: BTreeSet<IpNet> = guard.routes.iter().map(|r| r.prefix).collect();

        let mut candidate = Inner {
            intents: guard.intents.clone(),
            routes: Vec::new(),
            policies: guard.policies.clone(),
        };
        let generation = self.generation() + 1;
        let warnings = apply_change(
            &mut candidate,
            &change,
            scope,
            &reason,
            &actor,
            self.network,
            self.local,
            generation,
            now,
        )?;
        let fib = candidate.rebuild_fib(self.ecmp_max, generation, now);
        let after: BTreeSet<IpNet> = candidate.routes.iter().map(|r| r.prefix).collect();
        let added: Vec<IpNet> = after.difference(&before).copied().collect();
        let removed: Vec<IpNet> = before.difference(&after).copied().collect();

        if candidate.routes.len() > self.max_routes {
            return Err(RoutingError::Limit(self.max_routes));
        }

        if !dry_run {
            *guard = candidate;
            self.generation.store(generation, Ordering::Relaxed);
            self.fib.store(fib);
            let _ = self.changed.send(generation);
        }

        Ok(ApplyResult {
            generation: if dry_run {
                self.generation()
            } else {
                generation
            },
            added,
            removed,
            warnings,
            dry_run,
        })
    }

    /// Replace all controller-sourced routes with the given snapshot.
    /// Static/local routes are preserved (and win by admin distance).
    pub fn replace_controller_routes(&self, routes: Vec<RouteEntry>) -> Result<u64, RoutingError> {
        let now = time::OffsetDateTime::now_utc();
        let mut guard = self.inner.write().unwrap_or_else(|e| e.into_inner());
        guard
            .intents
            .retain(|i| i.entry.source != RouteSource::Controller);
        for mut entry in routes {
            if entry.source != RouteSource::Controller {
                entry.source = RouteSource::Controller;
            }
            entry.state = RouteState::Active;
            guard.intents.push(IntentRecord {
                entry: entry.clone(),
                scope: Scope::Network,
                reason: "controller snapshot".into(),
                created_by: "controller".into(),
                created_at: now,
            });
        }
        if guard.intents.len() > self.max_routes {
            return Err(RoutingError::Limit(self.max_routes));
        }
        let generation = self.generation() + 1;
        let fib = guard.rebuild_fib(self.ecmp_max, generation, now);
        self.generation.store(generation, Ordering::Relaxed);
        self.fib.store(fib);
        let _ = self.changed.send(generation);
        Ok(generation)
    }

    /// Replace all link-state-sourced routes (peer LSA / SPF results).
    pub fn replace_link_state_routes(&self, routes: Vec<RouteEntry>) -> Result<u64, RoutingError> {
        let now = time::OffsetDateTime::now_utc();
        let mut guard = self.inner.write().unwrap_or_else(|e| e.into_inner());
        guard
            .intents
            .retain(|i| i.entry.source != RouteSource::LinkState);
        for mut entry in routes {
            entry.source = RouteSource::LinkState;
            entry.state = RouteState::Active;
            guard.intents.push(IntentRecord {
                entry,
                scope: Scope::Network,
                reason: "link-state SPF".into(),
                created_by: "link-state".into(),
                created_at: now,
            });
        }
        if guard.intents.len() > self.max_routes {
            return Err(RoutingError::Limit(self.max_routes));
        }
        let generation = self.generation() + 1;
        let fib = guard.rebuild_fib(self.ecmp_max, generation, now);
        self.generation.store(generation, Ordering::Relaxed);
        self.fib.store(fib);
        let _ = self.changed.send(generation);
        Ok(generation)
    }

    pub fn delete(&self, id: RouteId, dry_run: bool) -> Result<ApplyResult, RoutingError> {
        self.apply(
            RouteChange::Delete { id },
            Scope::Local,
            "delete".into(),
            "local".into(),
            dry_run,
        )
    }

    pub fn pin(
        &self,
        prefix: IpNet,
        next_hop: NodeId,
        ttl_secs: Option<u64>,
        dry_run: bool,
    ) -> Result<ApplyResult, RoutingError> {
        self.apply(
            RouteChange::Pin {
                prefix,
                next_hop,
                ttl_secs,
            },
            Scope::Local,
            "pin".into(),
            "local".into(),
            dry_run,
        )
    }

    pub fn unpin(&self, prefix: IpNet, dry_run: bool) -> Result<ApplyResult, RoutingError> {
        self.apply(
            RouteChange::Unpin { prefix },
            Scope::Local,
            "unpin".into(),
            "local".into(),
            dry_run,
        )
    }

    pub fn drain(
        &self,
        node: NodeId,
        grace_secs: u64,
        dry_run: bool,
    ) -> Result<ApplyResult, RoutingError> {
        self.apply(
            RouteChange::Drain { node, grace_secs },
            Scope::Local,
            "drain".into(),
            "local".into(),
            dry_run,
        )
    }

    pub fn routes(&self, view: RouteView) -> Vec<RouteEntry> {
        match view {
            RouteView::Intent => {
                let guard = self.inner.read().unwrap_or_else(|e| e.into_inner());
                guard.intents.iter().map(|i| i.entry.clone()).collect()
            }
            RouteView::Rib => {
                let guard = self.inner.read().unwrap_or_else(|e| e.into_inner());
                guard.routes.clone()
            }
            RouteView::Fib => Vec::new(),
        }
    }

    pub fn fib_view(&self) -> Vec<FibViewEntry> {
        self.fib
            .load()
            .entries()
            .into_iter()
            .map(|(prefix, entry)| FibViewEntry {
                prefix,
                next_hops: entry
                    .next_hops
                    .iter()
                    .map(|h| FibViewHop {
                        node: h.node,
                        weight: h.weight,
                        path_hint: h.path_hint,
                    })
                    .collect(),
                source: entry.source,
            })
            .collect()
    }

    pub fn lookup(&self, dst: IpAddr) -> Option<FibEntry> {
        self.fib.load().lookup(dst).cloned()
    }

    pub fn explain(&self, dst: IpAddr) -> Explain {
        let guard = self.inner.read().unwrap_or_else(|e| e.into_inner());
        let now = time::OffsetDateTime::now_utc();
        let matching: Vec<&RouteEntry> = guard
            .routes
            .iter()
            .filter(|r| r.prefix.contains(&dst) && r.is_active_at(now))
            .collect();
        if matching.is_empty() {
            return Explain {
                dst,
                selected: None,
                candidates: Vec::new(),
                generation: self.generation(),
            };
        }
        let max_len = matching
            .iter()
            .map(|r| r.prefix.prefix_len())
            .max()
            .unwrap_or(0);
        let mut candidates_routes: Vec<&RouteEntry> = matching
            .into_iter()
            .filter(|r| r.prefix.prefix_len() == max_len)
            .collect();
        if candidates_routes.iter().any(|r| r.pin) {
            candidates_routes.retain(|r| r.pin);
        }
        let best = candidates_routes
            .iter()
            .min_by_key(|r| (r.admin_distance, std::cmp::Reverse(r.local_pref), r.metric));
        let selected = best.map(|r| (*r).clone());
        let candidates = candidates_routes
            .iter()
            .map(|r| {
                let eligible = best.is_some_and(|b| b.id == r.id);
                ExplainCandidate {
                    route: (*r).clone(),
                    eligible,
                    reason: if eligible {
                        "selected".into()
                    } else {
                        "higher admin distance/local_pref/metric".into()
                    },
                }
            })
            .collect();
        Explain {
            dst,
            selected,
            candidates,
            generation: self.generation(),
        }
    }

    pub fn expire(&self) -> Result<u64, RoutingError> {
        let now = time::OffsetDateTime::now_utc();
        let mut guard = self.inner.write().unwrap_or_else(|e| e.into_inner());
        let before = guard.intents.len();
        guard
            .intents
            .retain(|i| i.entry.expires_at.map(|t| t > now).unwrap_or(true));
        if guard.intents.len() == before {
            return Ok(self.generation());
        }
        let generation = self.generation() + 1;
        let fib = guard.rebuild_fib(self.ecmp_max, generation, now);
        self.generation.store(generation, Ordering::Relaxed);
        self.fib.store(fib);
        let _ = self.changed.send(generation);
        Ok(generation)
    }

    pub fn export(&self) -> Result<Vec<IntentRecord>, RoutingError> {
        let guard = self.inner.read().unwrap_or_else(|e| e.into_inner());
        Ok(guard.intents.clone())
    }

    pub fn import(&self, mut intents: Vec<IntentRecord>) -> Result<u64, RoutingError> {
        let now = time::OffsetDateTime::now_utc();
        intents.retain(|i| {
            !matches!(
                i.entry.source,
                RouteSource::Controller | RouteSource::LinkState
            )
        });
        let mut guard = self.inner.write().unwrap_or_else(|e| e.into_inner());
        guard.intents = intents;
        if guard.intents.len() > self.max_routes {
            return Err(RoutingError::Limit(self.max_routes));
        }
        let generation = self.generation() + 1;
        let fib = guard.rebuild_fib(self.ecmp_max, generation, now);
        self.generation.store(generation, Ordering::Relaxed);
        self.fib.store(fib);
        let _ = self.changed.send(generation);
        Ok(generation)
    }

    pub fn save(&self, path: impl AsRef<Path>) -> Result<(), RoutingError> {
        let mut intents = self.export()?;
        intents.retain(|i| {
            !matches!(
                i.entry.source,
                RouteSource::Controller | RouteSource::LinkState
            )
        });
        let json =
            serde_json::to_vec_pretty(&intents).map_err(|e| RoutingError::Json(e.to_string()))?;
        std::fs::write(path, json).map_err(|e| RoutingError::Io(e.to_string()))
    }

    pub fn load(&self, path: impl AsRef<Path>) -> Result<(), RoutingError> {
        let path = path.as_ref();
        if !path.exists() {
            return Ok(());
        }
        let data = std::fs::read(path).map_err(|e| RoutingError::Io(e.to_string()))?;
        let intents: Vec<IntentRecord> =
            serde_json::from_slice(&data).map_err(|e| RoutingError::Json(e.to_string()))?;
        self.import(intents)?;
        Ok(())
    }
}

#[allow(clippy::too_many_arguments)]
fn apply_change(
    inner: &mut Inner,
    change: &RouteChange,
    scope: Scope,
    reason: &str,
    actor: &str,
    network: NetworkId,
    local: NodeId,
    generation: u64,
    now: time::OffsetDateTime,
) -> Result<Vec<String>, RoutingError> {
    let mut warnings = Vec::new();
    match change {
        RouteChange::UpsertStatic(upsert) => {
            inner.intents.retain(|i| {
                !(i.entry.prefix == upsert.prefix
                    && matches!(i.entry.source, RouteSource::Static)
                    && i.entry.next_hop == upsert.via)
            });
            let mut entry = RouteEntry::new(
                network,
                upsert.prefix,
                RouteSource::Static,
                local,
                upsert.via,
            );
            entry.id = RouteId::new();
            entry.admin_distance = upsert.admin_distance.unwrap_or(1);
            entry.local_pref = upsert.local_pref.unwrap_or(0);
            entry.metric = upsert.metric.unwrap_or(0);
            entry.weight = upsert.weight.unwrap_or(1);
            entry.pin = upsert.pin;
            entry.state = RouteState::Active;
            entry.generation = generation;
            entry.expires_at = upsert.expires_at;
            entry.attrs = upsert.attrs.clone();
            inner.intents.push(IntentRecord {
                entry,
                scope,
                reason: reason.to_string(),
                created_by: actor.to_string(),
                created_at: now,
            });
        }
        RouteChange::Delete { id } => {
            let before = inner.intents.len();
            inner.intents.retain(|i| i.entry.id != *id);
            if inner.intents.len() == before {
                return Err(RoutingError::NotFound(*id));
            }
        }
        RouteChange::Pin {
            prefix,
            next_hop,
            ttl_secs,
        } => {
            inner
                .intents
                .retain(|i| !(i.entry.prefix == *prefix && i.entry.pin));
            let mut entry =
                RouteEntry::new(network, *prefix, RouteSource::Static, local, *next_hop);
            entry.admin_distance = 1;
            entry.pin = true;
            entry.generation = generation;
            entry.expires_at = ttl_secs.map(|s| now + time::Duration::seconds(s as i64));
            inner.intents.push(IntentRecord {
                entry,
                scope,
                reason: reason.to_string(),
                created_by: actor.to_string(),
                created_at: now,
            });
            warnings.push("pin is local to this node".into());
        }
        RouteChange::Unpin { prefix } => {
            inner
                .intents
                .retain(|i| !(i.entry.prefix == *prefix && i.entry.pin));
        }
        RouteChange::Drain { node, grace_secs } => {
            let _ = grace_secs;
            inner.intents.retain(|i| i.entry.next_hop != *node);
            warnings.push("drain removes all local intents via the node".into());
        }
        RouteChange::Reset { prefix } => {
            if let Some(prefix) = prefix {
                inner.intents.retain(|i| {
                    !(i.entry.prefix == *prefix && matches!(i.entry.source, RouteSource::Static))
                });
            } else {
                inner
                    .intents
                    .retain(|i| !matches!(i.entry.source, RouteSource::Static));
            }
        }
    }
    Ok(warnings)
}

fn apply_policies(routes: Vec<RouteEntry>, policies: &[RoutePolicy]) -> Vec<RouteEntry> {
    if policies.is_empty() {
        return routes;
    }
    let mut ordered: Vec<&RoutePolicy> = policies.iter().collect();
    ordered.sort_by_key(|p| p.priority);
    let mut out = Vec::with_capacity(routes.len());
    for mut route in routes {
        let mut denied = false;
        for policy in &ordered {
            if !policy_matches(&policy.match_, &route) {
                continue;
            }
            match &policy.action {
                Action::Deny => {
                    denied = true;
                    break;
                }
                Action::Accept => break,
                Action::SetAdminDistance { value } => route.admin_distance = *value,
                Action::SetLocalPref { value } => route.local_pref = *value,
                Action::SetMetric { value } => route.metric = *value,
                Action::SetPathHint { .. } => {}
                Action::SetWeight { value } => route.weight = *value,
            }
        }
        if !denied {
            out.push(route);
        }
    }
    out
}

fn policy_matches(m: &Match, route: &RouteEntry) -> bool {
    if let Some(prefix) = m.prefix
        && prefix != route.prefix
    {
        return false;
    }
    if let Some(peer) = m.peer
        && peer != route.next_hop
    {
        return false;
    }
    if let Some(tag) = &m.tag
        && !route.attrs.tags.iter().any(|t| t == tag)
    {
        return false;
    }
    if let Some(source) = m.source
        && source != route.source
    {
        return false;
    }
    if let Some(zone) = &m.zone
        && route.attrs.zone.as_deref() != Some(zone.as_str())
    {
        return false;
    }
    if let Some(region) = &m.region
        && route.attrs.region.as_deref() != Some(region.as_str())
    {
        return false;
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    fn local() -> NodeId {
        NodeId::new([1; 32])
    }

    fn peer(n: u8) -> NodeId {
        NodeId::new([n; 32])
    }

    fn engine() -> RouteEngine {
        RouteEngine::new(NetworkId::new(), local(), 8, 100)
    }

    #[test]
    fn add_lookup_delete() {
        let e = engine();
        let prefix: IpNet = "10.0.0.0/16".parse().unwrap();
        let r = e
            .add_static(prefix, peer(2), None, Some(10), None, false, None, "test")
            .unwrap();
        assert_eq!(r.generation, 2);
        assert_eq!(
            e.lookup("10.0.0.5".parse().unwrap()).unwrap().next_hops[0].node,
            peer(2)
        );
        let id = e.routes(RouteView::Intent)[0].id;
        e.delete(id, false).unwrap();
        assert!(e.lookup("10.0.0.5".parse().unwrap()).is_none());
    }

    #[test]
    fn dry_run_does_not_commit() {
        let e = engine();
        let _ = e
            .add_static(
                "10.0.0.0/16".parse().unwrap(),
                peer(2),
                None,
                Some(10),
                None,
                false,
                None,
                "test",
            )
            .unwrap();
        let apply = e
            .apply(
                RouteChange::UpsertStatic(UpsertStatic {
                    prefix: "10.1.0.0/16".parse().unwrap(),
                    via: peer(3),
                    admin_distance: None,
                    local_pref: None,
                    metric: Some(10),
                    weight: None,
                    pin: false,
                    expires_at: None,
                    attrs: Default::default(),
                }),
                Scope::Local,
                "dry".into(),
                "test".into(),
                true,
            )
            .unwrap();
        assert!(apply.dry_run);
        assert!(e.lookup("10.1.0.5".parse().unwrap()).is_none());
    }

    #[test]
    fn pin_wins_and_unpin_restores() {
        let e = engine();
        let prefix: IpNet = "10.0.0.0/16".parse().unwrap();
        e.add_static(prefix, peer(2), None, Some(1), None, false, None, "a")
            .unwrap();
        e.add_static(prefix, peer(3), None, Some(50), None, false, None, "b")
            .unwrap();
        e.pin(prefix, peer(3), None, false).unwrap();
        assert_eq!(
            e.lookup("10.0.0.1".parse().unwrap()).unwrap().next_hops[0].node,
            peer(3)
        );
        e.unpin(prefix, false).unwrap();
        let nodes: Vec<_> = e
            .lookup("10.0.0.1".parse().unwrap())
            .unwrap()
            .next_hops
            .iter()
            .map(|h| h.node)
            .collect();
        assert!(nodes.contains(&peer(2)));
    }

    #[test]
    fn explain_reports_candidates() {
        let e = engine();
        let prefix: IpNet = "10.0.0.0/16".parse().unwrap();
        e.add_static(prefix, peer(2), None, Some(10), None, false, None, "a")
            .unwrap();
        e.add_static(prefix, peer(3), None, Some(20), None, false, None, "b")
            .unwrap();
        let ex = e.explain("10.0.0.1".parse().unwrap());
        assert!(ex.selected.is_some());
        assert_eq!(ex.candidates.len(), 2);
    }

    #[test]
    fn generation_changes_are_observable() {
        let e = engine();
        let mut rx = e.subscribe();
        e.add_static(
            "10.0.0.0/16".parse().unwrap(),
            peer(2),
            None,
            Some(10),
            None,
            false,
            None,
            "test",
        )
        .unwrap();
        assert!(rx.has_changed().unwrap());
        let generation = *rx.borrow_and_update();
        assert_eq!(generation, e.generation());
    }

    #[test]
    fn route_policy_can_deny_and_set_local_pref() {
        let e = engine();
        let prefix: IpNet = "10.0.0.0/16".parse().unwrap();
        e.add_static(prefix, peer(2), None, Some(10), None, false, None, "static")
            .unwrap();
        e.set_policies(vec![RoutePolicy {
            id: "deny".into(),
            priority: 1,
            match_: Match {
                prefix: Some(prefix),
                ..Default::default()
            },
            action: Action::Deny,
        }])
        .unwrap();
        assert!(e.lookup("10.0.0.1".parse().unwrap()).is_none());

        e.set_policies(vec![RoutePolicy {
            id: "pref".into(),
            priority: 1,
            match_: Match {
                prefix: Some(prefix),
                ..Default::default()
            },
            action: Action::SetLocalPref { value: 999 },
        }])
        .unwrap();
        let entry = e.lookup("10.0.0.1".parse().unwrap()).unwrap();
        assert_eq!(entry.next_hops.len(), 1);
    }

    #[test]
    fn expired_route_is_removed_by_expire() {
        let e = engine();
        let prefix: IpNet = "10.5.0.0/16".parse().unwrap();
        e.add_static(
            prefix,
            peer(2),
            None,
            None,
            None,
            false,
            Some(time::OffsetDateTime::now_utc() + time::Duration::seconds(1)),
            "ttl",
        )
        .unwrap();
        assert!(e.lookup("10.5.1.1".parse().unwrap()).is_some());
        std::thread::sleep(std::time::Duration::from_millis(1200));
        e.expire().unwrap();
        assert!(e.lookup("10.5.1.1".parse().unwrap()).is_none());
    }

    #[test]
    fn policy_zone_match_targets_the_route_zone() {
        let e = engine();
        let prefix: IpNet = "10.6.0.0/16".parse().unwrap();
        e.set_policies(vec![RoutePolicy {
            id: "deny-z1".into(),
            priority: 1,
            match_: Match {
                zone: Some("az-a".into()),
                ..Default::default()
            },
            action: Action::Deny,
        }])
        .unwrap();
        let attrs = RouteAttributes {
            zone: Some("az-a".into()),
            ..Default::default()
        };
        e.add_static_with_attrs(
            prefix,
            peer(2),
            None,
            None,
            None,
            None,
            false,
            None,
            attrs,
            "zone",
        )
        .unwrap();
        assert!(e.lookup("10.6.1.1".parse().unwrap()).is_none());

        let other: IpNet = "10.7.0.0/16".parse().unwrap();
        let attrs = RouteAttributes {
            zone: Some("az-b".into()),
            ..Default::default()
        };
        e.add_static_with_attrs(
            other,
            peer(2),
            None,
            None,
            None,
            None,
            false,
            None,
            attrs,
            "zone",
        )
        .unwrap();
        assert!(e.lookup("10.7.1.1".parse().unwrap()).is_some());
    }

    #[test]
    fn controller_routes_replace_without_touching_static() {
        let e = engine();
        e.add_static(
            "10.0.0.0/16".parse().unwrap(),
            peer(2),
            None,
            Some(10),
            None,
            false,
            None,
            "static",
        )
        .unwrap();
        let mut controller = RouteEntry::new(
            e.network,
            "192.168.50.0/24".parse().unwrap(),
            RouteSource::Controller,
            peer(9),
            peer(3),
        );
        controller.admin_distance = 20;
        controller.metric = 10;
        e.replace_controller_routes(vec![controller]).unwrap();
        assert!(e.lookup("192.168.50.1".parse().unwrap()).is_some());
        assert!(e.lookup("10.0.0.1".parse().unwrap()).is_some());

        e.replace_controller_routes(Vec::new()).unwrap();
        assert!(e.lookup("192.168.50.1".parse().unwrap()).is_none());
        assert!(e.lookup("10.0.0.1".parse().unwrap()).is_some());
    }

    #[test]
    fn persist_roundtrip() {
        let e = engine();
        let prefix: IpNet = "10.0.0.0/16".parse().unwrap();
        e.add_static(prefix, peer(2), None, Some(10), None, false, None, "a")
            .unwrap();
        let dir =
            std::env::temp_dir().join(format!("stellaris-routing-test-{}", uuid::Uuid::now_v7()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("intents.json");
        e.save(&path).unwrap();
        let e2 = engine();
        e2.load(&path).unwrap();
        assert_eq!(
            e2.lookup("10.0.0.1".parse().unwrap()).unwrap().next_hops[0].node,
            peer(2)
        );
        std::fs::remove_dir_all(dir).unwrap();
    }
}
