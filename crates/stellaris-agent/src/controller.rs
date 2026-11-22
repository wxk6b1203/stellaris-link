//! Stellaris controller: signed snapshots over HTTP and the iroh control protocol.
//!
//! HTTP is kept for compatibility/debugging; members can use `control.endpoint_id`
//! + `control.addrs` to use iroh instead. HA/openraft is still future work.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};

use anyhow::{Context, bail};
use axum::extract::{Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use hmac::{Hmac, Mac};
use ipnet::IpNet;
use iroh::{Endpoint, RelayMode, RelayUrl, SecretKey, endpoint::presets};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::Sha256;
use stellaris_linkstate::{LinkStateDb, Lsa};
use stellaris_types::{Config, NetworkId, NodeId, RouteEntry, RouteId, RouteSource, RouteState};
use uuid::Uuid;

#[derive(Clone)]
pub struct ControllerState {
    pub network: NetworkId,
    secret: Option<String>,
    routes: Arc<RwLock<Vec<RouteEntry>>>,
    link_state: Arc<RwLock<LinkStateDb>>,
    acks: Arc<RwLock<HashMap<NodeId, u64>>>,
    acks_path: PathBuf,
    pub epoch: u64,
    generation: Arc<AtomicU64>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Snapshot {
    pub network_id: String,
    pub epoch: u64,
    pub generation: u64,
    pub members: Vec<MemberView>,
    pub routes: Vec<RouteEntry>,
    /// HMAC-SHA256 over the snapshot payload when control.secret is set.
    #[serde(default)]
    pub signature: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MemberView {
    pub node_id: String,
    pub zone: Option<String>,
    pub overlay_ip: Option<std::net::IpAddr>,
    pub addrs: Vec<SocketAddr>,
    pub prefixes: Vec<String>,
    pub links: Vec<String>,
    pub last_seq: u64,
}

#[derive(Serialize)]
struct SnapshotPayload<'a> {
    network_id: &'a str,
    epoch: u64,
    generation: u64,
    members: &'a [MemberView],
    routes: &'a [RouteEntry],
}

/// Sign a snapshot. Kept public so members and tests use identical canonical bytes.
#[allow(clippy::too_many_arguments)]
pub fn snapshot_signature(
    secret: &str,
    network_id: &str,
    epoch: u64,
    generation: u64,
    members: &[MemberView],
    routes: &[RouteEntry],
) -> String {
    let payload = SnapshotPayload {
        network_id,
        epoch,
        generation,
        members,
        routes,
    };
    let bytes = serde_json::to_vec(&payload).unwrap_or_default();
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).expect("hmac key");
    mac.update(&bytes);
    hex::encode(mac.finalize().into_bytes())
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
            routes.push(entry);
        }
        let state_dir = PathBuf::from(&config.node.state_dir);
        let acks_path = state_dir.join("controller-acks.json");
        let acks = load_acks(&acks_path);
        let epoch = config.control.epoch.unwrap_or_else(now_epoch);
        Ok(Self {
            network,
            secret: config.control.secret.clone(),
            routes: Arc::new(RwLock::new(routes)),
            link_state: Arc::new(RwLock::new(LinkStateDb::new())),
            acks: Arc::new(RwLock::new(acks)),
            acks_path,
            epoch,
            generation: Arc::new(AtomicU64::new(1)),
        })
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
        Snapshot {
            network_id,
            epoch: self.epoch,
            generation,
            members,
            routes,
            signature,
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
        }
    }

    fn members(&self) -> Vec<MemberView> {
        let db = self.link_state.read().unwrap_or_else(|e| e.into_inner());
        let mut out: Vec<MemberView> = db
            .all()
            .map(|lsa| MemberView {
                node_id: lsa.origin.to_string(),
                zone: lsa.zone.clone(),
                overlay_ip: lsa.overlay_ip,
                addrs: lsa.addrs.clone(),
                prefixes: lsa.prefixes.iter().map(|p| p.prefix.to_string()).collect(),
                links: lsa.links.iter().map(|l| l.to.to_string()).collect(),
                last_seq: lsa.seq,
            })
            .collect();
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

    fn apply_lsa(&self, lsa: Lsa) -> bool {
        let changed = self
            .link_state
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .apply(lsa);
        if changed {
            self.generation.fetch_add(1, Ordering::Relaxed);
        }
        changed
    }

    fn authorized(&self, headers: &HeaderMap) -> bool {
        let provided = headers
            .get("x-stellaris-secret")
            .and_then(|v| v.to_str().ok());
        self.authorized_secret(provided)
    }

    pub fn authorized_secret(&self, provided: Option<&str>) -> bool {
        match self.secret.as_deref() {
            Some(expected) => provided == Some(expected),
            None => true,
        }
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
        self.persist_acks();
        Ok(())
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
        .route("/v1/status", get(status))
        .route("/v1/snapshot", get(snapshot))
        .route("/v1/routes", post(add_route))
        .route("/v1/lsa", post(apply_lsa))
        .route("/v1/ack", post(ack))
        .with_state(state)
}

async fn status(State(state): State<ControllerState>, headers: HeaderMap) -> Response {
    if !state.authorized(&headers) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    Json(json!({
        "network_id": state.network.to_string(),
        "epoch": state.epoch,
        "generation": state.generation.load(Ordering::Relaxed),
        "routes": state.routes.read().unwrap_or_else(|e| e.into_inner()).len(),
        "acks": state.acks.read().unwrap_or_else(|e| e.into_inner()).len(),
    }))
    .into_response()
}

#[derive(Debug, Deserialize)]
struct SnapshotQuery {
    node: Option<String>,
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
    Json(state.snapshot(local)).into_response()
}

async fn apply_lsa(
    State(state): State<ControllerState>,
    headers: HeaderMap,
    Json(lsa): Json<Lsa>,
) -> Response {
    if !state.authorized(&headers) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    let changed = state.apply_lsa(lsa);
    Json(json!({
        "changed": changed,
        "generation": state.generation.load(Ordering::Relaxed),
        "lsas": state.link_state.read().unwrap_or_else(|e| e.into_inner()).len(),
    }))
    .into_response()
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
    match state.record_ack(node, req.generation, req.epoch) {
        Ok(()) => Json(json!({"acked": req.generation, "node": node.to_string()})).into_response(),
        Err((code, message)) => (
            StatusCode::from_u16(code).unwrap_or(StatusCode::BAD_REQUEST),
            message,
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
    if !state.authorized(&headers) {
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
    let entry = state.add_route(prefix, via, req.metric);
    Json(json!({"generation": state.generation.load(Ordering::Relaxed), "route": entry}))
        .into_response()
}

pub async fn run(config: Config) -> anyhow::Result<()> {
    let state = ControllerState::from_config(&config)?;
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
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .with_context(|| format!("bind controller {addr}"))?;
    tracing::info!(%addr, network = %state.network, "stellaris controller started");
    axum::serve(listener, router(state))
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await
        .context("controller HTTP server")
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
        let response = dispatch_control(&state, request);
        crate::control_wire::write_frame(&mut send, &response).await?;
        let _ = send.finish();
    }
    Ok(())
}

fn dispatch_control(
    state: &ControllerState,
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
            Response::Snapshot {
                snapshot: state.snapshot(local),
            }
        }
        Request::Lsa { lsa, secret } => {
            if !state.authorized_secret(secret.as_deref()) {
                return Response::Error {
                    code: 401,
                    message: "unauthorized".into(),
                };
            }
            let changed = state.apply_lsa(lsa);
            Response::Ok {
                changed,
                generation: state.generation.load(Ordering::Relaxed),
                epoch: state.epoch,
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
            match state.record_ack(node, generation, epoch) {
                Ok(()) => Response::Ok {
                    changed: true,
                    generation,
                    epoch: state.epoch,
                },
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

    fn state() -> ControllerState {
        let toml = r#"
[node]
name = "ctrl"
role = "controller"

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
"#;
        ControllerState::from_config(&Config::from_toml(toml).unwrap()).unwrap()
    }

    async fn json(response: axum::response::Response) -> serde_json::Value {
        let body = response.into_body().collect().await.unwrap().to_bytes();
        serde_json::from_slice(&body).unwrap()
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
    fn link_state_snapshot_computes_routes() {
        let state = state();
        let a = stellaris_types::NodeId::new([1u8; 32]);
        let b = stellaris_types::NodeId::new([2u8; 32]);
        state.apply_lsa(Lsa {
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
        });
        state.apply_lsa(Lsa {
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
        });
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
}
