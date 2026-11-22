use std::net::IpAddr;

use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode, header::AUTHORIZATION};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use ipnet::IpNet;
use serde::Deserialize;
use serde_json::{Value, json};
use stellaris_routing::{ApplyResult, RouteView};
use stellaris_types::{NodeId, RouteChange, RouteId, Scope};

use crate::policy::{Policy, PolicyFile};
use crate::{AgentState, PeerState};

#[derive(Debug)]
pub struct ApiError {
    status: StatusCode,
    code: &'static str,
    message: String,
}

impl ApiError {
    fn new(status: StatusCode, code: &'static str, message: impl Into<String>) -> Self {
        Self {
            status,
            code,
            message: message.into(),
        }
    }

    fn bad_request(message: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, "INVALID_ARGUMENT", message)
    }

    fn unauthorized() -> Self {
        Self::new(
            StatusCode::UNAUTHORIZED,
            "UNAUTHENTICATED",
            "missing or invalid token",
        )
    }

    fn internal(message: impl Into<String>) -> Self {
        Self::new(StatusCode::INTERNAL_SERVER_ERROR, "INTERNAL", message)
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (
            self.status,
            Json(json!({
                "code": self.code,
                "message": self.message,
            })),
        )
            .into_response()
    }
}

fn bearer(headers: &HeaderMap) -> Result<&str, ApiError> {
    let value = headers
        .get(AUTHORIZATION)
        .ok_or_else(ApiError::unauthorized)?;
    let value = value.to_str().map_err(|_| ApiError::unauthorized())?;
    value
        .strip_prefix("Bearer ")
        .ok_or_else(ApiError::unauthorized)
}

fn token_allowed(state: &AgentState, token: &str) -> bool {
    state.config.api.token.as_deref() == Some(token)
        || state.config.api.previous_tokens.iter().any(|t| t == token)
}

fn authorize_write(state: &AgentState, headers: &HeaderMap) -> Result<(), ApiError> {
    if state.config.api.token.is_none() && state.config.api.previous_tokens.is_empty() {
        return Ok(());
    }
    if token_allowed(state, bearer(headers)?) {
        Ok(())
    } else {
        Err(ApiError::unauthorized())
    }
}

fn authorize_read(state: &AgentState, headers: &HeaderMap) -> Result<(), ApiError> {
    if state.config.api.token.is_none()
        && state.config.api.previous_tokens.is_empty()
        && state.config.api.read_token.is_none()
    {
        return Ok(());
    }
    let token = bearer(headers)?;
    if token_allowed(state, token) || state.config.api.read_token.as_deref() == Some(token) {
        return Ok(());
    }
    Err(ApiError::unauthorized())
}

pub fn router(state: AgentState) -> Router {
    Router::new()
        .route("/", get(ui))
        .route("/ui", get(ui))
        .route("/healthz", get(healthz))
        .route("/v1/status", get(status))
        .route("/metrics", get(metrics))
        .route("/v1/peers", get(peers))
        .route("/v1/routes", get(routes).post(apply))
        .route("/v1/routes/lookup", get(lookup))
        .route("/v1/routes/explain", get(explain))
        .route("/v1/routes/pin", post(pin))
        .route("/v1/routes/unpin", post(unpin))
        .route("/v1/routes/drain", post(drain))
        .route("/v1/routes/reset", post(reset))
        .route("/v1/routes/{id}", delete(delete_route))
        .route("/v1/policy", get(get_policy).put(put_policy))
        .with_state(state)
}

async fn ui() -> Html<&'static str> {
    Html(include_str!("../static/index.html"))
}

async fn healthz() -> &'static str {
    "ok"
}

async fn get_policy(
    State(state): State<AgentState>,
    headers: HeaderMap,
) -> Result<Json<PolicyFile>, ApiError> {
    authorize_read(&state, &headers)?;
    let file = state
        .policy
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .file();
    Ok(Json(file))
}

async fn put_policy(
    State(state): State<AgentState>,
    headers: HeaderMap,
    Json(file): Json<PolicyFile>,
) -> Result<Json<PolicyFile>, ApiError> {
    authorize_write(&state, &headers)?;
    file.validate().map_err(ApiError::bad_request)?;
    let policy = Policy::from_file(file.clone());
    let path = state.policy_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| {
            ApiError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "IO",
                format!("create {}: {e}", parent.display()),
            )
        })?;
    }
    let bytes = serde_json::to_vec_pretty(&file).map_err(|e| {
        ApiError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "SERIALIZE",
            e.to_string(),
        )
    })?;
    std::fs::write(&path, bytes).map_err(|e| {
        ApiError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "IO",
            format!("write {}: {e}", path.display()),
        )
    })?;
    *state.policy.write().unwrap_or_else(|e| e.into_inner()) = policy;
    Ok(Json(file))
}

async fn status(
    State(state): State<AgentState>,
    headers: HeaderMap,
) -> Result<Json<Value>, ApiError> {
    authorize_read(&state, &headers)?;
    Ok(Json(json!({
        "node_id": state.node_id.to_string(),
        "node_name": state.config.node.name,
        "zone": state.config.node.zone,
        "acl_rules": state.policy.read().unwrap_or_else(|e| e.into_inner()).acl_rules(),
        "acl_hits": state.policy.read().unwrap_or_else(|e| e.into_inner()).acl_hits(),
        "qos_classes": state.policy.read().unwrap_or_else(|e| e.into_inner()).qos_classes(),
        "stats": state.stats.snapshot(),
        "network_id": state.network.to_string(),
        "network_name": state.config.network.name,
        "cidr": state.config.network.cidr.to_string(),
        "role": "member",
        "control_mode": "none",
        "rib_mode": state.config.routing.rib_mode,
        "generation": state.routes.generation(),
        "uptime_secs": state.started_at.elapsed().as_secs(),
        "peers": {
            "total": state.peers.total(),
            "connected": state.peers.connected_count(),
        },
        "routes": {
            "fib": state.routes.fib_view().len(),
        },
        "dataplane": {
            "enabled": state.config.dataplane.enabled,
            "tun_name": state.config.dataplane.tun_name,
            "mtu": state.config.dataplane.mtu,
        }
    })))
}

async fn metrics(
    State(state): State<AgentState>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, ApiError> {
    authorize_read(&state, &headers)?;
    let stats = &state.stats;
    let load = |c: &std::sync::atomic::AtomicU64| c.load(std::sync::atomic::Ordering::Relaxed);
    let body = format!(
        "# HELP stellaris_acl_denied_total ACL denied packets\n\
# TYPE stellaris_acl_denied_total counter\n\
stellaris_acl_denied_total {}\n\
# TYPE stellaris_qos_rate_limited_total counter\n\
stellaris_qos_rate_limited_total {}\n\
# TYPE stellaris_queue_dropped_total counter\n\
stellaris_queue_dropped_total {}\n\
# TYPE stellaris_delivered_total counter\n\
stellaris_delivered_total {}\n\
# TYPE stellaris_forwarded_total counter\n\
stellaris_forwarded_total {}\n\
# TYPE stellaris_fib_routes gauge\n\
stellaris_fib_routes {}\n\
# TYPE stellaris_peers gauge\n\
stellaris_peers_total {}\n\
stellaris_peers_connected {}\n\
# TYPE stellaris_peer_path_changes_total counter\n\
stellaris_peer_path_changes_total {}\n",
        load(&stats.acl_denied),
        load(&stats.qos_rate_limited),
        load(&stats.queue_dropped),
        load(&stats.delivered),
        load(&stats.forwarded),
        state.routes.fib_view().len(),
        state.peers.total(),
        state.peers.connected_count(),
        state
            .peers
            .list()
            .iter()
            .map(|peer| peer.path_changes)
            .sum::<u64>(),
    );
    Ok((
        [(
            axum::http::header::CONTENT_TYPE,
            "text/plain; version=0.0.4",
        )],
        body,
    ))
}

async fn peers(
    State(state): State<AgentState>,
    headers: HeaderMap,
) -> Result<Json<Vec<PeerState>>, ApiError> {
    authorize_read(&state, &headers)?;
    Ok(Json(state.peers.list()))
}

#[derive(Debug, Deserialize)]
struct RoutesQuery {
    #[serde(default)]
    view: Option<String>,
}

async fn routes(
    State(state): State<AgentState>,
    headers: HeaderMap,
    Query(query): Query<RoutesQuery>,
) -> Result<Json<Value>, ApiError> {
    authorize_read(&state, &headers)?;
    let view = match query.view.as_deref().unwrap_or("rib") {
        "intent" => RouteView::Intent,
        "rib" => RouteView::Rib,
        "fib" => RouteView::Fib,
        other => return Err(ApiError::bad_request(format!("unknown view: {other}"))),
    };
    let generation = state.routes.generation();
    if view == RouteView::Fib {
        return Ok(Json(json!({
            "generation": generation,
            "view": "fib",
            "routes": state.routes.fib_view(),
        })));
    }
    Ok(Json(json!({
        "generation": generation,
        "view": if view == RouteView::Intent { "intent" } else { "rib" },
        "routes": state.routes.routes(view),
    })))
}

#[derive(Debug, Deserialize)]
struct DstQuery {
    dst: String,
}

fn parse_dst(query: &DstQuery) -> Result<IpAddr, ApiError> {
    query
        .dst
        .parse()
        .map_err(|e| ApiError::bad_request(format!("invalid dst {}: {e}", query.dst)))
}

async fn lookup(
    State(state): State<AgentState>,
    headers: HeaderMap,
    Query(query): Query<DstQuery>,
) -> Result<Json<Value>, ApiError> {
    authorize_read(&state, &headers)?;
    let dst = parse_dst(&query)?;
    let entry = state.routes.lookup(dst);
    Ok(Json(json!({
        "dst": dst.to_string(),
        "matched": entry.is_some(),
        "entry": entry,
        "generation": state.routes.generation(),
    })))
}

async fn explain(
    State(state): State<AgentState>,
    headers: HeaderMap,
    Query(query): Query<DstQuery>,
) -> Result<Json<Value>, ApiError> {
    authorize_read(&state, &headers)?;
    let dst = parse_dst(&query)?;
    Ok(Json(
        serde_json::to_value(state.routes.explain(dst))
            .map_err(|e| ApiError::internal(e.to_string()))?,
    ))
}

#[derive(Debug, Deserialize)]
struct ApplyRequest {
    change: RouteChange,
    #[serde(default)]
    scope: Scope,
    #[serde(default)]
    dry_run: bool,
    #[serde(default)]
    reason: String,
}

async fn apply(
    State(state): State<AgentState>,
    headers: HeaderMap,
    Json(req): Json<ApplyRequest>,
) -> Result<Json<ApplyResult>, ApiError> {
    authorize_write(&state, &headers)?;
    if req.scope == Scope::Network {
        return Err(ApiError::bad_request(
            "scope=network requires a controller; MVP supports local scope only",
        ));
    }
    let result = state
        .routes
        .apply(req.change, req.scope, req.reason, "api".into(), req.dry_run)
        .map_err(|e| ApiError::bad_request(e.to_string()))?;
    if !req.dry_run {
        state.save_routes();
    }
    Ok(Json(result))
}

async fn delete_route(
    State(state): State<AgentState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<ApplyResult>, ApiError> {
    authorize_write(&state, &headers)?;
    let id: RouteId = id
        .parse()
        .map_err(|e| ApiError::bad_request(format!("invalid route id: {e}")))?;
    let result = state
        .routes
        .delete(id, false)
        .map_err(|e| ApiError::bad_request(e.to_string()))?;
    state.save_routes();
    Ok(Json(result))
}

#[derive(Debug, Deserialize)]
struct PinRequest {
    prefix: String,
    next_hop: String,
    ttl_secs: Option<u64>,
    #[serde(default)]
    dry_run: bool,
}

async fn pin(
    State(state): State<AgentState>,
    headers: HeaderMap,
    Json(req): Json<PinRequest>,
) -> Result<Json<ApplyResult>, ApiError> {
    authorize_write(&state, &headers)?;
    let prefix: IpNet = req
        .prefix
        .parse()
        .map_err(|e| ApiError::bad_request(format!("invalid prefix: {e}")))?;
    let next_hop: NodeId = req
        .next_hop
        .parse()
        .map_err(|e| ApiError::bad_request(format!("invalid next_hop: {e}")))?;
    let result = state
        .routes
        .pin(prefix, next_hop, req.ttl_secs, req.dry_run)
        .map_err(|e| ApiError::bad_request(e.to_string()))?;
    if !req.dry_run {
        state.save_routes();
    }
    Ok(Json(result))
}

#[derive(Debug, Deserialize)]
struct PrefixRequest {
    prefix: String,
    #[serde(default)]
    dry_run: bool,
}

async fn unpin(
    State(state): State<AgentState>,
    headers: HeaderMap,
    Json(req): Json<PrefixRequest>,
) -> Result<Json<ApplyResult>, ApiError> {
    authorize_write(&state, &headers)?;
    let prefix: IpNet = req
        .prefix
        .parse()
        .map_err(|e| ApiError::bad_request(format!("invalid prefix: {e}")))?;
    let result = state
        .routes
        .unpin(prefix, req.dry_run)
        .map_err(|e| ApiError::bad_request(e.to_string()))?;
    if !req.dry_run {
        state.save_routes();
    }
    Ok(Json(result))
}

#[derive(Debug, Deserialize)]
struct DrainRequest {
    node: String,
    #[serde(default = "default_grace")]
    grace_secs: u64,
    #[serde(default)]
    dry_run: bool,
}

fn default_grace() -> u64 {
    0
}

async fn drain(
    State(state): State<AgentState>,
    headers: HeaderMap,
    Json(req): Json<DrainRequest>,
) -> Result<Json<ApplyResult>, ApiError> {
    authorize_write(&state, &headers)?;
    let node: NodeId = req
        .node
        .parse()
        .map_err(|e| ApiError::bad_request(format!("invalid node: {e}")))?;
    let result = state
        .routes
        .drain(node, req.grace_secs, req.dry_run)
        .map_err(|e| ApiError::bad_request(e.to_string()))?;
    if !req.dry_run {
        state.save_routes();
    }
    Ok(Json(result))
}

#[derive(Debug, Deserialize)]
struct ResetRequest {
    prefix: Option<String>,
    #[serde(default)]
    dry_run: bool,
}

async fn reset(
    State(state): State<AgentState>,
    headers: HeaderMap,
    Json(req): Json<ResetRequest>,
) -> Result<Json<ApplyResult>, ApiError> {
    authorize_write(&state, &headers)?;
    let prefix = match req.prefix {
        Some(p) => Some(
            p.parse()
                .map_err(|e| ApiError::bad_request(format!("invalid prefix: {e}")))?,
        ),
        None => None,
    };
    let result = state
        .routes
        .apply(
            RouteChange::Reset { prefix },
            Scope::Local,
            "reset".into(),
            "api".into(),
            req.dry_run,
        )
        .map_err(|e| ApiError::bad_request(e.to_string()))?;
    if !req.dry_run {
        state.save_routes();
    }
    Ok(Json(result))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use http_body_util::BodyExt;
    use stellaris_types::Config;
    use tower::ServiceExt;

    fn state(token: Option<&str>) -> AgentState {
        let dir = std::env::temp_dir().join(format!("stellaris-api-test-{}", uuid::Uuid::now_v7()));
        std::fs::create_dir_all(&dir).unwrap();
        let token_line = token
            .map(|t| format!("token = \"{t}\""))
            .unwrap_or_default();
        let toml = format!(
            r#"
[node]
name = "a"
state_dir = "{}"
overlay_ip = "10.7.0.1"

[network]
name = "demo"
cidr = "10.7.0.0/16"

[api]
bind = "127.0.0.1:0"
{}
"#,
            dir.display(),
            token_line
        );
        AgentState::build(Config::from_toml(&toml).unwrap()).unwrap()
    }

    fn state_with_tokens(admin: &str, read: &str) -> AgentState {
        let dir = std::env::temp_dir().join(format!("stellaris-api-test-{}", uuid::Uuid::now_v7()));
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

[api]
bind = "127.0.0.1:0"
token = "{}"
read_token = "{}"
"#,
            dir.display(),
            admin,
            read
        );
        AgentState::build(Config::from_toml(&toml).unwrap()).unwrap()
    }

    fn state_with_rotation() -> AgentState {
        let dir = std::env::temp_dir().join(format!("stellaris-api-test-{}", uuid::Uuid::now_v7()));
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

[api]
bind = "127.0.0.1:0"
token = "new"
previous_tokens = ["old"]
"#,
            dir.display()
        );
        AgentState::build(Config::from_toml(&toml).unwrap()).unwrap()
    }

    async fn body_json(response: axum::response::Response) -> Value {
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        serde_json::from_slice(&bytes).unwrap()
    }

    #[tokio::test]
    async fn status_ok() {
        let app = router(state(None));
        let response = app
            .oneshot(
                axum::http::Request::builder()
                    .uri("/v1/status")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let json = body_json(response).await;
        assert_eq!(json["network_name"], "demo");
    }

    #[tokio::test]
    async fn previous_api_token_is_accepted() {
        let app = router(state_with_rotation());
        let response = app
            .oneshot(
                axum::http::Request::builder()
                    .uri("/v1/status")
                    .header("authorization", "Bearer old")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn read_token_cannot_mutate() {
        let app = router(state_with_tokens("admin", "read"));
        let read_status = app
            .clone()
            .oneshot(
                axum::http::Request::builder()
                    .uri("/v1/status")
                    .header("authorization", "Bearer read")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(read_status.status(), StatusCode::OK);

        let body = serde_json::json!({
            "acl": {"default_action": "allow", "rules": []},
            "qos": {"enabled": false, "classes": []}
        });
        let read_write = app
            .clone()
            .oneshot(
                axum::http::Request::builder()
                    .method("PUT")
                    .uri("/v1/policy")
                    .header("authorization", "Bearer read")
                    .header("content-type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(read_write.status(), StatusCode::UNAUTHORIZED);

        let admin_write = app
            .oneshot(
                axum::http::Request::builder()
                    .method("PUT")
                    .uri("/v1/policy")
                    .header("authorization", "Bearer admin")
                    .header("content-type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(admin_write.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn metrics_endpoint_exposes_counters() {
        let app = router(state(None));
        let response = app
            .oneshot(
                axum::http::Request::builder()
                    .uri("/metrics")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), 64 * 1024)
            .await
            .unwrap();
        let text = String::from_utf8(body.to_vec()).unwrap();
        assert!(text.contains("stellaris_acl_denied_total"));
        assert!(text.contains("stellaris_fib_routes"));
    }

    #[tokio::test]
    async fn policy_api_replaces_policy() {
        let app = router(state(None));
        let body = serde_json::json!({
            "acl": {
                "default_action": "allow",
                "rules": [{
                    "name": "deny-ssh",
                    "action": "deny",
                    "direction": "inbound",
                    "protocol": 6,
                    "dst_port": 22
                }]
            },
            "qos": {
                "enabled": true,
                "classes": [{
                    "name": "https",
                    "dscp": 46,
                    "rate_pps": 10,
                    "burst": 2
                }]
            }
        });
        let response = app
            .clone()
            .oneshot(
                axum::http::Request::builder()
                    .method("PUT")
                    .uri("/v1/policy")
                    .header("content-type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let response = app
            .oneshot(
                axum::http::Request::builder()
                    .uri("/v1/policy")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let json = body_json(response).await;
        assert_eq!(json["acl"]["rules"].as_array().unwrap().len(), 1);
        assert_eq!(json["qos"]["classes"].as_array().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn auth_required_when_token_set() {
        let app = router(state(Some("secret")));
        let response = app
            .clone()
            .oneshot(
                axum::http::Request::builder()
                    .uri("/v1/status")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        let response = app
            .oneshot(
                axum::http::Request::builder()
                    .uri("/v1/status")
                    .header("authorization", "Bearer secret")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }
}
