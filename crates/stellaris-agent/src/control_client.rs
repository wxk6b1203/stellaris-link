//! Controller client: HTTP (MVP) or iroh control protocol.
//!
//! Both transports carry the same signed snapshot / LSA / ACK data model.

use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::Context;
use iroh::{
    Endpoint, EndpointAddr, EndpointId, RelayMode, RelayUrl, SecretKey, TransportAddr,
    endpoint::presets,
};
use stellaris_linkstate::{Link, Lsa, Prefix};
use stellaris_types::NodeId;

use crate::AgentState;
use crate::control_wire::{CONTROL_ALPN, Request, Response};
use crate::controller::Snapshot;
use crate::transport::IrohTransport;

pub async fn run(
    state: AgentState,
    base: Option<String>,
    secret: Option<String>,
    transport: Option<std::sync::Arc<IrohTransport>>,
) {
    if state.config.control.endpoint_id.is_some() {
        run_iroh(state, secret, transport).await;
    } else if let Some(base) = base {
        run_http(state, base, secret, transport).await;
    }
}

async fn run_http(
    state: AgentState,
    base: String,
    secret: Option<String>,
    transport: Option<std::sync::Arc<IrohTransport>>,
) {
    let base = base.trim_end_matches('/').to_string();
    if base.is_empty() {
        return;
    }
    let client = match http_client(&state.config) {
        Ok(client) => client,
        Err(e) => {
            tracing::warn!(error = %e, "build controller HTTP client");
            return;
        }
    };
    let mut joined = state.config.control.join_token.is_none();
    let mut last_manifest = Instant::now() - Duration::from_secs(60);
    let mut last_generation = 0u64;
    let mut last_epoch = 0u64;
    let mut last_lsa = Instant::now() - Duration::from_secs(60);
    let mut seq = 0u64;
    loop {
        if !joined && state.config.control.join_token.is_some() {
            joined = try_join(&client, &base, &state, secret.as_deref()).await;
        }
        if !state.config.control.controller_keys.is_empty()
            && last_manifest.elapsed() >= Duration::from_secs(10)
            && try_manifest(&client, &base, &state, secret.as_deref()).await
        {
            last_manifest = Instant::now();
        }
        if last_lsa.elapsed() >= Duration::from_secs(10) {
            seq = seq.max(now_seq());
            let lsa = local_lsa(&state, seq);
            let mut request = client.post(format!("{base}/v1/lsa"));
            if let Some(secret) = &secret {
                request = request.header("x-stellaris-secret", secret);
            }
            match request.json(&lsa).send().await {
                Ok(response) if response.status().is_success() => {
                    last_lsa = Instant::now();
                }
                Ok(response) => {
                    tracing::debug!(%base, status = %response.status(), "controller rejected LSA")
                }
                Err(e) => tracing::debug!(%base, error = ?e, "controller LSA unreachable"),
            }
        }

        let mut snapshot = None;
        let mut request = client.get(format!("{base}/v1/snapshot?node={}", state.node_id));
        if let Some(secret) = &secret {
            request = request.header("x-stellaris-secret", secret);
        }
        match request.send().await {
            Ok(response) if response.status().is_success() => {
                match response.json::<Snapshot>().await {
                    Ok(candidate) => {
                        if verify_snapshot(&state, secret.as_deref(), &candidate) {
                            snapshot = Some(candidate);
                        } else {
                            tracing::warn!(%base, "controller snapshot rejected");
                        }
                    }
                    Err(e) => tracing::warn!(%base, error = %e, "invalid controller snapshot"),
                }
            }
            Ok(response) => {
                tracing::warn!(%base, status = %response.status(), "controller snapshot rejected")
            }
            Err(e) => tracing::debug!(%base, error = ?e, "controller unreachable"),
        }

        if let Some(snapshot) = snapshot
            && let Some((generation, epoch)) = apply_verified_snapshot(
                &state,
                snapshot,
                last_generation,
                &mut last_epoch,
                transport.as_ref(),
            )
        {
            last_generation = generation;
            let mut ack = client.post(format!("{base}/v1/ack"));
            if let Some(secret) = &secret {
                ack = ack.header("x-stellaris-secret", secret);
            }
            let _ = ack
                .json(&serde_json::json!({
                    "node": state.node_id.to_string(),
                    "generation": generation,
                    "epoch": epoch,
                }))
                .send()
                .await;
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
}

async fn run_iroh(
    state: AgentState,
    secret: Option<String>,
    transport: Option<std::sync::Arc<IrohTransport>>,
) {
    let Some(endpoint_hex) = state.config.control.endpoint_id.clone() else {
        return;
    };
    let controller: NodeId = match endpoint_hex.parse() {
        Ok(node) => node,
        Err(e) => {
            tracing::warn!(error = %e, "invalid control.endpoint_id");
            return;
        }
    };
    let remote = match EndpointId::from_bytes(controller.as_bytes()) {
        Ok(id) => id,
        Err(e) => {
            tracing::warn!(error = %e, "invalid controller endpoint");
            return;
        }
    };
    let addrs: Vec<TransportAddr> = state
        .config
        .control
        .addrs
        .iter()
        .map(|a| TransportAddr::Ip(*a))
        .collect();
    let addr = EndpointAddr::from_parts(remote, addrs);

    let key = SecretKey::from_bytes(&state.identity_secret);
    let mut builder = Endpoint::builder(presets::N0)
        .secret_key(key)
        .alpns(vec![CONTROL_ALPN.to_vec()]);
    if state.config.transport.disable_relay {
        builder = builder.relay_mode(RelayMode::Disabled);
    } else if !state.config.transport.relay_urls.is_empty() {
        let urls: Vec<RelayUrl> = state
            .config
            .transport
            .relay_urls
            .iter()
            .filter_map(|s| s.parse().ok())
            .collect();
        builder = builder.relay_mode(RelayMode::custom(urls));
    }
    let endpoint = match builder.bind().await {
        Ok(ep) => ep,
        Err(e) => {
            tracing::warn!(error = %e, "bind control endpoint");
            return;
        }
    };
    if !state.config.transport.disable_relay {
        endpoint.online().await;
    }

    let mut last_generation = 0u64;
    let mut last_epoch = 0u64;
    let mut last_lsa = Instant::now() - Duration::from_secs(60);
    let mut seq = 0u64;
    loop {
        let conn = match endpoint.connect(addr.clone(), CONTROL_ALPN).await {
            Ok(conn) => conn,
            Err(e) => {
                tracing::debug!(error = %e, "controller iroh unreachable");
                tokio::time::sleep(Duration::from_secs(2)).await;
                continue;
            }
        };
        loop {
            if last_lsa.elapsed() >= Duration::from_secs(10) {
                seq = seq.max(now_seq());
                let lsa = local_lsa(&state, seq);
                let signature = crate::lsa_auth::sign(&state.identity_secret, &lsa);
                let req = Request::Lsa {
                    lsa,
                    signature,
                    secret: secret.clone(),
                };
                match request(&conn, &req).await {
                    Ok(Response::Ok { .. }) => last_lsa = Instant::now(),
                    Ok(Response::Error { code, message }) => {
                        tracing::debug!(code, message, "controller rejected LSA")
                    }
                    Ok(_) => {}
                    Err(e) => {
                        tracing::debug!(error = %e, "LSA request failed");
                        break;
                    }
                }
            }
            let req = Request::Snapshot {
                node: Some(state.node_id.to_string()),
                secret: secret.clone(),
            };
            match request(&conn, &req).await {
                Ok(Response::Snapshot { snapshot }) => {
                    if verify_snapshot(&state, secret.as_deref(), &snapshot)
                        && let Some((generation, epoch)) = apply_verified_snapshot(
                            &state,
                            snapshot,
                            last_generation,
                            &mut last_epoch,
                            transport.as_ref(),
                        )
                    {
                        last_generation = generation;
                        let ack = Request::Ack {
                            node: state.node_id.to_string(),
                            generation,
                            epoch: Some(epoch),
                            secret: secret.clone(),
                        };
                        let _ = request(&conn, &ack).await;
                    }
                }
                Ok(Response::Error { code, message }) => {
                    tracing::warn!(code, message, "controller error");
                }
                Ok(Response::Ok { .. }) => {}
                Err(e) => {
                    tracing::debug!(error = %e, "controller iroh request failed");
                    break;
                }
            }
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
    }
}

async fn request(conn: &iroh::endpoint::Connection, request: &Request) -> anyhow::Result<Response> {
    let (mut send, mut recv) = conn.open_bi().await.context("open control stream")?;
    crate::control_wire::write_frame(&mut send, request).await?;
    let _ = send.finish();
    crate::control_wire::read_frame(&mut recv)
        .await?
        .context("empty controller response")
}

fn http_client(config: &stellaris_types::Config) -> anyhow::Result<reqwest::Client> {
    let mut builder = reqwest::Client::builder();
    if let Some(path) = &config.control.tls_ca {
        let pem = std::fs::read(path).with_context(|| format!("read control.tls_ca {path}"))?;
        let cert = reqwest::Certificate::from_pem(&pem).context("parse control.tls_ca")?;
        builder = builder.add_root_certificate(cert);
    }
    if config.control.tls_insecure {
        builder = builder.danger_accept_invalid_certs(true);
    }
    builder.build().context("build controller HTTP client")
}

async fn try_manifest(
    client: &reqwest::Client,
    base: &str,
    state: &AgentState,
    secret: Option<&str>,
) -> bool {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let mut request = client.get(format!("{base}/v1/manifest"));
    if let Some(secret) = secret {
        request = request.header("x-stellaris-secret", secret);
    }
    match request.send().await {
        Ok(response) if response.status().is_success() => {
            match response
                .json::<crate::controller::MembershipManifest>()
                .await
            {
                Ok(manifest) => {
                    if verify_manifest(state, &manifest, now).is_none() {
                        return false;
                    }
                    state.set_grants(&manifest.members);
                    tracing::debug!(
                        generation = manifest.generation,
                        members = manifest.members.len(),
                        "applied signed membership manifest"
                    );
                    true
                }
                Err(e) => {
                    tracing::warn!(%base, error = %e, "invalid manifest");
                    false
                }
            }
        }
        Ok(response) => {
            tracing::debug!(%base, status = %response.status(), "manifest rejected");
            false
        }
        Err(e) => {
            tracing::debug!(%base, error = %e, "manifest unreachable");
            false
        }
    }
}

fn verify_manifest(
    state: &AgentState,
    manifest: &crate::controller::MembershipManifest,
    now: u64,
) -> Option<NodeId> {
    if manifest.network_id != state.network.to_string() {
        tracing::warn!("manifest network mismatch");
        return None;
    }
    if manifest.expires_at <= now {
        tracing::warn!("controller manifest expired");
        return None;
    }
    let controller = manifest
        .controller
        .as_deref()
        .and_then(|s| s.parse::<NodeId>().ok())?;
    if !state
        .config
        .control
        .controller_keys
        .iter()
        .any(|key| key == &controller.to_string())
    {
        tracing::warn!(%controller, "untrusted manifest controller");
        return None;
    }
    let signature = manifest.signature.as_deref()?;
    let payload = crate::controller::manifest_payload_bytes(manifest);
    crate::controller::verify_ed25519(controller, &payload, signature).ok()?;
    Some(controller)
}

async fn try_join(
    client: &reqwest::Client,
    base: &str,
    state: &AgentState,
    secret: Option<&str>,
) -> bool {
    let Some(token) = state.config.control.join_token.as_deref() else {
        return true;
    };
    let Some(overlay) = state.config.node.overlay_ip else {
        tracing::warn!("join_token requires node.overlay_ip");
        return true;
    };
    let nonce = uuid::Uuid::now_v7().to_string();
    let payload = crate::controller::join_payload_bytes(
        &state.network.to_string(),
        &state.node_id.to_string(),
        &overlay.to_string(),
        token,
        &nonce,
    );
    let signature = crate::controller::sign_ed25519(&state.identity_secret, &payload);
    let mut request = client
        .post(format!("{base}/v1/join"))
        .json(&serde_json::json!({
            "node_id": state.node_id.to_string(),
            "overlay_ip": overlay.to_string(),
            "token": token,
            "nonce": nonce,
            "signature": signature,
        }));
    if let Some(secret) = secret {
        request = request.header("x-stellaris-secret", secret);
    }
    match request.send().await {
        Ok(response) if response.status().is_success() => {
            tracing::info!(%base, "controller admitted member");
            true
        }
        Ok(response) => {
            tracing::warn!(%base, status = %response.status(), "join rejected");
            false
        }
        Err(e) => {
            tracing::debug!(%base, error = %e, "join request failed");
            false
        }
    }
}

fn verify_snapshot(state: &AgentState, secret: Option<&str>, snapshot: &Snapshot) -> bool {
    if snapshot.network_id != state.network.to_string() {
        tracing::warn!(
            expected = %state.network,
            got = %snapshot.network_id,
            "controller snapshot is for another network; ignored"
        );
        return false;
    }
    if !state.config.control.controller_keys.is_empty() {
        let Some(signer) = snapshot
            .signer
            .as_deref()
            .and_then(|s| s.parse::<NodeId>().ok())
        else {
            tracing::warn!("controller snapshot has no signer");
            return false;
        };
        if !state
            .config
            .control
            .controller_keys
            .iter()
            .any(|key| key == &signer.to_string())
        {
            tracing::warn!(%signer, "untrusted controller signer");
            return false;
        }
        let Some(signature) = snapshot.ed25519_signature.as_deref() else {
            tracing::warn!("controller snapshot has no Ed25519 signature");
            return false;
        };
        let payload = crate::controller::snapshot_payload_bytes(
            &snapshot.network_id,
            snapshot.epoch,
            snapshot.generation,
            &snapshot.members,
            &snapshot.routes,
        );
        if let Err(e) = crate::controller::verify_ed25519(signer, &payload, signature) {
            tracing::warn!(error = %e, "controller Ed25519 signature mismatch");
            return false;
        }
        true
    } else if let Some(secret) = secret {
        let expected = crate::controller::snapshot_signature(
            secret,
            &snapshot.network_id,
            snapshot.epoch,
            snapshot.generation,
            &snapshot.members,
            &snapshot.routes,
        );
        if snapshot.signature.as_deref() != Some(expected.as_str()) {
            tracing::warn!("controller snapshot signature mismatch; ignored");
            return false;
        }
        true
    } else if state.config.control.allow_unsigned_snapshot {
        tracing::warn!("accepted unsigned controller snapshot (control.allow_unsigned_snapshot)");
        true
    } else {
        tracing::warn!(
            "unsigned controller snapshot rejected; set controller_keys, control.secret, or allow_unsigned_snapshot"
        );
        false
    }
}

fn apply_verified_snapshot(
    state: &AgentState,
    mut snapshot: Snapshot,
    last_generation: u64,
    last_epoch: &mut u64,
    transport: Option<&std::sync::Arc<IrohTransport>>,
) -> Option<(u64, u64)> {
    if snapshot.generation == last_generation {
        return None;
    }
    if snapshot.epoch < *last_epoch {
        tracing::warn!(
            got = snapshot.epoch,
            seen = *last_epoch,
            "controller snapshot epoch rolled back; ignored"
        );
        return None;
    }
    *last_epoch = (*last_epoch).max(snapshot.epoch);
    state.set_grants(&snapshot.members);
    if state.config.control.discover_members {
        discover_members(state, &snapshot.members, transport);
    }
    let before = snapshot.routes.len();
    snapshot.routes.retain(|route| {
        route.next_hop == state.node_id
            || state
                .peers
                .get(&route.next_hop)
                .is_some_and(|peer| peer.connected)
    });
    if snapshot.routes.len() != before {
        tracing::warn!(
            dropped = before - snapshot.routes.len(),
            "dropped controller routes with unconnected next hop"
        );
    }
    if !state.config.control.apply_routes {
        return Some((snapshot.generation, snapshot.epoch));
    }
    if state.config.routing.prefer_same_zone
        && let Some(local_zone) = state.config.node.zone.as_deref()
    {
        for route in &mut snapshot.routes {
            if route.attrs.zone.as_deref() == Some(local_zone) {
                route.local_pref = route.local_pref.saturating_add(100);
            }
        }
    }
    match state.routes.replace_controller_routes(snapshot.routes) {
        Ok(local_generation) => {
            tracing::info!(
                controller_generation = snapshot.generation,
                local_generation,
                "applied controller routes"
            );
            Some((snapshot.generation, snapshot.epoch))
        }
        Err(e) => {
            tracing::warn!(error = %e, "failed to apply controller routes");
            None
        }
    }
}

fn discover_members(
    state: &AgentState,
    members: &[crate::controller::MemberView],
    transport: Option<&std::sync::Arc<IrohTransport>>,
) {
    let Some(transport) = transport else {
        return;
    };
    for member in members {
        let Ok(node) = member.node_id.parse::<NodeId>() else {
            continue;
        };
        if node == state.node_id || state.peers.get(&node).is_some() {
            continue;
        }
        let Some(overlay_ip) = member.overlay_ip else {
            continue;
        };
        if member.addrs.is_empty() {
            continue;
        }
        let advertised = member
            .prefixes
            .iter()
            .filter_map(|p| p.parse().ok())
            .collect();
        let peer = stellaris_types::PeerConfig {
            name: format!("auto-{}", node.short()),
            endpoint_id: member.node_id.clone(),
            overlay_ip,
            addrs: member.addrs.clone(),
            relay_url: None,
            advertised,
            zone: member.zone.clone(),
        };
        if transport.add_peer(peer, false) {
            tracing::info!(peer = %node.short(), "discovered member via controller");
        }
    }
}

fn link_metric(state: &AgentState, peer: &crate::PeerState) -> u32 {
    let latency = peer
        .rtt_ms
        .map(|rtt| ((rtt / 10).max(1)) as u32)
        .unwrap_or(1);
    let cross_zone = state.config.node.zone.is_some()
        && peer.zone.is_some()
        && state.config.node.zone != peer.zone;
    if cross_zone {
        latency.saturating_add(state.config.routing.cross_zone_penalty)
    } else {
        latency
    }
}

fn now_seq() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(1)
}

fn local_lsa(state: &AgentState, seq: u64) -> Lsa {
    let links = state
        .peers
        .list()
        .into_iter()
        .filter_map(|peer| {
            peer.endpoint_id.parse().ok().map(|to| Link {
                to,
                metric: link_metric(state, &peer),
                zone: peer.zone.clone(),
            })
        })
        .collect();

    let mut prefixes = Vec::new();
    if let Some(ip) = state.config.node.overlay_ip {
        prefixes.push(Prefix {
            prefix: stellaris_types::host_prefix(ip),
            metric: 0,
        });
    }
    for prefix in &state.config.dataplane.advertise {
        prefixes.push(Prefix {
            prefix: *prefix,
            metric: 10,
        });
    }

    Lsa {
        origin: state.node_id,
        seq,
        zone: state.config.node.zone.clone(),
        links,
        prefixes,
        overlay_ip: state.config.node.overlay_ip,
        addrs: state.config.transport.advertise.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use stellaris_types::Config;

    fn agent(control: &str) -> AgentState {
        let dir =
            std::env::temp_dir().join(format!("stellaris-snapshot-test-{}", uuid::Uuid::now_v7()));
        std::fs::create_dir_all(&dir).unwrap();
        let toml = format!(
            r#"
[node]
name = "m"
state_dir = "{}"
overlay_ip = "10.7.0.2"

[network]
name = "demo"
cidr = "10.7.0.0/16"

[control]
url = "http://127.0.0.1:7800"
{control}
"#,
            dir.display()
        );
        AgentState::build(Config::from_toml(&toml).unwrap()).unwrap()
    }

    fn snapshot(network: &str) -> Snapshot {
        Snapshot {
            network_id: network.to_string(),
            epoch: 3,
            generation: 2,
            members: Vec::new(),
            routes: Vec::new(),
            signer: None,
            signature: None,
            ed25519_signature: None,
        }
    }

    #[test]
    fn unsigned_snapshot_is_rejected_by_default() {
        let state = agent("");
        let snapshot = snapshot(&state.network.to_string());
        assert!(!verify_snapshot(&state, None, &snapshot));
    }

    #[test]
    fn unsigned_snapshot_can_be_opted_in_for_development() {
        let state = agent("allow_unsigned_snapshot = true");
        let snapshot = snapshot(&state.network.to_string());
        assert!(verify_snapshot(&state, None, &snapshot));
    }

    #[test]
    fn snapshot_for_another_network_is_rejected() {
        let state = agent("allow_unsigned_snapshot = true");
        let other = stellaris_types::NetworkId::new().to_string();
        assert!(!verify_snapshot(&state, None, &snapshot(&other)));
    }

    #[test]
    fn snapshot_epoch_rollback_is_rejected() {
        let mut state = agent("allow_unsigned_snapshot = true");
        state.config = std::sync::Arc::new(state.config.as_ref().clone());
        let mut last_epoch = 5;
        let generation = 9;
        let mut snap = snapshot(&state.network.to_string());
        snap.epoch = 4;
        assert!(
            apply_verified_snapshot(&state, snap, generation - 1, &mut last_epoch, None).is_none()
        );
        assert_eq!(last_epoch, 5);
    }
}
