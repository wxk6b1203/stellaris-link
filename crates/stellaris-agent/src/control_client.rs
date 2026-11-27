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

/// Ordered HTTP controller endpoints: `control.url` first, then
/// `control.failover_urls`, normalized and de-duplicated.
pub fn controller_bases(config: &stellaris_types::Config) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for raw in config
        .control
        .url
        .iter()
        .chain(config.control.failover_urls.iter())
    {
        let value = raw.trim().trim_end_matches('/');
        if value.is_empty() || out.iter().any(|existing| existing == value) {
            continue;
        }
        out.push(value.to_string());
    }
    out
}

fn rotate_controller(bases: &[String], index: &mut usize, base: &mut String) {
    if bases.len() < 2 {
        return;
    }
    *index = (*index + 1) % bases.len();
    *base = bases[*index].clone();
    tracing::warn!(controller = %base, "rotating to the next controller endpoint");
}

pub async fn run(
    state: AgentState,
    bases: Vec<String>,
    secret: Option<String>,
    transport: Option<std::sync::Arc<IrohTransport>>,
) {
    if state.config.control.endpoint_id.is_some() {
        run_iroh(state, secret, transport).await;
    } else if !bases.is_empty() {
        run_http(state, bases, secret, transport).await;
    }
}

async fn run_http(
    state: AgentState,
    bases: Vec<String>,
    secret: Option<String>,
    transport: Option<std::sync::Arc<IrohTransport>>,
) {
    let mut normalized: Vec<String> = Vec::new();
    for raw in bases {
        let value = raw.trim().trim_end_matches('/');
        if value.is_empty() || normalized.iter().any(|existing| existing == value) {
            continue;
        }
        normalized.push(value.to_string());
    }
    let bases = controller_bases(&state.config);
    let mut base = match normalized.first().or_else(|| bases.first()) {
        Some(base) => base.clone(),
        None => return,
    };
    let mut base_index = 0usize;
    let client = match http_client(&state.config) {
        Ok(client) => client,
        Err(e) => {
            tracing::warn!(error = %e, "build controller HTTP client");
            return;
        }
    };
    let mut last_enroll = Instant::now() - Duration::from_secs(60);
    let mut last_manifest = Instant::now() - Duration::from_secs(60);
    let mut last_lsa = Instant::now() - Duration::from_secs(60);
    let mut seq = 0u64;
    loop {
        if credential_needs_renewal(&state) && last_enroll.elapsed() >= Duration::from_secs(5) {
            last_enroll = Instant::now();
            if !enroll_http(&client, &base, &state, secret.as_deref()).await {
                rotate_controller(&bases, &mut base_index, &mut base);
            }
        }
        if !state.config.control.controller_keys.is_empty()
            && last_manifest.elapsed() >= Duration::from_secs(10)
            && try_manifest(
                &client,
                &base,
                &state,
                transport.as_ref(),
                secret.as_deref(),
            )
            .await
        {
            last_manifest = Instant::now();
        } else {
            rotate_controller(&bases, &mut base_index, &mut base);
        }
        if last_lsa.elapsed() >= Duration::from_secs(10) {
            seq = seq.max(now_seq());
            let lsa = local_lsa(&state, seq);
            let signature = crate::lsa_auth::sign(&state.identity_secret, &lsa);
            let body = serde_json::json!({"lsa": &lsa, "signature": signature});
            let mut request = client.post(format!("{base}/v1/lsa"));
            if let Some(secret) = &secret {
                request = request.header("x-stellaris-secret", secret);
            }
            match request.json(&body).send().await {
                Ok(response) if response.status().is_success() => {
                    last_lsa = Instant::now();
                }
                Ok(response) => {
                    tracing::debug!(%base, status = %response.status(), "controller rejected LSA");
                    if response.status() == reqwest::StatusCode::SERVICE_UNAVAILABLE {
                        rotate_controller(&bases, &mut base_index, &mut base);
                    }
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
            Ok(response) if response.status() == reqwest::StatusCode::SERVICE_UNAVAILABLE => {
                tracing::warn!(%base, "controller is not the Raft leader; trying the next endpoint");
                rotate_controller(&bases, &mut base_index, &mut base);
                tokio::time::sleep(Duration::from_millis(500)).await;
                continue;
            }
            Ok(response) => {
                tracing::warn!(%base, status = %response.status(), "controller snapshot rejected")
            }
            Err(e) => tracing::debug!(%base, error = ?e, "controller unreachable"),
        }

        if let Some(snapshot) = snapshot
            && let Some((generation, epoch)) =
                apply_verified_snapshot(&state, snapshot, transport.as_ref())
        {
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

    // Prefer the data endpoint: a second endpoint with the same NodeId on the
    // same relay makes iroh-relay mark one of them inactive, which can silently
    // break relay-only data paths. A standalone endpoint is only needed when
    // the data transport is disabled.
    let endpoint = if let Some(transport) = &transport {
        transport.endpoint()
    } else {
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
        if !state.config.transport.disable_relay
            && tokio::time::timeout(Duration::from_secs(10), endpoint.online())
                .await
                .is_err()
        {
            tracing::warn!("control relay did not come online within 10s");
        }
        endpoint
    };

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
            if credential_needs_renewal(&state) {
                let auto = state.config.node.ipam == stellaris_types::IpamMode::Auto;
                let req = Request::Enroll {
                    overlay_ip: state.config.node.overlay_ip,
                    auto,
                    pool: None,
                    zone: state.config.node.zone.clone(),
                    addrs: state.config.transport.advertise.clone(),
                    secret: secret.clone(),
                };
                match request(&conn, &req).await {
                    Ok(Response::Credential { credential }) => {
                        if install_credential(&state, &credential) {
                            tracing::info!("membership credential issued");
                        }
                    }
                    Ok(Response::Pending { .. }) => {
                        tracing::debug!("enrollment pending administrator approval");
                    }
                    Ok(Response::Denied { reason, .. }) => {
                        tracing::warn!(%reason, "enrollment denied");
                    }
                    Ok(Response::Error { code, message }) => {
                        tracing::warn!(code, message, "controller enrollment error");
                    }
                    Ok(_) => {}
                    Err(e) => {
                        tracing::debug!(error = %e, "controller enroll request failed");
                        break;
                    }
                }
            }
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
                        && let Some((generation, epoch)) =
                            apply_verified_snapshot(&state, snapshot, transport.as_ref())
                    {
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
                Ok(_) => {}
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
    transport: Option<&std::sync::Arc<IrohTransport>>,
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
                    if !state.manifest_floor_allows(manifest.epoch, manifest.generation) {
                        let (epoch, generation) = state.manifest_floor();
                        tracing::warn!(
                            got_epoch = manifest.epoch,
                            got_generation = manifest.generation,
                            seen_epoch = epoch,
                            seen_generation = generation,
                            "membership manifest replayed or stale; ignored"
                        );
                        return false;
                    }
                    apply_members(state, &manifest.members, &manifest.revoked, transport);
                    state.record_manifest_floor(manifest.epoch, manifest.generation);
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

/// True when we have no credential, or it is past two thirds of its lifetime.
fn credential_needs_renewal(state: &AgentState) -> bool {
    if state.config.network.auth.mode != stellaris_types::AuthMode::Controller {
        return false;
    }
    let Some(credential) = state.credential() else {
        return true;
    };
    // The controller revises a member on address/prefix/capability changes;
    // pick those up immediately instead of waiting for the TTL to run down.
    state.revision(state.node_id) > credential.credential.revision
        || credential.needs_renewal(crate::credential::now_secs())
}

fn install_credential(state: &AgentState, signed: &crate::credential::SignedCredential) -> bool {
    let keys: Vec<NodeId> = state
        .config
        .control
        .controller_keys
        .iter()
        .filter_map(|key| key.parse().ok())
        .collect();
    if keys.is_empty() {
        tracing::warn!("controller credential ignored: control.controller_keys is empty");
        return false;
    }
    match signed.verify(
        &state.network,
        state.node_id,
        &keys,
        0,
        crate::credential::now_secs(),
    ) {
        Ok(verified) => {
            if state.config.node.ipam == stellaris_types::IpamMode::Auto {
                match (verified.overlay_ip, state.local_overlay()) {
                    (Some(ip), None) => match state.reconfigure_overlay(ip) {
                        Ok(()) => {
                            tracing::info!(%ip, "controller allocated overlay address");
                        }
                        Err(error) => {
                            tracing::warn!(%ip, %error, "failed to configure overlay address");
                            return false;
                        }
                    },
                    (Some(ip), Some(existing)) if existing != ip => {
                        match state.reconfigure_overlay(ip) {
                            Ok(()) => {
                                tracing::info!(
                                    %existing,
                                    %ip,
                                    "controller changed the overlay address; TUN reconfigured"
                                );
                            }
                            Err(error) => {
                                tracing::warn!(
                                    %existing,
                                    %ip,
                                    %error,
                                    "failed to reconfigure the overlay address; keeping the old one"
                                );
                                return false;
                            }
                        }
                    }
                    (Some(_), Some(_)) => {}
                    (None, _) => tracing::warn!("credential has no overlay address"),
                }
            }
            state.set_credential(signed.clone());
            true
        }
        Err(error) => {
            tracing::warn!(%error, "controller credential rejected");
            false
        }
    }
}

/// Apply the controller membership list: refresh revisions and revoke peers
/// that are no longer members (close their connection, drop their grant).
fn apply_members(
    state: &AgentState,
    members: &[crate::controller::MemberView],
    revoked: &[crate::controller::RevokedView],
    transport: Option<&std::sync::Arc<IrohTransport>>,
) {
    let mut known = std::collections::HashSet::new();
    for member in members {
        if let Ok(node) = member.node_id.parse::<NodeId>() {
            known.insert(node);
            if let Some(transport) = transport {
                // A member that is present again (or whose revision changed)
                // must be allowed to reconnect after a prior revoke.
                transport.allow_peer(node);
            }
            // Multi-hop LSA authorization uses controller-signed grants, not
            // only grants learned from a direct credential handshake.
            let prefixes = member
                .prefixes
                .iter()
                .filter_map(|prefix| prefix.parse().ok())
                .collect();
            state.install_snapshot_grant(
                node,
                member.overlay_ip,
                prefixes,
                member.capabilities.clone(),
                member.revision,
            );
            let previous = state.revision(node);
            state.observe_revision(node, member.revision);
            if node != state.node_id && member.revision > previous {
                if let Some(ip) = member.overlay_ip
                    && state.peers.update_overlay(&node, ip)
                {
                    tracing::info!(
                        peer = %node.short(),
                        %ip,
                        "controller changed a member overlay; reconnecting"
                    );
                }
                // Force re-authentication so the peer's new credential (and
                // its overlay grant) replaces the cached one. This is not a
                // revocation: the peer stays allowed to reconnect and the
                // connect loop performs the handshake again.
                if let Some(transport) = transport {
                    transport.reconnect_peer(node);
                }
            }
        }
    }
    // Explicit tombstones: fence the revoked node even when this process has
    // never seen its grant and the credential has not expired yet.
    for member in revoked {
        if let Ok(node) = member.node_id.parse::<NodeId>() {
            let floor = member.revision.saturating_add(1);
            state.observe_revision(node, floor);
            tracing::warn!(peer = %node.short(), revision = member.revision, "controller revoked member");
            match transport {
                Some(transport) => transport.close_peer(node),
                None => state.drop_grant(node),
            }
        }
    }
    let stale: Vec<NodeId> = state
        .grants
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .keys()
        .copied()
        .filter(|node| !known.contains(node))
        .collect();
    for node in stale {
        tracing::warn!(peer = %node.short(), "member is no longer authorized; revoking");
        // Fence the credential the peer already holds: a revoked node keeps a
        // cryptographically valid credential until it expires, so raise the
        // local revision floor. Re-approval bumps the controller revision past
        // this value and is accepted again.
        let floor = state.revision(node).saturating_add(1);
        state.observe_revision(node, floor);
        match transport {
            Some(transport) => transport.close_peer(node),
            None => state.drop_grant(node),
        }
    }
}

/// HTTP enrollment (debug/bootstrap path). The request is signed by the node
/// key; the iroh control channel does not need a signature.
async fn enroll_http(
    client: &reqwest::Client,
    base: &str,
    state: &AgentState,
    secret: Option<&str>,
) -> bool {
    let auto = state.config.node.ipam == stellaris_types::IpamMode::Auto;
    let overlay = state.config.node.overlay_ip;
    let overlay_text = overlay.map(|ip| ip.to_string());
    let payload = crate::controller::enroll_payload_bytes(
        &state.network.to_string(),
        &state.node_id.to_string(),
        overlay_text.as_deref(),
        state.config.node.zone.as_deref(),
    );
    let signature = crate::controller::sign_ed25519(&state.identity_secret, &payload);
    let mut request = client
        .post(format!("{base}/v1/enroll"))
        .json(&serde_json::json!({
            "node_id": state.node_id.to_string(),
            "overlay_ip": overlay_text,
            "auto": auto,
            "zone": state.config.node.zone,
            "addrs": state.config.transport.advertise,
            "signature": signature,
        }));
    if let Some(secret) = secret {
        request = request.header("x-stellaris-secret", secret);
    }
    match request.send().await {
        Ok(response) if response.status().is_success() => {
            match response
                .json::<serde_json::Value>()
                .await
                .ok()
                .and_then(|value| value.get("credential").cloned())
                .and_then(|value| {
                    serde_json::from_value::<crate::credential::SignedCredential>(value).ok()
                }) {
                Some(credential) => {
                    if install_credential(state, &credential) {
                        tracing::info!(%base, "membership credential issued");
                    }
                }
                None => tracing::warn!(%base, "controller response carried no credential"),
            }
            true
        }
        Ok(response) if response.status() == reqwest::StatusCode::ACCEPTED => {
            tracing::info!(%base, "enrollment queued for administrator approval");
            true
        }
        Ok(response) if response.status() == reqwest::StatusCode::FORBIDDEN => {
            tracing::warn!(%base, status = %response.status(), "enrollment denied");
            true
        }
        Ok(response) if response.status() == reqwest::StatusCode::SERVICE_UNAVAILABLE => {
            tracing::debug!(%base, "enrollment hit a non-leader controller");
            false
        }
        Ok(response) => {
            tracing::warn!(%base, status = %response.status(), "enrollment rejected");
            true
        }
        Err(e) => {
            tracing::debug!(%base, error = %e, "controller enrollment unreachable");
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
            &snapshot.revoked,
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
            &snapshot.revoked,
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
    transport: Option<&std::sync::Arc<IrohTransport>>,
) -> Option<(u64, u64)> {
    let (last_epoch, last_generation) = state.snapshot_floor();
    if !state.snapshot_floor_allows(snapshot.epoch, snapshot.generation) {
        tracing::warn!(
            got_epoch = snapshot.epoch,
            got_generation = snapshot.generation,
            seen_epoch = last_epoch,
            seen_generation = last_generation,
            "controller snapshot is not newer than the persisted floor; ignored"
        );
        return None;
    }
    let epoch = snapshot.epoch;
    let generation = snapshot.generation;
    apply_members(state, &snapshot.members, &snapshot.revoked, transport);
    if state.config.control.discover_members {
        discover_members(state, &snapshot.members, transport);
    }
    if !state.config.control.apply_routes {
        state.record_snapshot_floor(epoch, generation);
        return Some((generation, epoch));
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
            state.record_snapshot_floor(epoch, generation);
            Some((generation, epoch))
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
        if node == state.node_id {
            continue;
        }
        if state.peers.get(&node).is_some() {
            if let Some(ip) = member.overlay_ip {
                state.peers.update_overlay(&node, ip);
            }
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
    if let Some(ip) = state.local_overlay() {
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
        overlay_ip: state.local_overlay(),
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
            revoked: Vec::new(),
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
        let state = agent("allow_unsigned_snapshot = true");
        let mut snap = snapshot(&state.network.to_string());
        snap.epoch = 5;
        snap.generation = 9;
        assert!(apply_verified_snapshot(&state, snap.clone(), None).is_some());
        assert_eq!(state.snapshot_floor(), (5, 9));
        // Same epoch, older generation is a replay.
        snap.generation = 8;
        assert!(apply_verified_snapshot(&state, snap.clone(), None).is_none());
        // Older epoch is a replay even with a higher generation.
        snap.epoch = 4;
        snap.generation = 10;
        assert!(apply_verified_snapshot(&state, snap, None).is_none());
        assert_eq!(state.snapshot_floor(), (5, 9));
    }

    fn node_for(secret: [u8; 32]) -> NodeId {
        use ed25519_dalek::SigningKey;
        NodeId::new(SigningKey::from_bytes(&secret).verifying_key().to_bytes())
    }

    #[tokio::test]
    async fn http_enrollment_installs_a_credential() {
        let controller_secret = [9u8; 32];
        let controller = node_for(controller_secret);
        let dir =
            std::env::temp_dir().join(format!("stellaris-enroll-test-{}", uuid::Uuid::now_v7()));
        std::fs::create_dir_all(&dir).unwrap();
        let agent_toml = format!(
            r#"
[node]
name = "m"
state_dir = "{}"
overlay_ip = "10.7.0.2"

[network]
name = "demo"
cidr = "10.7.0.0/16"

[network.auth]
mode = "controller"

[control]
url = "http://127.0.0.1:1"
secret = "s3cret"
controller_keys = ["{controller}"]
credential_ttl_secs = 600
"#,
            dir.join("agent").display()
        );
        let agent = AgentState::build(Config::from_toml(&agent_toml).unwrap()).unwrap();
        let cdir = dir.join("controller");
        std::fs::create_dir_all(&cdir).unwrap();
        let controller_toml = format!(
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
node_id = "{}"
overlay_ip = "10.7.0.2"
prefixes = ["192.168.50.0/24"]
"#,
            cdir.display(),
            agent.node_id
        );
        let mut controller_state = crate::controller::ControllerState::from_config(
            &Config::from_toml(&controller_toml).unwrap(),
        )
        .unwrap();
        controller_state.set_signing_key(controller_secret);
        let app = crate::controller::router(controller_state);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        let client = http_client(&agent.config).unwrap();
        enroll_http(&client, &format!("http://{addr}"), &agent, Some("s3cret")).await;
        let credential = agent.credential().expect("credential installed");
        assert_eq!(credential.credential.node, agent.node_id);
        assert_eq!(credential.issuer, controller);
        assert_eq!(
            credential.credential.prefixes,
            vec!["192.168.50.0/24".parse().unwrap()]
        );
    }

    #[test]
    fn revoked_members_lose_their_grants_and_revisions_advance() {
        let state = agent("");
        let node = NodeId::new([5u8; 32]);
        state.grants.write().unwrap().insert(
            node,
            crate::membership::Grant {
                overlay_ip: Some("10.7.0.5".parse().unwrap()),
                prefixes: Vec::new(),
                capabilities: vec!["member".into()],
                expires_at: None,
            },
        );
        let view = crate::controller::MemberView {
            node_id: node.to_string(),
            zone: None,
            overlay_ip: Some("10.7.0.5".parse().unwrap()),
            addrs: Vec::new(),
            prefixes: Vec::new(),
            allowed_prefixes: Vec::new(),
            capabilities: vec!["member".into()],
            links: Vec::new(),
            last_seq: 0,
            revision: 5,
        };
        apply_members(&state, &[view], &[], None);
        assert_eq!(state.revision(node), 5);
        assert!(state.grants.read().unwrap().contains_key(&node));
        apply_members(&state, &[], &[], None);
        assert!(!state.grants.read().unwrap().contains_key(&node));
        // The revoked node's still-valid credential is fenced locally.
        assert_eq!(state.revision(node), 6);
    }

    #[test]
    fn revoked_snapshot_fences_a_node_never_seen_before() {
        let state = agent("");
        let node = NodeId::new([9u8; 32]);
        assert_eq!(state.revision(node), 0);
        apply_members(
            &state,
            &[],
            &[crate::controller::RevokedView {
                node_id: node.to_string(),
                revision: 4,
            }],
            None,
        );
        // Old credentials use revision <= 4, so the floor must be 5 even
        // though this process never saw the node's grant.
        assert_eq!(state.revision(node), 5);
        assert!(!state.grants.read().unwrap().contains_key(&node));
    }

    #[tokio::test]
    async fn auto_enrollment_adopts_the_controller_allocated_address() {
        let controller_secret = [9u8; 32];
        let controller = node_for(controller_secret);
        let dir =
            std::env::temp_dir().join(format!("stellaris-auto-test-{}", uuid::Uuid::now_v7()));
        std::fs::create_dir_all(&dir).unwrap();
        let agent_toml = format!(
            r#"
[node]
name = "m"
state_dir = "{}"
ipam = "auto"

[network]
name = "ipam-demo"
cidr = "10.30.0.0/16"

[network.auth]
mode = "controller"

[control]
url = "http://127.0.0.1:1"
secret = "s3cret"
controller_keys = ["{controller}"]
credential_ttl_secs = 600
"#,
            dir.join("agent").display()
        );
        let agent = AgentState::build(Config::from_toml(&agent_toml).unwrap()).unwrap();
        assert!(agent.local_overlay().is_none());
        let cdir = dir.join("controller");
        std::fs::create_dir_all(&cdir).unwrap();
        let controller_toml = format!(
            r#"
[node]
name = "ctrl"
role = "controller"
state_dir = "{}"

[network]
name = "ipam-demo"
cidr = "10.30.0.0/16"

[control]
secret = "s3cret"

[control.ipam]
[[control.ipam.pools]]
id = "p"
cidr = "10.30.0.0/24"
lease_secs = 600

[[control.members]]
node_id = "{}"
"#,
            cdir.display(),
            agent.node_id
        );
        let mut controller_state = crate::controller::ControllerState::from_config(
            &Config::from_toml(&controller_toml).unwrap(),
        )
        .unwrap();
        controller_state.set_signing_key(controller_secret);
        let app = crate::controller::router(controller_state);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        let client = http_client(&agent.config).unwrap();
        enroll_http(&client, &format!("http://{addr}"), &agent, Some("s3cret")).await;
        let credential = agent.credential().expect("credential installed");
        assert_eq!(
            credential.credential.overlay_ip,
            Some("10.30.0.1".parse().unwrap())
        );
        assert_eq!(agent.local_overlay(), Some("10.30.0.1".parse().unwrap()));
    }
}
