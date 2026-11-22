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
    urls: Vec<String>,
    secret: Option<String>,
    transport: Option<std::sync::Arc<IrohTransport>>,
) {
    if state.config.control.endpoint_id.is_some() {
        run_iroh(state, secret, transport).await;
    } else {
        run_http(state, urls, secret, transport).await;
    }
}

async fn run_http(
    state: AgentState,
    urls: Vec<String>,
    secret: Option<String>,
    transport: Option<std::sync::Arc<IrohTransport>>,
) {
    let bases: Vec<String> = urls
        .into_iter()
        .map(|url| url.trim_end_matches('/').to_string())
        .filter(|url| !url.is_empty())
        .collect();
    if bases.is_empty() {
        return;
    }
    let client = reqwest::Client::new();
    let mut last_generation = 0u64;
    let mut last_lsa = Instant::now() - Duration::from_secs(60);
    let mut seq = 0u64;
    loop {
        if last_lsa.elapsed() >= Duration::from_secs(10) {
            seq = seq.max(now_seq());
            let lsa = local_lsa(&state, seq);
            let mut accepted = false;
            for base in &bases {
                let mut request = client.post(format!("{base}/v1/lsa"));
                if let Some(secret) = &secret {
                    request = request.header("x-stellaris-secret", secret);
                }
                match request.json(&lsa).send().await {
                    Ok(response) if response.status().is_success() => accepted = true,
                    Ok(response) => {
                        tracing::debug!(base, status = %response.status(), "controller rejected LSA")
                    }
                    Err(e) => tracing::debug!(base, error = %e, "controller LSA unreachable"),
                }
            }
            if accepted {
                last_lsa = Instant::now();
            }
        }

        let mut best: Option<Snapshot> = None;
        for base in &bases {
            let mut request = client.get(format!("{base}/v1/snapshot?node={}", state.node_id));
            if let Some(secret) = &secret {
                request = request.header("x-stellaris-secret", secret);
            }
            match request.send().await {
                Ok(response) if response.status().is_success() => {
                    match response.json::<Snapshot>().await {
                        Ok(snapshot) => {
                            let newer = best
                                .as_ref()
                                .map(|b| {
                                    (snapshot.epoch, snapshot.generation) > (b.epoch, b.generation)
                                })
                                .unwrap_or(true);
                            if newer {
                                best = Some(snapshot);
                            }
                        }
                        Err(e) => tracing::warn!(base, error = %e, "invalid controller snapshot"),
                    }
                }
                Ok(response) => {
                    tracing::warn!(base, status = %response.status(), "controller snapshot rejected")
                }
                Err(e) => tracing::debug!(base, error = %e, "controller unreachable"),
            }
        }

        if let Some(snapshot) = best
            && let Some((generation, epoch)) = apply_snapshot(
                &state,
                secret.as_deref(),
                snapshot,
                last_generation,
                transport.as_ref(),
            )
        {
            last_generation = generation;
            for base in &bases {
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
                let req = Request::Lsa {
                    lsa: local_lsa(&state, seq),
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
                    if let Some((generation, epoch)) = apply_snapshot(
                        &state,
                        secret.as_deref(),
                        snapshot,
                        last_generation,
                        transport.as_ref(),
                    ) {
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

fn apply_snapshot(
    state: &AgentState,
    secret: Option<&str>,
    mut snapshot: Snapshot,
    last_generation: u64,
    transport: Option<&std::sync::Arc<IrohTransport>>,
) -> Option<(u64, u64)> {
    if snapshot.generation == last_generation {
        return None;
    }
    if let Some(secret) = secret {
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
            return None;
        }
    }
    discover_members(state, &snapshot.members, transport);
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
    if let Some(ip) = state.config.node.overlay_ip
        && let Ok(prefix) = ipnet::IpNet::new(ip, 32)
    {
        prefixes.push(Prefix { prefix, metric: 0 });
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
