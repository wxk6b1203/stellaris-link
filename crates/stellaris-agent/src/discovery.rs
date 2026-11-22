//! UDP broadcast bootstrap discovery.
//!
//! Discovery only adds candidate peers; PSK/controller membership still
//! authenticates every connection before data or LSA is accepted.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use socket2::{Domain, Protocol, Socket, Type};
use stellaris_types::{NodeId, PeerConfig};
use tracing::{debug, info, warn};

use crate::AgentState;
use crate::transport::IrohTransport;

#[derive(Debug, Serialize, Deserialize)]
struct Announce {
    network: String,
    node: String,
    overlay_ip: IpAddr,
    zone: Option<String>,
    addrs: Vec<SocketAddr>,
}

pub fn start(state: AgentState, transport: Arc<IrohTransport>) {
    let Some(port) = state.config.transport.discovery_port else {
        return;
    };
    if state.config.transport.advertise.is_empty() {
        warn!("transport.discovery_port requires transport.advertise");
        return;
    }
    let Some(overlay_ip) = state.config.node.overlay_ip else {
        warn!("transport.discovery_port requires node.overlay_ip");
        return;
    };
    let socket = match bind_port(port) {
        Ok(socket) => socket,
        Err(e) => {
            warn!(error = %e, port, "bind UDP discovery");
            return;
        }
    };
    let socket = Arc::new(socket);
    let announce = Announce {
        network: state.network.to_string(),
        node: state.node_id.to_string(),
        overlay_ip,
        zone: state.config.node.zone.clone(),
        addrs: state.config.transport.advertise.clone(),
    };
    let payload = match serde_json::to_vec(&announce) {
        Ok(payload) => Arc::new(payload),
        Err(e) => {
            warn!(error = %e, "serialize discovery announce");
            return;
        }
    };
    info!(port, "UDP discovery started");

    {
        let socket = socket.clone();
        let payload = payload.clone();
        let targets = {
            let mut targets = vec![SocketAddr::from(([255, 255, 255, 255], port))];
            if let Some(target) = state.config.transport.discovery_broadcast
                && !targets.contains(&target)
            {
                targets.push(target);
            }
            targets
        };
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_secs(2));
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                tick.tick().await;
                for target in &targets {
                    if let Err(e) = socket.send_to(&payload, *target).await {
                        debug!(error = %e, %target, "send discovery announce");
                    }
                }
            }
        });
    }

    tokio::spawn(async move {
        let mut buf = [0u8; 8192];
        loop {
            let Ok((n, _from)) = socket.recv_from(&mut buf).await else {
                break;
            };
            let Ok(announce) = serde_json::from_slice::<Announce>(&buf[..n]) else {
                continue;
            };
            if announce.network != state.network.to_string() {
                continue;
            }
            let Ok(node) = announce.node.parse::<NodeId>() else {
                continue;
            };
            if node == state.node_id || state.peers.get(&node).is_some() {
                continue;
            }
            if announce.addrs.is_empty() {
                continue;
            }
            let peer = PeerConfig {
                name: format!("udp-{}", node.short()),
                endpoint_id: node.to_string(),
                overlay_ip: announce.overlay_ip,
                addrs: announce.addrs,
                relay_url: None,
                advertised: Vec::new(),
                zone: announce.zone,
            };
            if transport.add_peer(peer, false) {
                info!(peer = %node.short(), "discovered peer via UDP broadcast");
            }
        }
    });
}

fn bind_port(port: u16) -> anyhow::Result<tokio::net::UdpSocket> {
    let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    socket.set_reuse_address(true)?;
    socket.set_broadcast(true)?;
    socket.bind(&SocketAddr::from(([0, 0, 0, 0], port)).into())?;
    socket.set_nonblocking(true)?;
    Ok(tokio::net::UdpSocket::from_std(socket.into())?)
}
