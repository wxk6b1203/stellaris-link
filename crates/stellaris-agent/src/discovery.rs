//! UDP broadcast bootstrap discovery.
//!
//! Discovery only adds candidate peers; PSK/controller membership still
//! authenticates every connection before data or LSA is accepted.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use mdns_sd::{IfKind, ServiceDaemon, ServiceEvent, ServiceInfo};
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
    if state.config.transport.discovery_port.is_some() {
        start_broadcast(state.clone(), transport.clone());
    }
    if state.config.transport.mdns {
        start_mdns(state, transport);
    }
}

/// A discovery announce is only usable inside its own network.
fn announce_matches_network(announce: &Announce, network: &crate::NetworkId) -> bool {
    announce.network == network.to_string()
}

fn start_broadcast(state: AgentState, transport: Arc<IrohTransport>) {
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
            if !announce_matches_network(&announce, &state.network) {
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

const MDNS_SERVICE: &str = "_stellaris._udp.local.";

fn start_mdns(state: AgentState, transport: Arc<IrohTransport>) {
    let Some(first) = state.config.transport.advertise.first().copied() else {
        warn!("transport.mdns requires transport.advertise");
        return;
    };
    let Some(overlay_ip) = state.config.node.overlay_ip else {
        warn!("transport.mdns requires node.overlay_ip");
        return;
    };
    let daemon = match state.config.transport.mdns_port {
        Some(port) => ServiceDaemon::new_with_port(port),
        None => ServiceDaemon::new(),
    };
    let daemon = match daemon {
        Ok(daemon) => daemon,
        Err(e) => {
            warn!(error = %e, "start mDNS daemon");
            return;
        }
    };
    let instance = format!("stellaris-{}", state.node_id.short());
    let host = format!("{instance}.local.");
    let mut properties = HashMap::new();
    properties.insert("network".to_string(), state.network.to_string());
    properties.insert("node".to_string(), state.node_id.to_string());
    properties.insert("overlay".to_string(), overlay_ip.to_string());
    if let Some(zone) = &state.config.node.zone {
        properties.insert("zone".to_string(), zone.clone());
    }
    properties.insert("addr".to_string(), first.to_string());
    let service = match ServiceInfo::new(
        MDNS_SERVICE,
        &instance,
        &host,
        first.ip().to_string(),
        first.port(),
        properties,
    ) {
        Ok(service) => service,
        Err(e) => {
            warn!(error = %e, "build mDNS service info");
            return;
        }
    };
    if let Some(interface) = &state.config.transport.mdns_interface {
        if let Err(e) = daemon.disable_interface(IfKind::All) {
            warn!(error = %e, "disable mDNS interfaces");
            return;
        }
        if let Err(e) = daemon.enable_interface(interface.as_str()) {
            warn!(error = %e, interface, "enable mDNS interface");
            return;
        }
    }
    if let Err(e) = daemon.register(service) {
        warn!(error = %e, "register mDNS service");
        return;
    }
    let receiver = match daemon.browse(MDNS_SERVICE) {
        Ok(receiver) => receiver,
        Err(e) => {
            warn!(error = %e, "browse mDNS service");
            return;
        }
    };
    info!(
        service = MDNS_SERVICE,
        interface = ?state.config.transport.mdns_interface,
        "mDNS discovery started"
    );
    let runtime = tokio::runtime::Handle::current();
    std::thread::spawn(move || {
        // Keep the daemon alive for the lifetime of the process.
        let _daemon = daemon;
        // add_peer() spawns a Tokio connect loop; expose the current runtime
        // to this std thread.
        let _runtime = runtime.enter();
        while let Ok(event) = receiver.recv() {
            let ServiceEvent::ServiceResolved(service) = event else {
                continue;
            };
            let Some(node) = service
                .get_property_val_str("node")
                .and_then(|s| s.parse::<NodeId>().ok())
            else {
                continue;
            };
            if node == state.node_id || state.peers.get(&node).is_some() {
                continue;
            }
            let Some(network) = service.get_property_val_str("network") else {
                continue;
            };
            if network != state.network.to_string() {
                continue;
            }
            let Some(overlay_ip) = service
                .get_property_val_str("overlay")
                .and_then(|s| s.parse::<IpAddr>().ok())
            else {
                continue;
            };
            let port = service.get_port();
            let mut addrs: Vec<SocketAddr> = service
                .get_addresses_v4()
                .into_iter()
                .map(|ip| SocketAddr::new(IpAddr::V4(ip), port))
                .collect();
            if addrs.is_empty()
                && let Some(addr) = service
                    .get_property_val_str("addr")
                    .and_then(|s| s.parse::<SocketAddr>().ok())
            {
                addrs.push(addr);
            }
            if addrs.is_empty() {
                continue;
            }
            let peer = PeerConfig {
                name: format!("mdns-{}", node.short()),
                endpoint_id: node.to_string(),
                overlay_ip,
                addrs,
                relay_url: None,
                advertised: Vec::new(),
                zone: service.get_property_val_str("zone").map(str::to_string),
            };
            if transport.add_peer(peer, false) {
                info!(peer = %node.short(), "discovered peer via mDNS");
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

#[cfg(test)]
mod tests {
    use super::*;
    use stellaris_types::NetworkId;

    #[test]
    fn announce_only_matches_its_network() {
        let network = NetworkId::new();
        let announce = Announce {
            network: network.to_string(),
            node: NodeId::new([1u8; 32]).to_string(),
            overlay_ip: "10.7.0.1".parse().unwrap(),
            zone: Some("az-a".into()),
            addrs: vec!["192.0.2.1:5611".parse().unwrap()],
        };
        assert!(announce_matches_network(&announce, &network));
        assert!(!announce_matches_network(&announce, &NetworkId::new()));
    }

    #[test]
    fn announce_json_roundtrips() {
        let network = NetworkId::new();
        let announce = Announce {
            network: network.to_string(),
            node: NodeId::new([2u8; 32]).to_string(),
            overlay_ip: "10.7.0.2".parse().unwrap(),
            zone: None,
            addrs: vec![],
        };
        let bytes = serde_json::to_vec(&announce).unwrap();
        let decoded: Announce = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(decoded.node, announce.node);
        assert_eq!(decoded.overlay_ip, announce.overlay_ip);
        assert!(MDNS_SERVICE.ends_with(".local."));
    }

    #[test]
    fn malformed_announce_is_rejected() {
        assert!(serde_json::from_slice::<Announce>(b"{}").is_err());
        assert!(serde_json::from_slice::<Announce>(b"not json").is_err());
    }
}
