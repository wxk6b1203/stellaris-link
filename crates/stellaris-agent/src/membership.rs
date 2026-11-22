//! Network membership authentication.
//!
//! PSK mode performs a mutual HMAC challenge-response on a fresh bi-stream
//! before the connection is admitted to the dataplane or LSA exchange.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, RwLock};

use anyhow::{Context, bail};
use hmac::{Hmac, Mac};
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use stellaris_types::{NetworkId, NodeId};

const CLIENT_DOMAIN: &[u8] = b"stellaris-join-client-v1";
const SERVER_DOMAIN: &[u8] = b"stellaris-join-server-v1";
const MAX_FRAME: usize = 4096;

#[derive(Clone, Debug, Default)]
pub struct Grant {
    pub overlay_ip: Option<IpAddr>,
    pub prefixes: Vec<IpNet>,
    pub capabilities: Vec<String>,
}

pub type GrantMap = Arc<RwLock<HashMap<NodeId, Grant>>>;

pub fn manifest_grants(members: &[crate::controller::MemberView]) -> HashMap<NodeId, Grant> {
    members
        .iter()
        .filter_map(|member| {
            let node: NodeId = member.node_id.parse().ok()?;
            Some((
                node,
                Grant {
                    overlay_ip: member.overlay_ip,
                    prefixes: member
                        .allowed_prefixes
                        .iter()
                        .filter_map(|p| p.parse().ok())
                        .collect(),
                    capabilities: member.capabilities.clone(),
                },
            ))
        })
        .collect()
}

/// Enforce controller grants (when present) on the dataplane source address.
pub fn inbound_source_allowed(state: &crate::AgentState, peer: NodeId, src: IpAddr) -> bool {
    let grants = state.grants.read().unwrap_or_else(|e| e.into_inner());
    if grants.is_empty() {
        return state.peers.get(&peer).is_some_and(|p| {
            src == p.overlay_ip || p.advertised.iter().any(|prefix| prefix.contains(&src))
        });
    }
    let Some(grant) = grants.get(&peer) else {
        return false;
    };
    let owns =
        grant.overlay_ip == Some(src) || grant.prefixes.iter().any(|prefix| prefix.contains(&src));
    if owns {
        return true;
    }
    // A forwarding member may carry another granted member's source.
    // The source must still belong to a valid member grant; `transit` is
    // reserved for additional gateway/exit policy.
    grants
        .values()
        .any(|g| g.overlay_ip == Some(src) || g.prefixes.iter().any(|prefix| prefix.contains(&src)))
}

pub fn lsa_authorized(state: &crate::AgentState, lsa: &stellaris_linkstate::Lsa) -> bool {
    let grants = state.grants.read().unwrap_or_else(|e| e.into_inner());
    if !grants.is_empty() {
        let Some(grant) = grants.get(&lsa.origin) else {
            return false;
        };
        if let Some(expected) = grant.overlay_ip
            && lsa.overlay_ip.is_some_and(|ip| ip != expected)
        {
            return false;
        }
        for prefix in &lsa.prefixes {
            let own = grant
                .overlay_ip
                .is_some_and(|ip| stellaris_types::host_prefix(ip) == prefix.prefix);
            if !own && !grant.prefixes.contains(&prefix.prefix) {
                return false;
            }
        }
        return true;
    }
    // No controller manifest: static peers grant their configured prefixes;
    // unknown/dynamic peers may only advertise their own overlay /32.
    let Some(peer) = state.peers.get(&lsa.origin) else {
        return lsa.prefixes.iter().all(|p| {
            lsa.overlay_ip
                .is_some_and(|ip| stellaris_types::host_prefix(ip) == p.prefix)
        });
    };
    for prefix in &lsa.prefixes {
        let own = stellaris_types::host_prefix(peer.overlay_ip) == prefix.prefix;
        if !own && !peer.advertised.contains(&prefix.prefix) {
            return false;
        }
    }
    true
}

#[derive(Debug, Serialize, Deserialize)]
struct AuthHello {
    network: String,
    node: String,
    nonce: String,
    proof: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct AuthAck {
    node: String,
    nonce: String,
    proof: String,
}

fn hmac_hex(secret: &str, parts: &[&[u8]]) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).expect("hmac key");
    for part in parts {
        mac.update(part);
    }
    hex::encode(mac.finalize().into_bytes())
}

fn nonce() -> String {
    let mut bytes = [0u8; 16];
    rand::RngCore::fill_bytes(&mut rand::rng(), &mut bytes);
    hex::encode(bytes)
}

/// Client side: prove PSK possession and verify the server's response.
pub async fn authenticate_client(
    conn: &iroh::endpoint::Connection,
    network: NetworkId,
    local: NodeId,
    expected_server: NodeId,
    secret: &str,
) -> anyhow::Result<()> {
    let (mut send, mut recv) = conn.open_bi().await.context("open auth stream")?;
    let client_nonce = nonce();
    let network_s = network.to_string();
    let local_s = local.to_string();
    let proof = hmac_hex(
        secret,
        &[
            CLIENT_DOMAIN,
            network_s.as_bytes(),
            local_s.as_bytes(),
            client_nonce.as_bytes(),
        ],
    );
    let hello = AuthHello {
        network: network_s.clone(),
        node: local_s.clone(),
        nonce: client_nonce.clone(),
        proof,
    };
    write_json(&mut send, &hello).await?;
    let _ = send.finish();

    let ack: AuthAck = read_json(&mut recv).await?;
    if ack.node != expected_server.to_string() {
        bail!("auth server identity mismatch");
    }
    let expected = hmac_hex(
        secret,
        &[
            SERVER_DOMAIN,
            network_s.as_bytes(),
            local_s.as_bytes(),
            expected_server.to_string().as_bytes(),
            client_nonce.as_bytes(),
            ack.nonce.as_bytes(),
        ],
    );
    if ack.proof != expected {
        bail!("auth server proof mismatch");
    }
    Ok(())
}

/// Server side: verify the client's PSK proof, optional allowlist, and send ack.
pub async fn authenticate_server(
    conn: &iroh::endpoint::Connection,
    network: NetworkId,
    local: NodeId,
    secret: &str,
    allowed: &[NodeId],
) -> anyhow::Result<NodeId> {
    let (mut send, mut recv) = conn.accept_bi().await.context("accept auth stream")?;
    let hello: AuthHello = read_json(&mut recv).await?;
    let remote = NodeId::new(*conn.remote_id().as_bytes());
    if hello.network != network.to_string() {
        bail!("auth network mismatch");
    }
    if hello.node != remote.to_string() {
        bail!("auth node identity mismatch");
    }
    if !allowed.is_empty() && !allowed.contains(&remote) {
        bail!("peer not in auth.allowed_nodes");
    }
    let expected = hmac_hex(
        secret,
        &[
            CLIENT_DOMAIN,
            hello.network.as_bytes(),
            hello.node.as_bytes(),
            hello.nonce.as_bytes(),
        ],
    );
    if hello.proof != expected {
        bail!("auth client proof mismatch");
    }
    let server_nonce = nonce();
    let proof = hmac_hex(
        secret,
        &[
            SERVER_DOMAIN,
            hello.network.as_bytes(),
            remote.to_string().as_bytes(),
            local.to_string().as_bytes(),
            hello.nonce.as_bytes(),
            server_nonce.as_bytes(),
        ],
    );
    let ack = AuthAck {
        node: local.to_string(),
        nonce: server_nonce,
        proof,
    };
    write_json(&mut send, &ack).await?;
    let _ = send.finish();
    Ok(remote)
}

async fn write_json<T: Serialize>(
    send: &mut iroh::endpoint::SendStream,
    value: &T,
) -> anyhow::Result<()> {
    let bytes = serde_json::to_vec(value).context("serialize auth frame")?;
    if bytes.len() > MAX_FRAME {
        bail!("auth frame too large");
    }
    send.write_all(&(bytes.len() as u32).to_be_bytes()).await?;
    send.write_all(&bytes).await?;
    Ok(())
}

async fn read_json<T: for<'de> Deserialize<'de>>(
    recv: &mut iroh::endpoint::RecvStream,
) -> anyhow::Result<T> {
    let mut len = [0u8; 4];
    recv.read_exact(&mut len).await?;
    let len = u32::from_be_bytes(len) as usize;
    if len == 0 || len > MAX_FRAME {
        bail!("invalid auth frame length {len}");
    }
    let mut bytes = vec![0u8; len];
    recv.read_exact(&mut bytes).await?;
    serde_json::from_slice(&bytes).context("parse auth frame")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn member_grants_filter_lsa_prefixes() {
        use stellaris_linkstate::{Link, Lsa, Prefix};
        use stellaris_types::Config;
        let dir =
            std::env::temp_dir().join(format!("stellaris-grant-test-{}", uuid::Uuid::now_v7()));
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

[[peers]]
name = "b"
endpoint_id = "{}"
overlay_ip = "10.7.0.2"
"#,
            dir.display(),
            hex::encode([2u8; 32])
        );
        let state = crate::AgentState::build(Config::from_toml(&toml).unwrap()).unwrap();
        let b = NodeId::new([2u8; 32]);
        state.grants.write().unwrap().insert(
            b,
            Grant {
                overlay_ip: Some("10.7.0.2".parse().unwrap()),
                prefixes: vec!["192.168.50.0/24".parse().unwrap()],
                capabilities: vec!["member".into()],
            },
        );
        let own = Lsa {
            origin: b,
            seq: 1,
            zone: None,
            links: vec![Link {
                to: NodeId::new([1u8; 32]),
                metric: 1,
                zone: None,
            }],
            prefixes: vec![
                Prefix {
                    prefix: "10.7.0.2/32".parse().unwrap(),
                    metric: 0,
                },
                Prefix {
                    prefix: "192.168.50.0/24".parse().unwrap(),
                    metric: 10,
                },
            ],
            overlay_ip: Some("10.7.0.2".parse().unwrap()),
            addrs: vec![],
        };
        assert!(lsa_authorized(&state, &own));
        let bad = Lsa {
            prefixes: vec![Prefix {
                prefix: "0.0.0.0/0".parse().unwrap(),
                metric: 0,
            }],
            ..own.clone()
        };
        assert!(!lsa_authorized(&state, &bad));
        let unknown = Lsa {
            origin: NodeId::new([3u8; 32]),
            ..own
        };
        assert!(!lsa_authorized(&state, &unknown));
    }

    #[test]
    fn dataplane_grants_allow_own_and_transit_sources() {
        use stellaris_types::Config;
        let dir =
            std::env::temp_dir().join(format!("stellaris-iface-test-{}", uuid::Uuid::now_v7()));
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

[[peers]]
name = "b"
endpoint_id = "{}"
overlay_ip = "10.7.0.2"
"#,
            dir.display(),
            hex::encode([2u8; 32])
        );
        let state = crate::AgentState::build(Config::from_toml(&toml).unwrap()).unwrap();
        let b = NodeId::new([2u8; 32]);
        state.grants.write().unwrap().insert(
            b,
            Grant {
                overlay_ip: Some("10.7.0.2".parse().unwrap()),
                prefixes: vec!["192.168.50.0/24".parse().unwrap()],
                capabilities: vec!["member".into()],
            },
        );
        assert!(inbound_source_allowed(
            &state,
            b,
            "10.7.0.2".parse().unwrap()
        ));
        assert!(inbound_source_allowed(
            &state,
            b,
            "192.168.50.9".parse().unwrap()
        ));
        assert!(!inbound_source_allowed(
            &state,
            b,
            "10.7.0.99".parse().unwrap()
        ));
        state.grants.write().unwrap().insert(
            NodeId::new([1u8; 32]),
            Grant {
                overlay_ip: Some("10.7.0.1".parse().unwrap()),
                prefixes: Vec::new(),
                capabilities: vec!["member".into()],
            },
        );
        assert!(inbound_source_allowed(
            &state,
            b,
            "10.7.0.1".parse().unwrap()
        ));
    }

    #[test]
    fn proofs_are_domain_separated() {
        let network = NetworkId::new();
        let node = NodeId::new([1u8; 32]);
        let a = hmac_hex(
            "secret",
            &[
                CLIENT_DOMAIN,
                network.to_string().as_bytes(),
                node.to_string().as_bytes(),
                b"nonce",
            ],
        );
        let b = hmac_hex(
            "secret",
            &[
                SERVER_DOMAIN,
                network.to_string().as_bytes(),
                node.to_string().as_bytes(),
                b"nonce",
            ],
        );
        assert_ne!(a, b);
        assert_eq!(a.len(), 64);
    }
}
