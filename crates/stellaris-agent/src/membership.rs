//! Network membership: controller-signed credentials and dataplane grants.
//!
//! Every connection must present a [`SignedCredential`] issued by a trusted
//! controller. The credential is verified during the iroh handshake against
//! `control.controller_keys`, which makes the controller the single authority
//! for who may carry overlay traffic and which source addresses they own.
//!
//! There is no shared network secret: a credential is a signed capability,
//! safe to show to any peer.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, RwLock};

use anyhow::{Context, bail};
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use stellaris_types::{NetworkId, NodeId};

use crate::credential::{CredentialError, SignedCredential, VerifiedCredential};

/// Credentials carry prefix lists, so allow room for a large member.
const MAX_FRAME: usize = 64 * 1024;

#[derive(Clone, Debug, Default)]
pub struct Grant {
    pub overlay_ip: Option<IpAddr>,
    pub prefixes: Vec<IpNet>,
    pub capabilities: Vec<String>,
}

pub type GrantMap = Arc<RwLock<HashMap<NodeId, Grant>>>;

impl Grant {
    pub fn from_verified(credential: &VerifiedCredential) -> Self {
        Self {
            overlay_ip: credential.overlay_ip,
            prefixes: credential.prefixes.clone(),
            capabilities: credential.capabilities.clone(),
        }
    }
}

/// Enforce credentials (when present) on the dataplane source address.
pub fn inbound_source_allowed(state: &crate::AgentState, peer: NodeId, src: IpAddr) -> bool {
    let grants = state.grants.read().unwrap_or_else(|e| e.into_inner());
    if grants.is_empty() {
        // In controller mode no authenticated peer has been seen yet, so
        // fail closed instead of falling back to static peers.
        if state.config.network.auth.mode == stellaris_types::AuthMode::Controller {
            return false;
        }
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
    // Only a member explicitly granted transit/gateway/exit may carry another
    // member's source address. Without the capability this is a spoof.
    let may_transit = grant
        .capabilities
        .iter()
        .any(|capability| matches!(capability.as_str(), "transit" | "gateway" | "exit"));
    if !may_transit {
        return false;
    }
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
    // No membership state yet: controller mode fails closed; otherwise static
    // peers grant their configured prefixes and unknown/dynamic peers may only
    // advertise their own overlay /32.
    if state.config.network.auth.mode == stellaris_types::AuthMode::Controller {
        return false;
    }
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
struct CredentialFrame {
    credential: SignedCredential,
}

fn verify_frame(
    frame: CredentialFrame,
    remote: NodeId,
    network: &NetworkId,
    controller_keys: &[NodeId],
    min_revision: u64,
) -> anyhow::Result<VerifiedCredential> {
    frame
        .credential
        .verify(
            network,
            remote,
            controller_keys,
            min_revision,
            crate::credential::now_secs(),
        )
        .map_err(|error| match error {
            CredentialError::WrongNetwork => anyhow::anyhow!("credential network mismatch"),
            other => anyhow::anyhow!("credential rejected: {other}"),
        })
}

/// Outbound side: present our credential, verify the peer's.
pub async fn authenticate_client(
    conn: &iroh::endpoint::Connection,
    network: &NetworkId,
    controller_keys: &[NodeId],
    own: Option<&SignedCredential>,
    min_revision: impl Fn(NodeId) -> u64,
) -> anyhow::Result<VerifiedCredential> {
    let own = own.ok_or_else(|| anyhow::anyhow!("no membership credential"))?;
    let remote = NodeId::new(*conn.remote_id().as_bytes());
    let (mut send, mut recv) = conn.open_bi().await.context("open auth stream")?;
    write_json(
        &mut send,
        &CredentialFrame {
            credential: own.clone(),
        },
    )
    .await?;
    let _ = send.finish();
    let frame: CredentialFrame = read_json(&mut recv).await?;
    verify_frame(
        frame,
        remote,
        network,
        controller_keys,
        min_revision(remote),
    )
}

/// Inbound side: verify the peer's credential, then present ours.
pub async fn authenticate_server(
    conn: &iroh::endpoint::Connection,
    network: &NetworkId,
    controller_keys: &[NodeId],
    own: Option<&SignedCredential>,
    min_revision: impl Fn(NodeId) -> u64,
) -> anyhow::Result<VerifiedCredential> {
    let own = own.ok_or_else(|| anyhow::anyhow!("no membership credential"))?;
    let remote = NodeId::new(*conn.remote_id().as_bytes());
    let (mut send, mut recv) = conn.accept_bi().await.context("accept auth stream")?;
    let frame: CredentialFrame = read_json(&mut recv).await?;
    let verified = verify_frame(
        frame,
        remote,
        network,
        controller_keys,
        min_revision(remote),
    )?;
    write_json(
        &mut send,
        &CredentialFrame {
            credential: own.clone(),
        },
    )
    .await?;
    let _ = send.finish();
    Ok(verified)
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
    fn dataplane_grants_require_transit_for_other_sources() {
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
        // A plain member may not carry another member's source address.
        assert!(!inbound_source_allowed(
            &state,
            b,
            "10.7.0.1".parse().unwrap()
        ));
        // Granting transit makes the same packet acceptable.
        state
            .grants
            .write()
            .unwrap()
            .get_mut(&b)
            .unwrap()
            .capabilities
            .push("transit".into());
        assert!(inbound_source_allowed(
            &state,
            b,
            "10.7.0.1".parse().unwrap()
        ));
    }

    #[test]
    fn controller_mode_without_grants_fails_closed() {
        use stellaris_linkstate::{Lsa, Prefix};
        use stellaris_types::Config;
        let dir =
            std::env::temp_dir().join(format!("stellaris-failclosed-{}", uuid::Uuid::now_v7()));
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

[network.auth]
mode = "controller"

[control]
url = "http://127.0.0.1:1"
controller_keys = ["0202020202020202020202020202020202020202020202020202020202020202"]

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
        let lsa = Lsa {
            origin: b,
            seq: 1,
            zone: None,
            links: Vec::new(),
            prefixes: vec![Prefix {
                prefix: "10.7.0.2/32".parse().unwrap(),
                metric: 0,
            }],
            overlay_ip: Some("10.7.0.2".parse().unwrap()),
            addrs: Vec::new(),
        };
        assert!(!lsa_authorized(&state, &lsa));
        assert!(!inbound_source_allowed(
            &state,
            b,
            "10.7.0.2".parse().unwrap()
        ));
    }
}
