//! Network membership authentication.
//!
//! PSK mode performs a mutual HMAC challenge-response on a fresh bi-stream
//! before the connection is admitted to the dataplane or LSA exchange.

use anyhow::{Context, bail};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use stellaris_types::{NetworkId, NodeId};

const CLIENT_DOMAIN: &[u8] = b"stellaris-join-client-v1";
const SERVER_DOMAIN: &[u8] = b"stellaris-join-server-v1";
const MAX_FRAME: usize = 4096;

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
    Ok(serde_json::from_slice(&bytes).context("parse auth frame")?)
}

#[cfg(test)]
mod tests {
    use super::*;

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
