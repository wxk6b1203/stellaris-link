//! Controller iroh control protocol (MVP): one request/response per bi-stream.

use anyhow::Context;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use stellaris_linkstate::Lsa;

use crate::controller::Snapshot;

pub const CONTROL_ALPN: &[u8] = b"stellaris/control/1";
const MAX_FRAME: usize = 4 << 20;

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Request {
    Snapshot {
        #[serde(default)]
        node: Option<String>,
        #[serde(default)]
        secret: Option<String>,
    },
    Lsa {
        lsa: Lsa,
        /// Ed25519 signature by `lsa.origin` over the canonical LSA payload.
        #[serde(default)]
        signature: String,
        #[serde(default)]
        secret: Option<String>,
    },
    Ack {
        node: String,
        generation: u64,
        #[serde(default)]
        epoch: Option<u64>,
        #[serde(default)]
        secret: Option<String>,
    },
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Response {
    Snapshot {
        snapshot: Snapshot,
    },
    Ok {
        changed: bool,
        generation: u64,
        epoch: u64,
    },
    Error {
        code: u16,
        message: String,
    },
}

pub async fn write_frame<T: Serialize>(
    send: &mut iroh::endpoint::SendStream,
    value: &T,
) -> anyhow::Result<()> {
    let bytes = serde_json::to_vec(value).context("serialize control frame")?;
    if bytes.len() > MAX_FRAME {
        anyhow::bail!("control frame too large");
    }
    send.write_all(&(bytes.len() as u32).to_be_bytes()).await?;
    send.write_all(&bytes).await?;
    Ok(())
}

pub async fn read_frame<T: DeserializeOwned>(
    recv: &mut iroh::endpoint::RecvStream,
) -> anyhow::Result<Option<T>> {
    let mut len = [0u8; 4];
    if recv.read_exact(&mut len).await.is_err() {
        return Ok(None);
    }
    let len = u32::from_be_bytes(len) as usize;
    if len == 0 || len > MAX_FRAME {
        anyhow::bail!("invalid control frame length {len}");
    }
    let mut bytes = vec![0u8; len];
    recv.read_exact(&mut bytes).await?;
    Ok(Some(
        serde_json::from_slice(&bytes).context("parse control frame")?,
    ))
}
