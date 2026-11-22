use std::fs;
use std::io::Write;
use std::path::Path;

use anyhow::{Context, bail};
use ed25519_dalek::SigningKey;
use rand::RngCore;
use stellaris_types::NodeId;

pub struct Identity {
    pub node_id: NodeId,
    /// Ed25519 secret key bytes. Reused by the iroh transport.
    pub secret: [u8; 32],
}

pub fn load_or_create(state_dir: &Path) -> anyhow::Result<Identity> {
    let path = state_dir.join("identity.key");
    let secret = if path.exists() {
        let bytes = fs::read(&path).with_context(|| format!("read {}", path.display()))?;
        if bytes.len() != 32 {
            bail!("identity.key must be 32 bytes, got {}", bytes.len());
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(&bytes);
        out
    } else {
        let mut secret = [0u8; 32];
        rand::rng().fill_bytes(&mut secret);
        let mut opts = fs::OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut file = opts
            .open(&path)
            .with_context(|| format!("create {}", path.display()))?;
        file.write_all(&secret)?;
        secret
    };

    let signing = SigningKey::from_bytes(&secret);
    let node_id = NodeId::new(signing.verifying_key().to_bytes());
    Ok(Identity { node_id, secret })
}
