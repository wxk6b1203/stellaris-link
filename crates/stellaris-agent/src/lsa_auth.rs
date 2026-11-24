//! Ed25519 authenticity for peer-to-peer LSAs.
//!
//! Control streams accept LSAs from any connected member. The LSA `origin`
//! field is the origin's Ed25519 public key (a `NodeId`), so every flooded LSA
//! carries a signature over a domain-separated canonical payload. Receivers
//! verify the signature against `origin` before accepting the LSA, which stops
//! a member from forging someone else's topology.

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use stellaris_linkstate::Lsa;

const DOMAIN: &[u8] = b"stellaris-lsa-v1|";

/// Canonical bytes covered by an LSA signature.
pub fn signing_payload(lsa: &Lsa) -> Vec<u8> {
    let body = serde_json::to_vec(lsa).unwrap_or_default();
    let mut out = Vec::with_capacity(DOMAIN.len() + body.len());
    out.extend_from_slice(DOMAIN);
    out.extend_from_slice(&body);
    out
}

/// Sign an LSA with the node's Ed25519 identity key.
pub fn sign(secret: &[u8; 32], lsa: &Lsa) -> String {
    let key = SigningKey::from_bytes(secret);
    hex::encode(key.sign(&signing_payload(lsa)).to_bytes())
}

/// Verify a hex signature against `lsa.origin`.
pub fn verify(lsa: &Lsa, signature_hex: &str) -> bool {
    let Ok(bytes) = hex::decode(signature_hex.trim()) else {
        return false;
    };
    let Ok(bytes): Result<[u8; 64], _> = bytes.try_into() else {
        return false;
    };
    let Ok(key) = VerifyingKey::from_bytes(lsa.origin.as_bytes()) else {
        return false;
    };
    key.verify_strict(&signing_payload(lsa), &Signature::from_bytes(&bytes))
        .is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use stellaris_linkstate::{Link, Prefix};
    use stellaris_types::NodeId;

    fn node(byte: u8) -> ([u8; 32], NodeId) {
        // Deterministic Ed25519 key material for tests.
        let secret = [byte; 32];
        let key = SigningKey::from_bytes(&secret);
        (secret, NodeId::new(key.verifying_key().to_bytes()))
    }

    fn lsa(origin: NodeId, seq: u64) -> Lsa {
        Lsa {
            origin,
            seq,
            zone: Some("z1".into()),
            links: vec![Link {
                to: NodeId::new([9; 32]),
                metric: 7,
                zone: None,
            }],
            prefixes: vec![Prefix {
                prefix: "10.7.0.0/24".parse().unwrap(),
                metric: 0,
            }],
            overlay_ip: Some("10.7.0.1".parse().unwrap()),
            addrs: vec!["192.0.2.1:5611".parse().unwrap()],
        }
    }

    #[test]
    fn signature_roundtrips() {
        let (secret, origin) = node(3);
        let lsa = lsa(origin, 42);
        let signature = sign(&secret, &lsa);
        assert!(verify(&lsa, &signature));
    }

    #[test]
    fn tampered_fields_are_rejected() {
        let (secret, origin) = node(3);
        let mut lsa = lsa(origin, 42);
        let signature = sign(&secret, &lsa);
        lsa.seq += 1;
        assert!(!verify(&lsa, &signature));
        lsa.seq -= 1;
        lsa.prefixes[0].prefix = "10.7.1.0/24".parse().unwrap();
        assert!(!verify(&lsa, &signature));
    }

    #[test]
    fn signature_from_another_key_is_rejected() {
        let (_, origin) = node(3);
        let (other_secret, _) = node(4);
        let lsa = lsa(origin, 1);
        let forged = sign(&other_secret, &lsa);
        assert!(!verify(&lsa, &forged));
    }

    #[test]
    fn malformed_signatures_are_rejected() {
        let (_, origin) = node(3);
        let lsa = lsa(origin, 1);
        assert!(!verify(&lsa, ""));
        assert!(!verify(&lsa, "zz"));
        assert!(!verify(&lsa, &"00".repeat(63)));
    }
}
