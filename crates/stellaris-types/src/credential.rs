//! Controller-signed membership credentials.
//!
//! The controller is the only authority allowed to admit a node. Instead of a
//! network-wide shared secret, every member receives a short-lived credential
//! that binds its NodeId (iroh endpoint key) to an overlay address, prefixes
//! and capabilities. Peers verify the credential against
//! `control.controller_keys` during the iroh handshake, so a node that was
//! never admitted (or was revoked) cannot join the data plane even if it can
//! reach another member.
//!
//! The credential is a capability, not a secret: it is signed by the
//! controller and can be shown to anyone, which is exactly why peer-to-peer
//! verification works without distributing per-node keys.

use std::net::IpAddr;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::{NetworkId, NodeId};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use ipnet::IpNet;
use serde::{Deserialize, Serialize};

/// Domain separator for credential signatures.
const DOMAIN: &[u8] = b"stellaris-credential-v1|";

/// A controller-signed membership grant.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MembershipCredential {
    /// Network the credential is valid for; prevents cross-network replay.
    pub network: String,
    /// Node the credential was issued to. Must equal the iroh remote id.
    pub node: NodeId,
    pub overlay_ip: Option<IpAddr>,
    pub prefixes: Vec<IpNet>,
    pub capabilities: Vec<String>,
    /// Monotonic per-node revision. A peer rejects a credential whose revision
    /// is lower than the highest revision it has already seen for this node,
    /// which fences replays of credentials issued before a revocation.
    pub revision: u64,
    /// Unix seconds when the credential was issued.
    #[serde(default)]
    pub issued_at: u64,
    /// Unix seconds after which the credential is no longer valid.
    pub not_after: u64,
}

/// A credential plus the controller signature that makes it authoritative.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedCredential {
    pub credential: MembershipCredential,
    /// Controller NodeId that signed the credential.
    pub issuer: NodeId,
    /// Hex-encoded Ed25519 signature by `issuer`.
    pub signature: String,
}

/// A credential that passed verification, reduced to what the data plane needs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedCredential {
    pub node: NodeId,
    pub overlay_ip: Option<IpAddr>,
    pub prefixes: Vec<IpNet>,
    pub capabilities: Vec<String>,
    pub revision: u64,
    pub not_after: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CredentialError {
    WrongNetwork,
    WrongNode,
    UnknownIssuer,
    BadSignature,
    Expired,
    Stale,
}

impl std::fmt::Display for CredentialError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let text = match self {
            Self::WrongNetwork => "credential is for another network",
            Self::WrongNode => "credential was issued to another node",
            Self::UnknownIssuer => "credential issuer is not a trusted controller",
            Self::BadSignature => "credential signature is invalid",
            Self::Expired => "credential has expired",
            Self::Stale => "credential revision is older than the last seen revision",
        };
        f.write_str(text)
    }
}

impl std::error::Error for CredentialError {}

pub fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn signing_payload(credential: &MembershipCredential, issuer: &NodeId) -> Vec<u8> {
    let body = serde_json::to_vec(credential).unwrap_or_default();
    let mut out = Vec::with_capacity(DOMAIN.len() + 32 + body.len());
    out.extend_from_slice(DOMAIN);
    out.extend_from_slice(issuer.as_bytes());
    out.extend_from_slice(&body);
    out
}

impl SignedCredential {
    /// Sign `credential` with a controller identity key.
    pub fn sign(secret: &[u8; 32], credential: MembershipCredential) -> Self {
        let signing = SigningKey::from_bytes(secret);
        let issuer = NodeId::new(signing.verifying_key().to_bytes());
        let signature = signing.sign(&signing_payload(&credential, &issuer));
        Self {
            credential,
            issuer,
            signature: hex::encode(signature.to_bytes()),
        }
    }

    /// Verify the signature, network, node binding, expiry and revision.
    ///
    /// `min_revision` is the highest revision previously observed for
    /// `expected_node` (0 when nothing was seen yet).
    pub fn verify(
        &self,
        network: &NetworkId,
        expected_node: NodeId,
        controller_keys: &[NodeId],
        min_revision: u64,
        now: u64,
    ) -> Result<VerifiedCredential, CredentialError> {
        let credential = &self.credential;
        if credential.network != network.to_string() {
            return Err(CredentialError::WrongNetwork);
        }
        if credential.node != expected_node {
            return Err(CredentialError::WrongNode);
        }
        if !controller_keys.contains(&self.issuer) {
            return Err(CredentialError::UnknownIssuer);
        }
        let Ok(bytes) = hex::decode(self.signature.trim()) else {
            return Err(CredentialError::BadSignature);
        };
        let Ok(bytes): Result<[u8; 64], _> = bytes.try_into() else {
            return Err(CredentialError::BadSignature);
        };
        let Ok(key) = VerifyingKey::from_bytes(self.issuer.as_bytes()) else {
            return Err(CredentialError::UnknownIssuer);
        };
        if key
            .verify_strict(
                &signing_payload(credential, &self.issuer),
                &Signature::from_bytes(&bytes),
            )
            .is_err()
        {
            return Err(CredentialError::BadSignature);
        }
        if credential.not_after <= now {
            return Err(CredentialError::Expired);
        }
        if credential.revision < min_revision {
            return Err(CredentialError::Stale);
        }
        Ok(VerifiedCredential {
            node: credential.node,
            overlay_ip: credential.overlay_ip,
            prefixes: credential.prefixes.clone(),
            capabilities: credential.capabilities.clone(),
            revision: credential.revision,
            not_after: credential.not_after,
        })
    }

    /// True once two thirds of the credential's actual lifetime have elapsed.
    ///
    /// The lifetime comes from the credential itself, so a controller with a
    /// shorter `credential_ttl_secs` than the member config still gets timely
    /// renewal.
    pub fn needs_renewal(&self, now: u64) -> bool {
        let lifetime = self
            .credential
            .not_after
            .saturating_sub(self.credential.issued_at);
        let remaining = self.credential.not_after.saturating_sub(now);
        remaining <= lifetime / 3
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn network() -> NetworkId {
        NetworkId::new()
    }

    fn controller() -> ([u8; 32], NodeId) {
        let secret = [7u8; 32];
        let signing = SigningKey::from_bytes(&secret);
        (secret, NodeId::new(signing.verifying_key().to_bytes()))
    }

    fn credential(network: &NetworkId, node: NodeId) -> MembershipCredential {
        MembershipCredential {
            network: network.to_string(),
            node,
            overlay_ip: Some("10.7.0.9".parse().unwrap()),
            prefixes: vec!["192.168.50.0/24".parse().unwrap()],
            capabilities: vec!["member".into()],
            revision: 3,
            issued_at: 0,
            not_after: 1_000,
        }
    }

    #[test]
    fn roundtrip_returns_the_grant() {
        let (secret, issuer) = controller();
        let network = network();
        let node = NodeId::new([9u8; 32]);
        let signed = SignedCredential::sign(&secret, credential(&network, node));
        assert_eq!(signed.issuer, issuer);
        let verified = signed
            .verify(&network, node, &[issuer], 3, 999)
            .expect("verified");
        assert_eq!(verified.node, node);
        assert_eq!(verified.overlay_ip, Some("10.7.0.9".parse().unwrap()));
        assert_eq!(verified.prefixes.len(), 1);
    }

    #[test]
    fn tampering_with_grants_is_rejected() {
        let (secret, issuer) = controller();
        let network = network();
        let node = NodeId::new([9u8; 32]);
        let mut signed = SignedCredential::sign(&secret, credential(&network, node));
        signed.credential.capabilities.push("transit".into());
        assert_eq!(
            signed.verify(&network, node, &[issuer], 0, 0),
            Err(CredentialError::BadSignature)
        );
    }

    #[test]
    fn expired_and_stale_credentials_are_rejected() {
        let (secret, issuer) = controller();
        let network = network();
        let node = NodeId::new([9u8; 32]);
        let signed = SignedCredential::sign(&secret, credential(&network, node));
        assert_eq!(
            signed.verify(&network, node, &[issuer], 0, 1_000),
            Err(CredentialError::Expired)
        );
        assert_eq!(
            signed.verify(&network, node, &[issuer], 4, 0),
            Err(CredentialError::Stale)
        );
    }

    #[test]
    fn wrong_node_network_and_issuer_are_rejected() {
        let (secret, issuer) = controller();
        let network = network();
        let node = NodeId::new([9u8; 32]);
        let signed = SignedCredential::sign(&secret, credential(&network, node));

        assert_eq!(
            signed.verify(&network, NodeId::new([8u8; 32]), &[issuer], 0, 0),
            Err(CredentialError::WrongNode)
        );
        assert_eq!(
            signed.verify(&NetworkId::new(), node, &[issuer], 0, 0),
            Err(CredentialError::WrongNetwork)
        );
        assert_eq!(
            signed.verify(&network, node, &[NodeId::new([1u8; 32])], 0, 0),
            Err(CredentialError::UnknownIssuer)
        );
    }

    #[test]
    fn renewal_happens_at_two_thirds_of_the_lifetime() {
        let (secret, _) = controller();
        let network = network();
        let node = NodeId::new([9u8; 32]);
        let mut cred = credential(&network, node);
        cred.issued_at = 0;
        cred.not_after = 1_000;
        let signed = SignedCredential::sign(&secret, cred);
        assert!(!signed.needs_renewal(500));
        assert!(signed.needs_renewal(700));
        assert!(signed.needs_renewal(999));
    }
}
