//! Offline membership credential issuance.
//!
//! This path does not contact a controller. The operator runs it next to the
//! controller identity key (or a copy) and places the signed credential in the
//! member's state directory.

use std::io::Write;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, bail};
use clap::{ArgGroup, Args, Subcommand};
use ipnet::IpNet;
use stellaris_types::credential::{MembershipCredential, SignedCredential};
use stellaris_types::{NetworkId, NodeId};

#[derive(Debug, Subcommand)]
pub enum CredentialCmd {
    /// Issue a controller-signed credential offline.
    Issue(IssueArgs),
    /// Verify a credential file without contacting a controller.
    Verify(VerifyArgs),
}

#[derive(Debug, Args)]
pub struct VerifyArgs {
    /// Credential JSON file, or `-` for stdin.
    #[arg(long, default_value = "-")]
    pub file: String,
    /// Network UUID the credential must be valid for.
    #[arg(long)]
    pub network: String,
    /// Node id the credential must be bound to.
    #[arg(long)]
    pub node: String,
    /// Trusted issuer NodeId. Required unless --allow-untrusted-issuer.
    #[arg(long, conflicts_with = "allow_untrusted_issuer")]
    pub issuer: Option<String>,
    /// Only check signature/claims; do not assert that the issuer is trusted.
    #[arg(long)]
    pub allow_untrusted_issuer: bool,
}

#[derive(Clone, Debug, Args)]
#[command(group(
    ArgGroup::new("key_source")
        .required(true)
        .args(["controller_state", "controller_key"])
))]
pub struct IssueArgs {
    /// Controller state directory containing identity.key.
    #[arg(long)]
    pub controller_state: Option<PathBuf>,
    /// Raw 32-byte controller identity key file.
    #[arg(long)]
    pub controller_key: Option<PathBuf>,
    /// Network UUID (must match the member's network.id or derived network id).
    #[arg(long)]
    pub network: String,
    /// Member NodeId (hex public key).
    #[arg(long)]
    pub node: String,
    /// Overlay address to bind the member to.
    #[arg(long)]
    pub overlay_ip: Option<IpAddr>,
    /// Advertised prefix; repeatable.
    #[arg(long = "prefix")]
    pub prefixes: Vec<IpNet>,
    /// Capability; repeatable (default: member).
    #[arg(long = "capability", default_value = "member")]
    pub capabilities: Vec<String>,
    /// Monotonic per-node revision.
    #[arg(long, default_value_t = 1)]
    pub revision: u64,
    /// Credential lifetime in seconds.
    #[arg(long, default_value_t = 3600)]
    pub ttl_secs: u64,
    /// Issued-at timestamp (0 = now; useful for reproducible test data).
    #[arg(long, default_value_t = 0)]
    pub issued_at: u64,
    /// Output file, or `-` for stdout.
    #[arg(long, default_value = "-")]
    pub out: String,
    /// Overwrite an existing output file.
    #[arg(long)]
    pub force: bool,
}

pub fn run(cmd: CredentialCmd) -> anyhow::Result<()> {
    match cmd {
        CredentialCmd::Issue(args) => issue(args),
        CredentialCmd::Verify(args) => verify(args),
    }
}

fn verify(args: VerifyArgs) -> anyhow::Result<()> {
    let bytes = if args.file == "-" {
        let mut bytes = Vec::new();
        std::io::Read::read_to_end(&mut std::io::stdin().lock(), &mut bytes)?;
        bytes
    } else {
        std::fs::read(&args.file).with_context(|| format!("read credential {}", args.file))?
    };
    let signed: SignedCredential = serde_json::from_slice(&bytes)
        .with_context(|| format!("parse credential {}", args.file))?;
    let network: NetworkId = args
        .network
        .parse()
        .with_context(|| format!("invalid network id {:?}", args.network))?;
    let node: NodeId = args
        .node
        .parse()
        .with_context(|| format!("invalid node id {:?}", args.node))?;
    let expected_issuer = match (&args.issuer, args.allow_untrusted_issuer) {
        (Some(issuer), false) => Some(
            issuer
                .parse::<NodeId>()
                .with_context(|| format!("invalid issuer {issuer:?}"))?,
        ),
        (None, true) => None,
        (None, false) => bail!(
            "pass --issuer <trusted-controller-node-id> to verify issuer trust, or --allow-untrusted-issuer for an integrity-only check"
        ),
        (Some(_), true) => bail!("--issuer and --allow-untrusted-issuer are mutually exclusive"),
    };
    let issuer_key = expected_issuer.unwrap_or(signed.issuer);
    let trusted = expected_issuer.is_some();
    let now = credential_now();
    let summary = |valid: bool, error: Option<String>| {
        serde_json::json!({
            "valid": valid,
            "trusted": trusted && valid,
            "error": error,
            "issuer": signed.issuer.to_string(),
            "network": signed.credential.network,
            "node": signed.credential.node.to_string(),
            "overlay_ip": signed.credential.overlay_ip.map(|ip| ip.to_string()),
            "prefixes": signed.credential.prefixes.iter().map(|p| p.to_string()).collect::<Vec<_>>(),
            "capabilities": signed.credential.capabilities,
            "revision": signed.credential.revision,
            "issued_at": signed.credential.issued_at,
            "not_after": signed.credential.not_after,
            "now": now,
        })
    };
    match signed.verify(&network, node, &[issuer_key], 0, now) {
        Ok(_) => {
            if expected_issuer.is_none() {
                eprintln!(
                    "warning: issuer trust was not checked; pass --issuer for a trusted verification"
                );
            }
            println!("{}", serde_json::to_string_pretty(&summary(true, None))?);
            Ok(())
        }
        Err(error) => {
            println!(
                "{}",
                serde_json::to_string_pretty(&summary(false, Some(error.to_string())))?
            );
            bail!("credential invalid: {error}");
        }
    }
}

fn credential_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

fn issue(args: IssueArgs) -> anyhow::Result<()> {
    if args.revision == 0 {
        bail!("--revision must be >= 1");
    }
    if args.ttl_secs == 0 {
        bail!("--ttl-secs must be >= 1");
    }
    let network: NetworkId = args
        .network
        .parse()
        .with_context(|| format!("invalid network id {:?}", args.network))?;
    let node: NodeId = args
        .node
        .parse()
        .with_context(|| format!("invalid node id {:?}", args.node))?;
    let (secret, key_path) = controller_secret(&args)?;
    let issued_at = if args.issued_at == 0 {
        credential_now()
    } else {
        args.issued_at
    };
    let not_after = issued_at.saturating_add(args.ttl_secs);
    if not_after <= issued_at {
        bail!("--ttl-secs overflows the expiry timestamp");
    }
    let mut capabilities = Vec::new();
    for capability in args.capabilities {
        let capability = capability.trim();
        if !capability.is_empty() && !capabilities.iter().any(|c| c == capability) {
            capabilities.push(capability.to_string());
        }
    }
    let credential = MembershipCredential {
        network: network.to_string(),
        node,
        overlay_ip: args.overlay_ip,
        prefixes: args.prefixes.clone(),
        capabilities,
        revision: args.revision,
        issued_at,
        not_after,
    };
    let signed = SignedCredential::sign(&secret, credential);
    // A self-check catches accidental serialization/format drift before the
    // credential is written.
    signed
        .verify(&network, node, &[signed.issuer], 0, issued_at)
        .map_err(|e| anyhow::anyhow!("generated credential failed verification: {e}"))?;
    let bytes = serde_json::to_vec_pretty(&signed)?;
    write_output(&args.out, &bytes, args.force)?;
    eprintln!(
        "issued credential: issuer={} network={} node={} overlay={} not_after={} key={}",
        signed.issuer,
        network,
        node,
        args.overlay_ip
            .map(|ip| ip.to_string())
            .unwrap_or_else(|| "-".into()),
        not_after,
        key_path.display()
    );
    Ok(())
}

fn controller_secret(args: &IssueArgs) -> anyhow::Result<([u8; 32], PathBuf)> {
    let path = match (&args.controller_state, &args.controller_key) {
        (Some(dir), None) => dir.join("identity.key"),
        (None, Some(path)) => path.clone(),
        _ => bail!("exactly one of --controller-state/--controller-key is required"),
    };
    let bytes =
        std::fs::read(&path).with_context(|| format!("read controller key {}", path.display()))?;
    let secret: [u8; 32] = bytes.try_into().map_err(|bytes: Vec<u8>| {
        anyhow::anyhow!(
            "controller key {} must be 32 bytes, got {}",
            path.display(),
            bytes.len()
        )
    })?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(metadata) = std::fs::metadata(&path)
            && metadata.permissions().mode() & 0o077 != 0
        {
            eprintln!(
                "warning: controller key {} is readable by group/others; use mode 0600",
                path.display()
            );
        }
    }
    Ok((secret, path))
}

fn write_output(out: &str, bytes: &[u8], force: bool) -> anyhow::Result<()> {
    if out == "-" {
        let mut stdout = std::io::stdout().lock();
        stdout.write_all(bytes)?;
        stdout.write_all(b"\n")?;
        return Ok(());
    }
    let path = Path::new(out);
    if path.exists() && !force {
        bail!(
            "{} already exists; pass --force to overwrite",
            path.display()
        );
    }
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("create output directory {}", parent.display()))?;
    }
    let tmp = path.with_extension("credential.tmp");
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    {
        let mut file = options
            .open(&tmp)
            .with_context(|| format!("write {}", tmp.display()))?;
        file.write_all(bytes)?;
        file.write_all(b"\n")?;
        file.sync_all()?;
    }
    std::fs::rename(&tmp, path)
        .with_context(|| format!("rename {} to {}", tmp.display(), path.display()))?;
    if let Some(parent) = path.parent()
        && let Ok(dir) = std::fs::File::open(parent)
    {
        let _ = dir.sync_all();
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use stellaris_types::credential::SignedCredential;

    fn test_args(dir: &Path) -> IssueArgs {
        IssueArgs {
            controller_state: None,
            controller_key: Some(dir.join("identity.key")),
            network: NetworkId::new().to_string(),
            node: NodeId::new([9u8; 32]).to_string(),
            overlay_ip: Some("10.7.0.9".parse().unwrap()),
            prefixes: vec!["192.168.50.0/24".parse().unwrap()],
            capabilities: vec!["member".into(), "transit".into()],
            revision: 3,
            ttl_secs: 600,
            issued_at: 1000,
            out: dir.join("credential.json").display().to_string(),
            force: false,
        }
    }

    #[test]
    fn issues_a_verifiable_credential_to_a_file() {
        let dir = std::env::temp_dir().join(format!("stellaris-cli-issue-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("identity.key"), [7u8; 32]).unwrap();
        let args = test_args(&dir);
        let network: NetworkId = args.network.parse().unwrap();
        let node: NodeId = args.node.parse().unwrap();
        issue(args).unwrap();
        let bytes = std::fs::read(dir.join("credential.json")).unwrap();
        let signed: SignedCredential = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(signed.credential.revision, 3);
        assert_eq!(
            signed.credential.overlay_ip,
            Some("10.7.0.9".parse().unwrap())
        );
        assert_eq!(signed.credential.prefixes.len(), 1);
        assert_eq!(signed.credential.capabilities, ["member", "transit"]);
        assert!(
            signed
                .verify(&network, node, &[signed.issuer], 0, 1000)
                .is_ok()
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn refuses_to_overwrite_without_force() {
        let dir =
            std::env::temp_dir().join(format!("stellaris-cli-overwrite-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("identity.key"), [7u8; 32]).unwrap();
        let args = test_args(&dir);
        let mut second = test_args(&dir);
        issue(args).unwrap();
        assert!(issue(second.clone()).is_err());
        second.force = true;
        issue(second).unwrap();
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn reads_the_key_from_a_controller_state_dir() {
        let dir = std::env::temp_dir().join(format!("stellaris-cli-state-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("identity.key"), [8u8; 32]).unwrap();
        let mut args = test_args(&dir);
        args.controller_key = None;
        args.controller_state = Some(dir.clone());
        args.out = dir.join("credential.json").display().to_string();
        issue(args).unwrap();
        let signed: SignedCredential =
            serde_json::from_slice(&std::fs::read(dir.join("credential.json")).unwrap()).unwrap();
        let expected = NodeId::new(
            ed25519_dalek::SigningKey::from_bytes(&[8u8; 32])
                .verifying_key()
                .to_bytes(),
        );
        assert_eq!(signed.issuer, expected);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn verify_requires_trusted_issuer_or_explicit_opt_out() {
        let dir =
            std::env::temp_dir().join(format!("stellaris-cli-verify-trust-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("identity.key"), [7u8; 32]).unwrap();
        let mut args = test_args(&dir);
        args.issued_at = credential_now();
        let network = args.network.clone();
        let node = args.node.clone();
        let path = args.out.clone();
        issue(args).unwrap();
        let signed: SignedCredential =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        let run = |issuer: Option<String>, allow: bool| {
            verify(VerifyArgs {
                file: path.clone(),
                network: network.clone(),
                node: node.clone(),
                issuer,
                allow_untrusted_issuer: allow,
            })
        };
        assert!(run(None, false).is_err(), "issuer trust must be explicit");
        assert!(run(Some(NodeId::new([1u8; 32]).to_string()), false).is_err());
        assert!(run(Some(signed.issuer.to_string()), false).is_ok());
        assert!(run(None, true).is_ok());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn verifies_a_file_and_reports_expiry() {
        let dir = std::env::temp_dir().join(format!("stellaris-cli-verify-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("identity.key"), [7u8; 32]).unwrap();
        let mut args = test_args(&dir);
        args.issued_at = credential_now();
        args.ttl_secs = 600;
        let network = args.network.clone();
        let node = args.node.clone();
        let path = args.out.clone();
        issue(args).unwrap();
        let signed: SignedCredential =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        verify(VerifyArgs {
            file: path.clone(),
            network: network.clone(),
            node: node.clone(),
            issuer: Some(signed.issuer.to_string()),
            allow_untrusted_issuer: false,
        })
        .unwrap();

        let mut expired = test_args(&dir);
        expired.issued_at = credential_now().saturating_sub(1000);
        expired.ttl_secs = 60;
        expired.out = dir.join("expired.json").display().to_string();
        issue(expired).unwrap();
        assert!(
            verify(VerifyArgs {
                file: dir.join("expired.json").display().to_string(),
                network,
                node,
                issuer: Some(signed.issuer.to_string()),
                allow_untrusted_issuer: false,
            })
            .is_err()
        );
        let _ = std::fs::remove_dir_all(dir);
    }
}
