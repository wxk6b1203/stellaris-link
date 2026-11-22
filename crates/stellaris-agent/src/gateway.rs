//! Host forwarding setup for subnet gateways / exit nodes.
//!
//! The agent writes overlay packets destined to an advertised prefix onto its
//! TUN; the kernel forwards them to the underlay. The underlay (or a NAT rule)
//! must provide the return path. This module only enables forwarding; NAT is
//! deliberately explicit because it changes host firewall state.

use anyhow::Context;

pub fn ensure_forwarding() -> anyhow::Result<()> {
    #[cfg(target_os = "linux")]
    {
        std::fs::write("/proc/sys/net/ipv4/ip_forward", b"1")
            .context("enable net.ipv4.ip_forward (need root/CAP_NET_ADMIN)")?;
        if let Err(e) = std::fs::write("/proc/sys/net/ipv6/conf/all/forwarding", b"1") {
            tracing::warn!(error = %e, "enable net.ipv6.conf.all.forwarding");
        }
    }
    #[cfg(target_os = "macos")]
    {
        let status = std::process::Command::new("sysctl")
            .args(["-w", "net.inet.ip.forwarding=1"])
            .status()
            .context("run sysctl net.inet.ip.forwarding")?;
        if !status.success() {
            anyhow::bail!("sysctl net.inet.ip.forwarding failed");
        }
        let _ = std::process::Command::new("sysctl")
            .args(["-w", "net.inet6.ip6.forwarding=1"])
            .status();
    }
    Ok(())
}

/// Install a Linux MASQUERADE rule for overlay traffic leaving the gateway
/// through any interface other than the TUN. Idempotent. macOS/Win are TODO.
pub fn ensure_nat(overlay: &str, tun: &str) -> anyhow::Result<()> {
    ensure_nat_with("iptables", overlay, tun)
}

/// IPv6 MASQUERADE (NAT66) for an IPv6 overlay/exit prefix.
pub fn ensure_nat_v6(overlay: &str, tun: &str) -> anyhow::Result<()> {
    ensure_nat_with("ip6tables", overlay, tun)
}

#[cfg(any(target_os = "linux", test))]
fn nat_rule_args(overlay: &str, tun: &str) -> Vec<String> {
    vec![
        "POSTROUTING".into(),
        "-s".into(),
        overlay.into(),
        "!".into(),
        "-o".into(),
        tun.into(),
        "-j".into(),
        "MASQUERADE".into(),
    ]
}

#[cfg(target_os = "linux")]
fn ensure_nat_with(binary: &str, overlay: &str, tun: &str) -> anyhow::Result<()> {
    let rule = nat_rule_args(overlay, tun);
    let check = std::process::Command::new(binary)
        .args(["-t", "nat", "-C"])
        .args(&rule)
        .status()
        .with_context(|| format!("run {binary} -C (is {binary} installed?)"))?;
    if check.success() {
        return Ok(());
    }
    let add = std::process::Command::new(binary)
        .args(["-t", "nat", "-A"])
        .args(&rule)
        .status()
        .with_context(|| format!("run {binary} -A"))?;
    if !add.success() {
        anyhow::bail!("{binary} MASQUERADE failed for {overlay} -> !{tun}");
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn ensure_nat_with(_binary: &str, overlay: &str, tun: &str) -> anyhow::Result<()> {
    let _ = (overlay, tun);
    anyhow::bail!("dataplane.nat is only implemented on Linux in this MVP")
}

#[cfg(test)]
mod tests {
    use super::nat_rule_args;

    #[test]
    fn nat_rule_has_chain_before_match() {
        let args = nat_rule_args("fd00:115::/64", "stellaris0");
        assert_eq!(args[0], "POSTROUTING");
        assert_eq!(args[1], "-s");
        assert_eq!(args[2], "fd00:115::/64");
        assert!(args.windows(2).any(|w| w == ["!", "-o"]));
        assert_eq!(args.last().map(String::as_str), Some("MASQUERADE"));
    }
}
