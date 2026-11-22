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
    }
    Ok(())
}

/// Install a Linux MASQUERADE rule for overlay traffic leaving the gateway
/// through any interface other than the TUN. Idempotent. macOS/Win are TODO.
pub fn ensure_nat(overlay: &str, tun: &str) -> anyhow::Result<()> {
    #[cfg(target_os = "linux")]
    {
        let check = std::process::Command::new("iptables")
            .args([
                "-t",
                "nat",
                "-C",
                "POSTROUTING",
                "-s",
                overlay,
                "!",
                "-o",
                tun,
                "-j",
                "MASQUERADE",
            ])
            .status()
            .context("run iptables -C (is iptables installed?)")?;
        if check.success() {
            return Ok(());
        }
        let add = std::process::Command::new("iptables")
            .args([
                "-t",
                "nat",
                "-A",
                "POSTROUTING",
                "-s",
                overlay,
                "!",
                "-o",
                tun,
                "-j",
                "MASQUERADE",
            ])
            .status()
            .context("run iptables -A")?;
        if !add.success() {
            anyhow::bail!("iptables MASQUERADE failed for {overlay} -> !{tun}");
        }
        Ok(())
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (overlay, tun);
        anyhow::bail!("dataplane.nat is only implemented on Linux in this MVP")
    }
}
