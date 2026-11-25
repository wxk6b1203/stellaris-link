//! Overlay address pools (IPAM) shared by controller config and model.

use std::net::IpAddr;

use ipnet::IpNet;
use serde::{Deserialize, Serialize};

fn default_lease_secs() -> u64 {
    3600
}

fn default_quarantine_secs() -> u64 {
    60
}

/// How a pool picks the next free address.
#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AllocStrategy {
    /// Scan the pool in order and take the first free address (IPv4 default).
    #[default]
    LowestFree,
    /// Hash the node id into the pool and probe forward (IPv6 default).
    HashProbe,
}

/// A controller-managed overlay address pool.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct AddressPool {
    /// Stable identifier used by leases and API calls.
    pub id: String,
    pub cidr: IpNet,
    /// Optional inclusive allocation range inside `cidr`.
    #[serde(default)]
    pub range: Option<(IpAddr, IpAddr)>,
    /// Subnets that must never be allocated (gateways, VIPs, ...).
    #[serde(default)]
    pub exclude: Vec<IpNet>,
    /// Lease lifetime in seconds; 0 is rejected by validation.
    #[serde(default = "default_lease_secs")]
    pub lease_secs: u64,
    /// How long a released address stays unusable.
    #[serde(default = "default_quarantine_secs")]
    pub quarantine_secs: u64,
    #[serde(default)]
    pub strategy: AllocStrategy,
    /// Optional AZ/site affinity: nodes in this zone prefer this pool.
    #[serde(default)]
    pub zone: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
}
