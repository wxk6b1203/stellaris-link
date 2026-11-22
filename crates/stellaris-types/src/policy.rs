use std::net::IpAddr;

use ipnet::IpNet;
use serde::{Deserialize, Serialize};

use crate::id::NodeId;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AclAction {
    #[default]
    Allow,
    Deny,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AclDirection {
    Inbound,
    Outbound,
    Forward,
    #[default]
    Both,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct AclConfig {
    #[serde(default)]
    pub default_action: AclAction,
    #[serde(default)]
    pub rules: Vec<AclRule>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AclRule {
    pub name: String,
    #[serde(default)]
    pub action: AclAction,
    #[serde(default)]
    pub direction: AclDirection,
    #[serde(default)]
    pub priority: i32,
    #[serde(default)]
    pub src: Option<IpNet>,
    #[serde(default)]
    pub dst: Option<IpNet>,
    #[serde(default)]
    pub protocol: Option<u8>,
    #[serde(default)]
    pub src_port: Option<u16>,
    #[serde(default)]
    pub dst_port: Option<u16>,
    #[serde(default)]
    pub peer: Option<NodeId>,
    #[serde(default)]
    pub zone: Option<String>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct QosConfig {
    #[serde(default)]
    pub enabled: bool,
    /// Egress priority queue depth (default 4096).
    #[serde(default)]
    pub queue_depth: Option<usize>,
    /// Optional per-priority queue depth cap.
    #[serde(default)]
    pub queue_depth_per_priority: Option<usize>,
    #[serde(default)]
    pub classes: Vec<QosClass>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct QosClass {
    pub name: String,
    /// DSCP value 0..=63.
    pub dscp: u8,
    #[serde(default)]
    pub priority: i32,
    #[serde(default)]
    pub src: Option<IpNet>,
    #[serde(default)]
    pub dst: Option<IpNet>,
    #[serde(default)]
    pub protocol: Option<u8>,
    #[serde(default)]
    pub src_port: Option<u16>,
    #[serde(default)]
    pub dst_port: Option<u16>,
    /// Optional token-bucket rate (packets per second).
    #[serde(default)]
    pub rate_pps: Option<u32>,
    /// Optional token-bucket burst size (defaults to rate_pps).
    #[serde(default)]
    pub burst: Option<u32>,
    /// Optional byte-rate shaper (bytes per second).
    #[serde(default)]
    pub rate_bps: Option<u32>,
    /// Optional byte burst (defaults to rate_bps).
    #[serde(default)]
    pub burst_bytes: Option<u32>,
}

impl AclRule {
    /// Returns true if this rule matches the packet and direction.
    #[allow(clippy::too_many_arguments)]
    pub fn matches(
        &self,
        direction: AclDirection,
        src: IpAddr,
        dst: IpAddr,
        protocol: u8,
        src_port: Option<u16>,
        dst_port: Option<u16>,
        peer: Option<NodeId>,
        zone: Option<&str>,
    ) -> bool {
        let dir_ok = self.direction == AclDirection::Both || self.direction == direction;
        if !dir_ok {
            return false;
        }
        if let Some(prefix) = self.src
            && !prefix.contains(&src)
        {
            return false;
        }
        if let Some(prefix) = self.dst
            && !prefix.contains(&dst)
        {
            return false;
        }
        if let Some(p) = self.protocol
            && p != protocol
        {
            return false;
        }
        if let Some(port) = self.src_port
            && src_port != Some(port)
        {
            return false;
        }
        if let Some(port) = self.dst_port
            && dst_port != Some(port)
        {
            return false;
        }
        if let Some(expected) = self.peer
            && peer != Some(expected)
        {
            return false;
        }
        if let Some(expected) = self.zone.as_deref()
            && zone != Some(expected)
        {
            return false;
        }
        true
    }
}

impl QosClass {
    pub fn matches(
        &self,
        src: IpAddr,
        dst: IpAddr,
        protocol: u8,
        src_port: Option<u16>,
        dst_port: Option<u16>,
    ) -> bool {
        if let Some(prefix) = self.src
            && !prefix.contains(&src)
        {
            return false;
        }
        if let Some(prefix) = self.dst
            && !prefix.contains(&dst)
        {
            return false;
        }
        if let Some(p) = self.protocol
            && p != protocol
        {
            return false;
        }
        if let Some(port) = self.src_port
            && src_port != Some(port)
        {
            return false;
        }
        if let Some(port) = self.dst_port
            && dst_port != Some(port)
        {
            return false;
        }
        true
    }
}
