use std::net::IpAddr;

use ipnet::IpNet;
use serde::{Deserialize, Serialize};

use crate::id::{NetworkId, NodeId, RouteId};

/// Where a route came from. Lower admin distance wins.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RouteSource {
    Connected,
    Static,
    Controller,
    LinkState,
    Aggregate,
    Default,
}

impl RouteSource {
    pub const fn admin_distance(self) -> u8 {
        match self {
            Self::Connected => 0,
            Self::Static => 1,
            Self::Controller => 20,
            Self::LinkState => 100,
            Self::Aggregate => 200,
            Self::Default => 255,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RouteState {
    Active,
    Stale,
    Withdrawn,
    Filtered,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PathHint {
    Auto,
    Direct,
    Relay,
    AvoidRelay,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct RouteAttributes {
    pub rtt_ms: Option<u16>,
    pub loss_ppm: Option<u32>,
    pub bandwidth_kbps: Option<u64>,
    pub energy_cost: Option<u32>,
    pub region: Option<String>,
    /// Availability-zone label of the path/peer (for AZ-aware preference).
    pub zone: Option<String>,
    pub tags: Vec<String>,
}

/// A route in the RIB / intent space.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RouteEntry {
    pub id: RouteId,
    pub network: NetworkId,
    pub prefix: IpNet,
    pub source: RouteSource,
    pub origin: NodeId,
    pub next_hop: NodeId,
    pub admin_distance: u8,
    pub local_pref: u32,
    pub metric: u32,
    pub weight: u16,
    pub pin: bool,
    pub state: RouteState,
    pub generation: u64,
    pub expires_at: Option<time::OffsetDateTime>,
    pub attrs: RouteAttributes,
}

impl RouteEntry {
    pub fn new(
        network: NetworkId,
        prefix: IpNet,
        source: RouteSource,
        origin: NodeId,
        next_hop: NodeId,
    ) -> Self {
        Self {
            id: RouteId::new(),
            network,
            prefix,
            source,
            origin,
            next_hop,
            admin_distance: source.admin_distance(),
            local_pref: 0,
            metric: 0,
            weight: 1,
            pin: false,
            state: RouteState::Active,
            generation: 0,
            expires_at: None,
            attrs: RouteAttributes::default(),
        }
    }

    pub fn is_active_at(&self, now: time::OffsetDateTime) -> bool {
        self.state == RouteState::Active && self.expires_at.map(|t| t > now).unwrap_or(true)
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Scope {
    #[default]
    Local,
    Network,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UpsertStatic {
    pub prefix: IpNet,
    pub via: NodeId,
    pub admin_distance: Option<u8>,
    pub local_pref: Option<u32>,
    pub metric: Option<u32>,
    pub weight: Option<u16>,
    pub pin: bool,
    pub expires_at: Option<time::OffsetDateTime>,
    pub attrs: RouteAttributes,
}

/// A route adjustment operation.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum RouteChange {
    UpsertStatic(UpsertStatic),
    Delete {
        id: RouteId,
    },
    Pin {
        prefix: IpNet,
        next_hop: NodeId,
        ttl_secs: Option<u64>,
    },
    Unpin {
        prefix: IpNet,
    },
    Drain {
        node: NodeId,
        grace_secs: u64,
    },
    Reset {
        prefix: Option<IpNet>,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RoutePolicy {
    pub id: String,
    pub priority: u32,
    pub match_: Match,
    pub action: Action,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Match {
    pub prefix: Option<IpNet>,
    pub peer: Option<NodeId>,
    pub tag: Option<String>,
    pub source: Option<RouteSource>,
    pub region: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Action {
    Accept,
    Deny,
    SetAdminDistance { value: u8 },
    SetLocalPref { value: u32 },
    SetMetric { value: u32 },
    SetPathHint { value: PathHint },
    SetWeight { value: u16 },
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RibMode {
    #[default]
    Full,
    Cache,
    None,
}

/// A peer as exposed by the agent/API.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PeerStatus {
    pub node_id: NodeId,
    pub name: String,
    pub overlay_ip: IpAddr,
    pub endpoint_id: String,
    pub connected: bool,
    pub path: Option<String>,
    pub rtt_ms: Option<u64>,
}
