//! Shared data types for Stellaris Linking.

pub mod config;
pub mod error;
pub mod id;
pub mod ipam;
pub mod policy;
pub mod route;
pub mod util;

pub use config::{
    ApiConfig, AuthMode, Config, ControlConfig, ControllerMemberConfig, DataplaneConfig,
    IpamConfig, IpamMode, MAX_RAFT_ELECTION_TIMEOUT_MS, MIN_RAFT_ELECTION_TIMEOUT_MS,
    NetworkAuthConfig, NetworkConfig, NodeConfig, PeerConfig, RaftTiming, RaftTimingSource,
    RelayModeConfig, RoutingConfig, StaticRouteConfig, TransportConfig,
};
pub use error::{ConfigError, NodeIdParseError};
pub use id::{NetworkId, NodeId, RouteId};
pub use ipam::{AddressPool, AllocStrategy};
pub use policy::{AclAction, AclConfig, AclDenyAction, AclDirection, AclRule, QosClass, QosConfig};
pub use route::{
    Action, Match, PathHint, PeerStatus, RibMode, RouteAttributes, RouteChange, RouteEntry,
    RoutePolicy, RouteSource, RouteState, Scope, UpsertStatic,
};
pub use util::host_prefix;
