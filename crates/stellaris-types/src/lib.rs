//! Shared data types for Stellaris Linking.

pub mod config;
pub mod error;
pub mod id;
pub mod policy;
pub mod route;

pub use config::{
    ApiConfig, AuthMode, Config, ControlConfig, ControllerMemberConfig, DataplaneConfig,
    NetworkAuthConfig, NetworkConfig, NodeConfig, PeerConfig, RoutingConfig, StaticRouteConfig,
    TransportConfig,
};
pub use error::{ConfigError, NodeIdParseError};
pub use id::{NetworkId, NodeId, RouteId};
pub use policy::{AclAction, AclConfig, AclDirection, AclRule, QosClass, QosConfig};
pub use route::{
    Action, Match, PathHint, PeerStatus, RibMode, RouteAttributes, RouteChange, RouteEntry,
    RoutePolicy, RouteSource, RouteState, Scope, UpsertStatic,
};
