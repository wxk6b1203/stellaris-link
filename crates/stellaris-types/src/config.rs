use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr};
use std::path::Path;

use ipnet::IpNet;
use serde::{Deserialize, Serialize};

use crate::error::ConfigError;
use crate::id::{NetworkId, NodeId};
use crate::policy::{AclConfig, QosConfig};
use crate::route::{RibMode, RoutePolicy};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub node: NodeConfig,
    #[serde(default)]
    pub control: ControlConfig,
    pub network: NetworkConfig,
    #[serde(default)]
    pub transport: TransportConfig,
    #[serde(default)]
    pub routing: RoutingConfig,
    #[serde(default)]
    pub dataplane: DataplaneConfig,
    #[serde(default)]
    pub api: ApiConfig,
    #[serde(default)]
    pub acl: AclConfig,
    #[serde(default)]
    pub qos: QosConfig,
    #[serde(default)]
    pub peers: Vec<PeerConfig>,
    #[serde(default)]
    pub routes: Vec<StaticRouteConfig>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NodeConfig {
    pub name: String,
    /// member | controller (MVP controller uses a simple HTTP control plane).
    #[serde(default = "default_role")]
    pub role: String,
    #[serde(default = "default_state_dir")]
    pub state_dir: String,
    /// This node's overlay IP. Required when dataplane is enabled.
    #[serde(default)]
    pub overlay_ip: Option<IpAddr>,
    /// Optional availability-zone / failure-domain label.
    #[serde(default)]
    pub zone: Option<String>,
}

impl Default for NodeConfig {
    fn default() -> Self {
        Self {
            name: "stellaris-node".to_string(),
            role: default_role(),
            state_dir: default_state_dir(),
            overlay_ip: None,
            zone: None,
        }
    }
}

fn default_state_dir() -> String {
    "./state".to_string()
}

fn default_role() -> String {
    "member".to_string()
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ControlConfig {
    /// Controller base URL for members (MVP: HTTP).
    #[serde(default)]
    pub url: Option<String>,
    /// Multiple controllers for active-active fanout (HTTP MVP).
    #[serde(default)]
    pub urls: Vec<String>,
    /// Controller listen address (controller role).
    #[serde(default)]
    pub bind: Option<String>,
    /// Shared secret for snapshot auth (MVP).
    #[serde(default)]
    pub secret: Option<String>,
    /// Controller term/epoch; generated at startup when omitted.
    #[serde(default)]
    pub epoch: Option<u64>,
    /// Membership manifest lifetime in seconds.
    #[serde(default = "default_manifest_ttl")]
    pub manifest_ttl_secs: u64,
    /// Trusted controller NodeIds for verifying Ed25519 snapshots.
    #[serde(default)]
    pub controller_keys: Vec<String>,
    /// Minimum distinct controller signatures for a snapshot (default 1).
    #[serde(default = "default_controller_threshold")]
    pub controller_threshold: usize,
    /// Optional controller-side member allowlist / prefix grants.
    #[serde(default)]
    pub members: Vec<ControllerMemberConfig>,
    /// One-time join tokens accepted by a controller.
    #[serde(default)]
    pub join_tokens: Vec<JoinTokenConfig>,
    /// Member: one-time token used to request admission.
    #[serde(default)]
    pub join_token: Option<String>,
    /// Controller iroh control UDP port (None = HTTP-only).
    #[serde(default)]
    pub iroh_port: Option<u16>,
    /// Member: controller iroh EndpointId (hex).
    #[serde(default)]
    pub endpoint_id: Option<String>,
    /// Member: controller iroh direct addresses.
    #[serde(default)]
    pub addrs: Vec<SocketAddr>,
}

impl Default for ControlConfig {
    fn default() -> Self {
        Self {
            url: None,
            urls: Vec::new(),
            bind: None,
            secret: None,
            epoch: None,
            manifest_ttl_secs: default_manifest_ttl(),
            controller_keys: Vec::new(),
            controller_threshold: 1,
            members: Vec::new(),
            join_tokens: Vec::new(),
            join_token: None,
            iroh_port: None,
            endpoint_id: None,
            addrs: Vec::new(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct JoinTokenConfig {
    pub token: String,
    #[serde(default)]
    pub prefixes: Vec<IpNet>,
    #[serde(default)]
    pub capabilities: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ControllerMemberConfig {
    pub node_id: String,
    #[serde(default)]
    pub overlay_ip: Option<IpAddr>,
    /// Prefixes this member may advertise; empty means only its overlay /32.
    #[serde(default)]
    pub prefixes: Vec<IpNet>,
    #[serde(default)]
    pub capabilities: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NetworkConfig {
    pub name: String,
    pub cidr: IpNet,
    #[serde(default)]
    pub id: Option<NetworkId>,
    #[serde(default)]
    pub auth: NetworkAuthConfig,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthMode {
    /// No membership authentication (development only).
    #[default]
    None,
    /// Shared network secret with mutual HMAC challenge-response.
    Psk,
    /// Controller-signed membership manifest (design; not implemented yet).
    Controller,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct NetworkAuthConfig {
    #[serde(default)]
    pub mode: AuthMode,
    #[serde(default)]
    pub secret: Option<String>,
    /// Optional allowed peer NodeIds; empty means any holder of the PSK.
    #[serde(default)]
    pub allowed_nodes: Vec<NodeId>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TransportConfig {
    #[serde(default)]
    pub relay_urls: Vec<String>,
    #[serde(default = "default_true")]
    pub listen: bool,
    /// Disable iroh relays entirely (LAN/direct-only tests).
    #[serde(default)]
    pub disable_relay: bool,
    /// Fixed UDP port for iroh (None = random).
    #[serde(default)]
    pub listen_port: Option<u16>,
    /// Underlay addresses advertised via LSA for auto-discovery.
    #[serde(default)]
    pub advertise: Vec<SocketAddr>,
}

impl Default for TransportConfig {
    fn default() -> Self {
        Self {
            relay_urls: Vec::new(),
            listen: true,
            disable_relay: false,
            listen_port: None,
            advertise: Vec::new(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RoutingConfig {
    #[serde(default)]
    pub rib_mode: RibMode,
    #[serde(default = "default_max_routes")]
    pub max_routes: usize,
    #[serde(default = "default_ecmp_max")]
    pub ecmp_max: usize,
    /// Prefer same-zone routes by bumping their local_pref at install time.
    #[serde(default = "default_true")]
    pub prefer_same_zone: bool,
    /// Enable peer-to-peer LSA exchange over iroh control streams.
    #[serde(default)]
    pub link_state: bool,
    /// Route policy rules applied to the RIB before FIB compilation.
    #[serde(default)]
    pub policies: Vec<RoutePolicy>,
    /// Extra metric for links that cross availability zones.
    #[serde(default = "default_cross_zone_penalty")]
    pub cross_zone_penalty: u32,
}

impl Default for RoutingConfig {
    fn default() -> Self {
        Self {
            rib_mode: RibMode::Full,
            max_routes: 10_000,
            ecmp_max: 8,
            prefer_same_zone: true,
            link_state: false,
            policies: Vec::new(),
            cross_zone_penalty: default_cross_zone_penalty(),
        }
    }
}

fn default_max_routes() -> usize {
    10_000
}

fn default_ecmp_max() -> usize {
    8
}

fn default_cross_zone_penalty() -> u32 {
    20
}

fn default_controller_threshold() -> usize {
    1
}

fn default_manifest_ttl() -> u64 {
    3600
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DataplaneConfig {
    #[serde(default)]
    pub enabled: bool,
    /// Prefixes this node forwards to its underlay (subnet gateway).
    #[serde(default)]
    pub advertise: Vec<IpNet>,
    /// Enable MASQUERADE for advertised prefixes (not required if the underlay has a return route).
    #[serde(default)]
    pub nat: bool,
    #[serde(default = "default_tun_name")]
    pub tun_name: String,
    #[serde(default = "default_mtu")]
    pub mtu: u16,
}

impl Default for DataplaneConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            advertise: Vec::new(),
            nat: false,
            tun_name: default_tun_name(),
            mtu: default_mtu(),
        }
    }
}

fn default_tun_name() -> String {
    "stellaris0".to_string()
}

fn default_mtu() -> u16 {
    1280
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ApiConfig {
    #[serde(default = "default_api_bind")]
    pub bind: String,
    #[serde(default)]
    pub token: Option<String>,
}

impl Default for ApiConfig {
    fn default() -> Self {
        Self {
            bind: default_api_bind(),
            token: None,
        }
    }
}

fn default_api_bind() -> String {
    "127.0.0.1:7777".to_string()
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PeerConfig {
    pub name: String,
    /// iroh endpoint id (Ed25519 public key, hex).
    pub endpoint_id: String,
    pub overlay_ip: IpAddr,
    #[serde(default)]
    pub addrs: Vec<SocketAddr>,
    #[serde(default)]
    pub relay_url: Option<String>,
    /// Prefixes reachable behind this peer (subnet gateway).
    #[serde(default)]
    pub advertised: Vec<IpNet>,
    /// Optional availability-zone label.
    #[serde(default)]
    pub zone: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StaticRouteConfig {
    pub prefix: IpNet,
    /// Peer name from [[peers]].
    pub via: String,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct PeersConfig {
    #[serde(default)]
    pub peers: Vec<PeerConfig>,
}

fn default_true() -> bool {
    true
}

impl Config {
    pub fn load(path: impl AsRef<Path>) -> Result<Self, ConfigError> {
        let path = path.as_ref();
        let text = std::fs::read_to_string(path)
            .map_err(|e| ConfigError::Io(path.display().to_string(), e.to_string()))?;
        let cfg: Config = toml::from_str(&text)
            .map_err(|e| ConfigError::Parse(path.display().to_string(), e.to_string()))?;
        cfg.validate()?;
        Ok(cfg)
    }

    pub fn from_toml(text: &str) -> Result<Self, ConfigError> {
        let cfg: Config =
            toml::from_str(text).map_err(|e| ConfigError::Parse("inline".into(), e.to_string()))?;
        cfg.validate()?;
        Ok(cfg)
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.node.name.trim().is_empty() {
            return Err(ConfigError::Invalid("node.name must not be empty".into()));
        }
        if self.network.name.trim().is_empty() {
            return Err(ConfigError::Invalid(
                "network.name must not be empty".into(),
            ));
        }
        if self.network.auth.mode == AuthMode::Psk
            && self
                .network
                .auth
                .secret
                .as_deref()
                .map(str::trim)
                .is_none_or(str::is_empty)
        {
            return Err(ConfigError::Invalid(
                "network.auth.secret is required when auth.mode = psk".into(),
            ));
        }
        if self.control.manifest_ttl_secs == 0 {
            return Err(ConfigError::Invalid(
                "control.manifest_ttl_secs must be > 0".into(),
            ));
        }
        if self.control.controller_threshold == 0 {
            return Err(ConfigError::Invalid(
                "control.controller_threshold must be > 0".into(),
            ));
        }
        if !self.control.controller_keys.is_empty()
            && self.control.controller_threshold > self.control.controller_keys.len()
        {
            return Err(ConfigError::Invalid(
                "control.controller_threshold exceeds controller_keys".into(),
            ));
        }
        for key in &self.control.controller_keys {
            key.parse::<NodeId>()
                .map_err(|e| ConfigError::Invalid(format!("control.controller_keys: {e}")))?;
        }
        let mut join_tokens = HashSet::new();
        for join in &self.control.join_tokens {
            if join.token.trim().is_empty() {
                return Err(ConfigError::Invalid(
                    "control.join_tokens token must not be empty".into(),
                ));
            }
            if !join_tokens.insert(join.token.clone()) {
                return Err(ConfigError::Invalid(
                    "duplicate control.join_tokens token".into(),
                ));
            }
        }
        let mut member_ids = HashSet::new();
        for member in &self.control.members {
            let node: NodeId = member
                .node_id
                .parse()
                .map_err(|e| ConfigError::Invalid(format!("control.members: {e}")))?;
            if !member_ids.insert(node) {
                return Err(ConfigError::Invalid(format!(
                    "duplicate controller member {}",
                    member.node_id
                )));
            }
        }
        if self.network.auth.mode == AuthMode::Controller {
            return Err(ConfigError::Invalid(
                "network.auth.mode = controller is not implemented yet".into(),
            ));
        }
        if self.dataplane.mtu < 576 {
            return Err(ConfigError::Invalid("dataplane.mtu must be >= 576".into()));
        }
        for rule in &self.acl.rules {
            if rule.name.trim().is_empty() {
                return Err(ConfigError::Invalid(
                    "acl rule name must not be empty".into(),
                ));
            }
        }
        if self.qos.queue_depth == Some(0) {
            return Err(ConfigError::Invalid("qos.queue_depth must be > 0".into()));
        }
        for class in &self.qos.classes {
            if class.name.trim().is_empty() {
                return Err(ConfigError::Invalid(
                    "qos class name must not be empty".into(),
                ));
            }
            if class.dscp > 63 {
                return Err(ConfigError::Invalid(format!(
                    "qos class {} dscp must be <= 63",
                    class.name
                )));
            }
            if class.rate_pps == Some(0) {
                return Err(ConfigError::Invalid(format!(
                    "qos class {} rate_pps must be > 0",
                    class.name
                )));
            }
            if class.burst == Some(0) {
                return Err(ConfigError::Invalid(format!(
                    "qos class {} burst must be > 0",
                    class.name
                )));
            }
        }
        if self.routing.ecmp_max == 0 {
            return Err(ConfigError::Invalid("routing.ecmp_max must be > 0".into()));
        }
        if self.api.bind.parse::<SocketAddr>().is_err() {
            return Err(ConfigError::Invalid(format!(
                "api.bind is not a socket address: {}",
                self.api.bind
            )));
        }

        let mut names = HashSet::new();
        let mut ips = HashSet::new();
        for peer in &self.peers {
            if peer.name.trim().is_empty() {
                return Err(ConfigError::Invalid("peer.name must not be empty".into()));
            }
            if !names.insert(peer.name.clone()) {
                return Err(ConfigError::Invalid(format!(
                    "duplicate peer name: {}",
                    peer.name
                )));
            }
            if !ips.insert(peer.overlay_ip) {
                return Err(ConfigError::Invalid(format!(
                    "duplicate peer overlay_ip: {}",
                    peer.overlay_ip
                )));
            }
            if !self.network.cidr.contains(&peer.overlay_ip) {
                return Err(ConfigError::Invalid(format!(
                    "peer {} overlay_ip {} is outside network {}",
                    peer.name, peer.overlay_ip, self.network.cidr
                )));
            }
            peer.endpoint_id.parse::<crate::id::NodeId>().map_err(|e| {
                ConfigError::Invalid(format!("peer {} endpoint_id: {e}", peer.name))
            })?;
        }

        if let Some(ip) = self.node.overlay_ip
            && !self.network.cidr.contains(&ip)
        {
            return Err(ConfigError::Invalid(format!(
                "node.overlay_ip {ip} is outside network {}",
                self.network.cidr
            )));
        }
        if self.dataplane.enabled && self.node.overlay_ip.is_none() {
            return Err(ConfigError::Invalid(
                "node.overlay_ip is required when dataplane.enabled = true".into(),
            ));
        }

        for route in &self.routes {
            if !names.contains(&route.via) {
                return Err(ConfigError::Invalid(format!(
                    "route {} via unknown peer {}",
                    route.prefix, route.via
                )));
            }
        }

        Ok(())
    }

    pub fn peer_by_name(&self, name: &str) -> Option<&PeerConfig> {
        self.peers.iter().find(|p| p.name == name)
    }

    pub fn peer_by_endpoint(&self, endpoint_id: &str) -> Option<&PeerConfig> {
        self.peers.iter().find(|p| p.endpoint_id == endpoint_id)
    }
}
