use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr};
use std::path::Path;

use ipnet::IpNet;
use serde::{Deserialize, Serialize};

use crate::error::ConfigError;
use crate::id::NetworkId;
use crate::policy::{AclConfig, QosConfig};
use crate::route::RibMode;

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

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
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

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NetworkConfig {
    pub name: String,
    pub cidr: IpNet,
    #[serde(default)]
    pub id: Option<NetworkId>,
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
