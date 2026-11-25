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

/// How a member obtains its overlay address.
#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum IpamMode {
    /// `node.overlay_ip` is configured by the operator.
    #[default]
    Static,
    /// The controller allocates an address and returns it in the credential.
    Auto,
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
    /// Static (default) or controller-allocated overlay address.
    #[serde(default)]
    pub ipam: IpamMode,
}

impl Default for NodeConfig {
    fn default() -> Self {
        Self {
            name: "stellaris-node".to_string(),
            role: default_role(),
            state_dir: default_state_dir(),
            overlay_ip: None,
            zone: None,
            ipam: IpamMode::Static,
        }
    }
}

fn default_state_dir() -> String {
    "./state".to_string()
}

fn default_role() -> String {
    "member".to_string()
}

/// Explicit relay policy; `auto` keeps backwards-compatible behaviour:
/// custom relays when `relay_urls` is non-empty, otherwise the N0 preset.
#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RelayModeConfig {
    #[default]
    Auto,
    N0,
    Custom,
    Disabled,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RaftPeerConfig {
    pub id: u64,
    pub addr: String,
}

/// Default minimum Raft election timeout, sized for the supported three-region
/// controller topology (Shenzhen / Shanghai / Chengdu).
///
/// openraft's default of 150 ms is too short for vote RPCs that cross regions:
/// the real three-region rolling restart failed with
/// `timeout after 150ms when Vote` until this value was raised. 1000 ms is the
/// value that made that rolling restart pass, so it is the default here.
pub const DEFAULT_RAFT_ELECTION_TIMEOUT_MS: u64 = 1000;

/// Lower bound for `control.raft_election_timeout_ms`.
///
/// Below this the derived heartbeat (`min / 4`) and the openraft validation
/// rule `heartbeat_interval < election_timeout_min` leave no room for RPC
/// jitter, so a smaller value buys nothing.
pub const MIN_RAFT_ELECTION_TIMEOUT_MS: u64 = 50;

/// Upper bound for `control.raft_election_timeout_ms`.
///
/// Beyond a minute a wedged leader keeps serving reads for too long and a
/// crashed controller stalls the control plane for over two minutes.
pub const MAX_RAFT_ELECTION_TIMEOUT_MS: u64 = 60_000;

/// Resolved openraft election/heartbeat timing.
///
/// Derived from `control.raft_election_timeout_ms`, or from the cross-region
/// default when that key is absent.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RaftTiming {
    /// `election_timeout_min` handed to openraft.
    pub election_timeout_min_ms: u64,
    /// `election_timeout_max`, always twice the minimum.
    pub election_timeout_max_ms: u64,
    /// `heartbeat_interval`, always a quarter of the minimum.
    pub heartbeat_interval_ms: u64,
    /// Where the minimum came from.
    pub source: RaftTimingSource,
}

/// Origin of the effective Raft election timeout.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum RaftTimingSource {
    /// No explicit value: [`DEFAULT_RAFT_ELECTION_TIMEOUT_MS`].
    #[serde(rename = "default-cross-region")]
    DefaultCrossRegion,
    /// `control.raft_election_timeout_ms`.
    #[serde(rename = "config")]
    Config,
    /// Deprecated `STELLARIS_RAFT_ELECTION_TIMEOUT_MS` environment override.
    #[serde(rename = "env")]
    Env,
}

impl RaftTimingSource {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::DefaultCrossRegion => "default-cross-region",
            Self::Config => "config",
            Self::Env => "env",
        }
    }
}

impl RaftTiming {
    /// Derive max timeout and heartbeat from a minimum election timeout.
    ///
    /// The minimum is clamped to the supported range so that the derived
    /// values always satisfy openraft's `validate()` rules.
    pub fn from_min(min_ms: u64, source: RaftTimingSource) -> Self {
        let min = min_ms.clamp(MIN_RAFT_ELECTION_TIMEOUT_MS, MAX_RAFT_ELECTION_TIMEOUT_MS);
        Self {
            election_timeout_min_ms: min,
            election_timeout_max_ms: min.saturating_mul(2),
            heartbeat_interval_ms: (min / 4).max(10),
            source,
        }
    }
}

impl Default for RaftTiming {
    fn default() -> Self {
        Self::from_min(
            DEFAULT_RAFT_ELECTION_TIMEOUT_MS,
            RaftTimingSource::DefaultCrossRegion,
        )
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct IpamConfig {
    /// Controller-side pools. IPAM is enabled when this list is non-empty.
    #[serde(default)]
    pub pools: Vec<crate::ipam::AddressPool>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ControlConfig {
    /// Controller base URL for members (MVP: HTTP).
    #[serde(default)]
    pub url: Option<String>,
    /// Deprecated: active-active fanout was removed. Non-empty is rejected.
    #[serde(default)]
    pub urls: Vec<String>,
    /// Controller listen address (controller role).
    #[serde(default)]
    pub bind: Option<String>,
    /// Shared secret for snapshot auth (MVP).
    #[serde(default)]
    pub secret: Option<String>,
    /// Optional admin secret for revoke/route writes. Falls back to `secret`
    /// when unset; setting it separates member and admin authority.
    #[serde(default)]
    pub admin_secret: Option<String>,
    /// Controller term/epoch; generated at startup when omitted.
    #[serde(default)]
    pub epoch: Option<u64>,
    /// Optional controller leader NodeId. Non-leader controllers reject writes.
    #[serde(default)]
    pub leader_id: Option<String>,
    /// Previous shared secrets accepted during rotation.
    #[serde(default)]
    pub previous_secrets: Vec<String>,
    /// Enable the Raft controller and persist here.
    #[serde(default)]
    pub raft_dir: Option<String>,
    /// Raft node id (defaults to 1).
    #[serde(default)]
    pub raft_id: Option<u64>,
    /// Internal Raft HTTP bind address.
    #[serde(default)]
    pub raft_bind: Option<String>,
    /// Other controller Raft nodes: id + HTTP address.
    #[serde(default)]
    pub raft_peers: Vec<RaftPeerConfig>,
    /// Shared secret for internal Raft RPC authentication.
    #[serde(default)]
    pub raft_secret: Option<String>,
    /// Initialize a pristine cluster with the configured peers.
    #[serde(default)]
    pub raft_bootstrap: bool,
    /// Minimum Raft election timeout in milliseconds.
    ///
    /// The maximum timeout is twice this value and the leader heartbeat is a
    /// quarter of it. When omitted the cross-region default
    /// [`DEFAULT_RAFT_ELECTION_TIMEOUT_MS`] is used, because the openraft
    /// default (150 ms) is too short for vote RPCs between regions.
    #[serde(default)]
    pub raft_election_timeout_ms: Option<u64>,
    /// Raft internal HTTPS certificate/key.
    #[serde(default)]
    pub raft_tls_cert: Option<String>,
    #[serde(default)]
    pub raft_tls_key: Option<String>,
    /// CA used to verify peer Raft HTTPS servers.
    #[serde(default)]
    pub raft_tls_ca: Option<String>,
    /// Development only: accept invalid Raft peer certificates.
    #[serde(default)]
    pub raft_tls_insecure: bool,
    /// Client certificate/key for Raft mTLS.
    #[serde(default)]
    pub raft_tls_client_cert: Option<String>,
    #[serde(default)]
    pub raft_tls_client_key: Option<String>,
    /// Require client certificates on the Raft HTTPS server.
    #[serde(default)]
    pub raft_tls_require_client_cert: bool,
    /// Membership manifest lifetime in seconds.
    #[serde(default = "default_manifest_ttl")]
    pub manifest_ttl_secs: u64,
    /// Leader-side LSA lifetime in seconds (Raft mode); stale LSAs are removed
    /// from the replicated model by an ``ExpireLsa`` command.
    #[serde(default = "default_lsa_ttl")]
    pub lsa_ttl_secs: u64,
    /// Controller-managed overlay address pools.
    #[serde(default)]
    pub ipam: IpamConfig,
    /// Trusted controller NodeIds for verifying Ed25519 snapshots.
    #[serde(default)]
    pub controller_keys: Vec<String>,
    /// Accept controller snapshots that carry neither an Ed25519 signature nor
    /// a shared-secret HMAC. Development only; rejected by default.
    #[serde(default)]
    pub allow_unsigned_snapshot: bool,
    /// Deprecated: fanout threshold was removed; only 1 is accepted.
    #[serde(default = "default_controller_threshold")]
    pub controller_threshold: usize,
    /// Optional controller-side member allowlist / prefix grants.
    #[serde(default)]
    pub members: Vec<ControllerMemberConfig>,
    /// Lifetime of a signed membership credential in seconds. Members renew
    /// at two thirds of this value; expired credentials are rejected.
    #[serde(default = "default_credential_ttl")]
    pub credential_ttl_secs: u64,
    /// Auto-add controller-listed members as peers (default true).
    #[serde(default = "default_true")]
    pub discover_members: bool,
    /// Apply controller snapshot routes (default true).
    #[serde(default = "default_true")]
    pub apply_routes: bool,
    /// Controller HTTPS certificate PEM path (requires tls_key).
    #[serde(default)]
    pub tls_cert: Option<String>,
    /// Controller HTTPS private key PEM path (requires tls_cert).
    #[serde(default)]
    pub tls_key: Option<String>,
    /// Member: PEM CA used to verify controller HTTPS.
    #[serde(default)]
    pub tls_ca: Option<String>,
    /// Member: skip controller HTTPS certificate verification (development only).
    #[serde(default)]
    pub tls_insecure: bool,
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
            admin_secret: None,
            epoch: None,
            leader_id: None,
            previous_secrets: Vec::new(),
            raft_dir: None,
            raft_id: None,
            raft_bind: None,
            raft_peers: Vec::new(),
            raft_secret: None,
            raft_bootstrap: false,
            raft_election_timeout_ms: None,
            raft_tls_cert: None,
            raft_tls_key: None,
            raft_tls_ca: None,
            raft_tls_insecure: false,
            raft_tls_client_cert: None,
            raft_tls_client_key: None,
            raft_tls_require_client_cert: false,
            manifest_ttl_secs: default_manifest_ttl(),
            lsa_ttl_secs: default_lsa_ttl(),
            ipam: IpamConfig::default(),
            controller_keys: Vec::new(),
            allow_unsigned_snapshot: false,
            controller_threshold: 1,
            members: Vec::new(),
            credential_ttl_secs: default_credential_ttl(),
            discover_members: true,
            apply_routes: true,
            tls_cert: None,
            tls_key: None,
            tls_ca: None,
            tls_insecure: false,
            iroh_port: None,
            endpoint_id: None,
            addrs: Vec::new(),
        }
    }
}

impl ControlConfig {
    /// Effective Raft election timing.
    ///
    /// Explicit `raft_election_timeout_ms` wins; otherwise the cross-region
    /// default applies. The value is validated by [`Config::validate`].
    pub fn raft_timing(&self) -> RaftTiming {
        match self.raft_election_timeout_ms {
            Some(min) => RaftTiming::from_min(min, RaftTimingSource::Config),
            None => RaftTiming::default(),
        }
    }
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
    /// WireGuard-style static allowlist: only NodeIds listed in `[[peers]]`
    /// may connect. The iroh handshake already authenticates the node key, so
    /// no extra credential or shared secret is needed.
    Static,
    /// Controller-signed membership credential presented during the iroh
    /// handshake; peers verify it against `control.controller_keys`.
    Controller,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct NetworkAuthConfig {
    #[serde(default)]
    pub mode: AuthMode,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TransportConfig {
    #[serde(default)]
    pub relay_urls: Vec<String>,
    #[serde(default = "default_true")]
    pub listen: bool,
    /// Disable iroh relays entirely (LAN/direct-only tests).
    /// Deprecated alias for `relay_mode = "disabled"`.
    #[serde(default)]
    pub disable_relay: bool,
    /// Relay policy: auto/n0/custom/disabled. `custom` requires relay_urls.
    #[serde(default)]
    pub relay_mode: RelayModeConfig,
    /// Disable direct-address discovery so tests can force relay-only paths.
    #[serde(default)]
    pub disable_discovery: bool,
    /// Allow UDP/mDNS discovery while `network.auth.mode = "none"`.
    /// Development only; discovery is rejected without an authenticator by default.
    #[serde(default)]
    pub allow_unauthenticated_discovery: bool,
    /// Fixed UDP port for iroh (None = random).
    #[serde(default)]
    pub listen_port: Option<u16>,
    /// Underlay addresses advertised via LSA for auto-discovery.
    #[serde(default)]
    pub advertise: Vec<SocketAddr>,
    /// Bind iroh UDP to this underlay IP (None = 0.0.0.0).
    /// Set this to avoid iroh using the TUN/overlay address as a direct path.
    #[serde(default)]
    pub bind_ip: Option<IpAddr>,
    /// UDP broadcast bootstrap discovery port (None = disabled).
    #[serde(default)]
    pub discovery_port: Option<u16>,
    /// Optional directed broadcast target (e.g. 192.168.1.255:47000).
    #[serde(default)]
    pub discovery_broadcast: Option<SocketAddr>,
    /// Enable mDNS/DNS-SD bootstrap discovery (`_stellaris._udp.local.`).
    #[serde(default)]
    pub mdns: bool,
    /// mDNS UDP port (default 5353; useful for isolated tests).
    #[serde(default)]
    pub mdns_port: Option<u16>,
    /// Restrict mDNS to one interface name (e.g. eth0/en0).
    #[serde(default)]
    pub mdns_interface: Option<String>,
}

impl Default for TransportConfig {
    fn default() -> Self {
        Self {
            relay_urls: Vec::new(),
            listen: true,
            disable_relay: false,
            relay_mode: RelayModeConfig::Auto,
            disable_discovery: false,
            allow_unauthenticated_discovery: false,
            listen_port: None,
            advertise: Vec::new(),
            bind_ip: None,
            discovery_port: None,
            discovery_broadcast: None,
            mdns: false,
            mdns_port: None,
            mdns_interface: None,
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

fn default_true() -> bool {
    true
}

fn default_controller_threshold() -> usize {
    1
}

fn default_lsa_ttl() -> u64 {
    30
}

fn default_manifest_ttl() -> u64 {
    3600
}

fn default_credential_ttl() -> u64 {
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
    /// Install a default route (`0.0.0.0/0` or `::/0`) learned from the RIB.
    ///
    /// Disabled by default: a leaked or misconfigured default route would send
    /// all host traffic into the TUN and can break the machine's connectivity.
    #[serde(default)]
    pub allow_default_route: bool,
    /// Replace an existing non-stellaris OS route for the same prefix.
    ///
    /// Disabled by default: conflicting routes (Tailscale, admin routes, other
    /// VPNs) are logged and skipped instead of being overwritten.
    #[serde(default)]
    pub replace_existing_routes: bool,
}

impl Default for DataplaneConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            advertise: Vec::new(),
            nat: false,
            tun_name: default_tun_name(),
            mtu: default_mtu(),
            allow_default_route: false,
            replace_existing_routes: false,
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
    /// Optional read-only bearer token (mutations still require `token`).
    #[serde(default)]
    pub read_token: Option<String>,
    /// Previous admin tokens accepted during rotation.
    #[serde(default)]
    pub previous_tokens: Vec<String>,
    /// HTTPS certificate PEM path (requires tls_key).
    #[serde(default)]
    pub tls_cert: Option<String>,
    /// HTTPS private key PEM path (requires tls_cert).
    #[serde(default)]
    pub tls_key: Option<String>,
}

impl Default for ApiConfig {
    fn default() -> Self {
        Self {
            bind: default_api_bind(),
            token: None,
            read_token: None,
            previous_tokens: Vec::new(),
            tls_cert: None,
            tls_key: None,
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
        if let Some(overlay) = self.node.overlay_ip
            && !self.network.cidr.contains(&overlay)
        {
            return Err(ConfigError::Invalid(format!(
                "node.overlay_ip {overlay} is outside network.cidr {}",
                self.network.cidr
            )));
        }
        if self.node.ipam == IpamMode::Auto {
            if self.node.role == "controller" {
                return Err(ConfigError::Invalid(
                    "node.ipam = auto is only valid for members".into(),
                ));
            }
            if self.node.overlay_ip.is_some() {
                return Err(ConfigError::Invalid(
                    "node.ipam = auto conflicts with node.overlay_ip".into(),
                ));
            }
            if self.network.auth.mode != AuthMode::Controller {
                return Err(ConfigError::Invalid(
                    "node.ipam = auto requires network.auth.mode = controller".into(),
                ));
            }
            if self.control.url.is_none() && self.control.endpoint_id.is_none() {
                return Err(ConfigError::Invalid(
                    "node.ipam = auto requires control.url or control.endpoint_id".into(),
                ));
            }
        } else if self.dataplane.enabled && self.node.overlay_ip.is_none() {
            return Err(ConfigError::Invalid(
                "node.overlay_ip is required when dataplane is enabled; set node.ipam = \"auto\" to let the controller allocate one".into(),
            ));
        }
        let mut pool_ids = HashSet::new();
        let mut pool_nets: Vec<(String, IpNet)> = Vec::new();
        for pool in &self.control.ipam.pools {
            if pool.id.trim().is_empty() {
                return Err(ConfigError::Invalid(
                    "ipam pool id must not be empty".into(),
                ));
            }
            if !pool_ids.insert(pool.id.clone()) {
                return Err(ConfigError::Invalid(format!(
                    "duplicate ipam pool id {}",
                    pool.id
                )));
            }
            let same_family = matches!(
                (&pool.cidr, &self.network.cidr),
                (IpNet::V4(_), IpNet::V4(_)) | (IpNet::V6(_), IpNet::V6(_))
            );
            if !same_family {
                return Err(ConfigError::Invalid(format!(
                    "ipam pool {} address family differs from network.cidr",
                    pool.id
                )));
            }
            if pool.cidr.prefix_len() < self.network.cidr.prefix_len()
                || !self.network.cidr.contains(&pool.cidr.network())
            {
                return Err(ConfigError::Invalid(format!(
                    "ipam pool {} ({}) is outside network.cidr {}",
                    pool.id, pool.cidr, self.network.cidr
                )));
            }
            if let Some((start, end)) = pool.range {
                if !pool.cidr.contains(&start) || !pool.cidr.contains(&end) {
                    return Err(ConfigError::Invalid(format!(
                        "ipam pool {} range is outside {}",
                        pool.id, pool.cidr
                    )));
                }
                let ordered = match (start, end) {
                    (std::net::IpAddr::V4(a), std::net::IpAddr::V4(b)) => {
                        u32::from(a) <= u32::from(b)
                    }
                    (std::net::IpAddr::V6(a), std::net::IpAddr::V6(b)) => {
                        u128::from(a) <= u128::from(b)
                    }
                    _ => false,
                };
                if !ordered {
                    return Err(ConfigError::Invalid(format!(
                        "ipam pool {} range start must be <= end and use one family",
                        pool.id
                    )));
                }
            }
            for excluded in &pool.exclude {
                if !pool.cidr.contains(&excluded.network())
                    || excluded.prefix_len() < pool.cidr.prefix_len()
                {
                    return Err(ConfigError::Invalid(format!(
                        "ipam pool {} exclude {} is outside {}",
                        pool.id, excluded, pool.cidr
                    )));
                }
            }
            if pool.lease_secs == 0 {
                return Err(ConfigError::Invalid(format!(
                    "ipam pool {} lease_secs must be > 0",
                    pool.id
                )));
            }
            if matches!(pool.cidr, IpNet::V4(_))
                && pool.range.is_none()
                && pool.cidr.prefix_len() < 16
            {
                return Err(ConfigError::Invalid(format!(
                    "ipam pool {} is larger than /16; set an explicit range",
                    pool.id
                )));
            }
            for (other_id, other) in &pool_nets {
                if other.contains(&pool.cidr.network()) || pool.cidr.contains(&other.network()) {
                    return Err(ConfigError::Invalid(format!(
                        "ipam pools {other_id} and {} overlap",
                        pool.id
                    )));
                }
            }
            pool_nets.push((pool.id.clone(), pool.cidr));
        }
        if self.control.credential_ttl_secs == 0 {
            return Err(ConfigError::Invalid(
                "control.credential_ttl_secs must be > 0".into(),
            ));
        }
        if self.control.lsa_ttl_secs == 0 {
            return Err(ConfigError::Invalid(
                "control.lsa_ttl_secs must be > 0".into(),
            ));
        }
        if self.control.manifest_ttl_secs == 0 {
            return Err(ConfigError::Invalid(
                "control.manifest_ttl_secs must be > 0".into(),
            ));
        }
        for (name, value) in [
            ("api.token", self.api.token.as_deref()),
            ("api.read_token", self.api.read_token.as_deref()),
            ("control.secret", self.control.secret.as_deref()),
            ("control.admin_secret", self.control.admin_secret.as_deref()),
            ("control.raft_secret", self.control.raft_secret.as_deref()),
        ] {
            if value.is_some_and(|value| value.trim().is_empty()) {
                return Err(ConfigError::Invalid(format!(
                    "{name} must not be empty when set"
                )));
            }
        }
        for token in &self.api.previous_tokens {
            if token.trim().is_empty() {
                return Err(ConfigError::Invalid(
                    "api.previous_tokens entries must not be empty".into(),
                ));
            }
        }
        for secret in &self.control.previous_secrets {
            if secret.trim().is_empty() {
                return Err(ConfigError::Invalid(
                    "control.previous_secrets entries must not be empty".into(),
                ));
            }
        }
        if self.control.raft_tls_cert.is_some() != self.control.raft_tls_key.is_some() {
            return Err(ConfigError::Invalid(
                "control.raft_tls_cert and control.raft_tls_key must be set together".into(),
            ));
        }
        if self.control.raft_tls_client_cert.is_some() != self.control.raft_tls_client_key.is_some()
        {
            return Err(ConfigError::Invalid(
                "control.raft_tls_client_cert and control.raft_tls_client_key must be set together"
                    .into(),
            ));
        }
        if self.control.raft_tls_require_client_cert && self.control.raft_tls_client_cert.is_none()
        {
            return Err(ConfigError::Invalid(
                "control.raft_tls_require_client_cert requires raft_tls_client_cert/key".into(),
            ));
        }
        if self.control.raft_dir.is_some() {
            if self
                .control
                .raft_secret
                .as_deref()
                .is_none_or(|secret| secret.trim().is_empty())
            {
                return Err(ConfigError::Invalid(
                    "control.raft_dir requires a non-empty control.raft_secret".into(),
                ));
            }
            if let Some(bind) = &self.control.raft_bind
                && bind.parse::<SocketAddr>().is_err()
            {
                return Err(ConfigError::Invalid(format!(
                    "control.raft_bind: {bind} is not a socket address"
                )));
            }
            let mut ids = HashSet::new();
            for peer in &self.control.raft_peers {
                if !ids.insert(peer.id) {
                    return Err(ConfigError::Invalid(format!(
                        "duplicate control.raft_peers id {}",
                        peer.id
                    )));
                }
                if peer.addr.parse::<SocketAddr>().is_err() {
                    return Err(ConfigError::Invalid(format!(
                        "control.raft_peers {}: {} is not a socket address",
                        peer.id, peer.addr
                    )));
                }
            }
        }
        if let Some(min) = self.control.raft_election_timeout_ms
            && !(MIN_RAFT_ELECTION_TIMEOUT_MS..=MAX_RAFT_ELECTION_TIMEOUT_MS).contains(&min)
        {
            return Err(ConfigError::Invalid(format!(
                "control.raft_election_timeout_ms must be between \
                 {MIN_RAFT_ELECTION_TIMEOUT_MS} and {MAX_RAFT_ELECTION_TIMEOUT_MS} ms (got {min})"
            )));
        }
        for key in &self.control.controller_keys {
            key.parse::<NodeId>()
                .map_err(|e| ConfigError::Invalid(format!("control.controller_keys: {e}")))?;
        }
        let api_bind: SocketAddr = self
            .api
            .bind
            .parse()
            .map_err(|e| ConfigError::Invalid(format!("api.bind: {e}")))?;
        if !api_bind.ip().is_loopback() && self.api.token.is_none() {
            return Err(ConfigError::Invalid(
                "api.bind is non-loopback but api.token is missing".into(),
            ));
        }
        if let Some(bind) = &self.control.bind {
            let bind: SocketAddr = bind
                .parse()
                .map_err(|e| ConfigError::Invalid(format!("control.bind: {e}")))?;
            if !bind.ip().is_loopback() && self.control.secret.is_none() {
                return Err(ConfigError::Invalid(
                    "control.bind is non-loopback but control.secret is missing".into(),
                ));
            }
        }
        if self.node.role == "controller"
            && self.control.iroh_port.is_some()
            && self.control.secret.is_none()
        {
            return Err(ConfigError::Invalid(
                "controller iroh control requires control.secret".into(),
            ));
        }
        if self.api.tls_cert.is_some() != self.api.tls_key.is_some() {
            return Err(ConfigError::Invalid(
                "api.tls_cert and api.tls_key must be set together".into(),
            ));
        }
        if self.control.tls_cert.is_some() != self.control.tls_key.is_some() {
            return Err(ConfigError::Invalid(
                "control.tls_cert and control.tls_key must be set together".into(),
            ));
        }
        if !self.control.urls.is_empty() {
            return Err(ConfigError::Invalid(
                "control.urls (legacy fanout) was removed; use a single control.url in front of Raft"
                    .into(),
            ));
        }
        if self.control.controller_threshold != 1 {
            return Err(ConfigError::Invalid(
                "control.controller_threshold (legacy fanout) was removed".into(),
            ));
        }
        let mut member_ids = HashSet::new();
        let mut member_overlays = HashSet::new();
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
            if let Some(ip) = member.overlay_ip {
                if !self.network.cidr.contains(&ip) {
                    return Err(ConfigError::Invalid(format!(
                        "controller member {} overlay {ip} is outside network.cidr",
                        member.node_id
                    )));
                }
                if !member_overlays.insert(ip) {
                    return Err(ConfigError::Invalid(format!(
                        "duplicate controller member overlay {ip}"
                    )));
                }
            }
        }
        if self.network.auth.mode == AuthMode::Static
            && self.node.role != "controller"
            && self.peers.is_empty()
        {
            return Err(ConfigError::Invalid(
                "network.auth.mode = static requires at least one [[peers]] entry".into(),
            ));
        }
        if self.network.auth.mode == AuthMode::Controller {
            if self.control.controller_keys.is_empty() {
                return Err(ConfigError::Invalid(
                    "network.auth.mode = controller requires control.controller_keys".into(),
                ));
            }
            if self.node.role != "controller"
                && self.control.endpoint_id.is_none()
                && self.control.url.is_none()
            {
                return Err(ConfigError::Invalid(
                    "network.auth.mode = controller requires control.endpoint_id or control.url"
                        .into(),
                ));
            }
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
        if self.qos.queue_depth_per_priority == Some(0) {
            return Err(ConfigError::Invalid(
                "qos.queue_depth_per_priority must be > 0".into(),
            ));
        }
        if self.qos.queue_bytes == Some(0) {
            return Err(ConfigError::Invalid("qos.queue_bytes must be > 0".into()));
        }
        if self.qos.queue_bytes_per_priority == Some(0) {
            return Err(ConfigError::Invalid(
                "qos.queue_bytes_per_priority must be > 0".into(),
            ));
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
            if class.queue_depth == Some(0) {
                return Err(ConfigError::Invalid(format!(
                    "qos class {} queue_depth must be > 0",
                    class.name
                )));
            }
            if class.rate_bps == Some(0) {
                return Err(ConfigError::Invalid(format!(
                    "qos class {} rate_bps must be > 0",
                    class.name
                )));
            }
            if class.burst_bytes == Some(0) {
                return Err(ConfigError::Invalid(format!(
                    "qos class {} burst_bytes must be > 0",
                    class.name
                )));
            }
            if class.queue_bytes == Some(0) {
                return Err(ConfigError::Invalid(format!(
                    "qos class {} queue_bytes must be > 0",
                    class.name
                )));
            }
        }
        let discovery_enabled = self.transport.discovery_port.is_some() || self.transport.mdns;
        if discovery_enabled
            && self.network.auth.mode == AuthMode::None
            && !self.transport.allow_unauthenticated_discovery
        {
            return Err(ConfigError::Invalid(
                "discovery (discovery_port/mdns) requires controller membership \
                 authentication; set transport.allow_unauthenticated_discovery only for isolated labs"
                    .into(),
            ));
        }
        let relay_mode = match (self.transport.relay_mode, self.transport.disable_relay) {
            (RelayModeConfig::Auto, true) => RelayModeConfig::Disabled,
            (RelayModeConfig::Auto, false) => RelayModeConfig::Auto,
            (RelayModeConfig::Disabled, false) => RelayModeConfig::Disabled,
            (RelayModeConfig::Custom, false) => RelayModeConfig::Custom,
            (RelayModeConfig::N0, false) => RelayModeConfig::N0,
            (_, true) => {
                return Err(ConfigError::Invalid(
                    "transport.disable_relay conflicts with transport.relay_mode".into(),
                ));
            }
        };
        if relay_mode == RelayModeConfig::Custom && self.transport.relay_urls.is_empty() {
            return Err(ConfigError::Invalid(
                "transport.relay_mode = custom requires transport.relay_urls".into(),
            ));
        }
        if relay_mode != RelayModeConfig::Custom
            && relay_mode != RelayModeConfig::Auto
            && !self.transport.relay_urls.is_empty()
        {
            return Err(ConfigError::Invalid(
                "transport.relay_urls is only valid with relay_mode = custom or auto".into(),
            ));
        }
        if !self.transport.listen {
            return Err(ConfigError::Invalid(
                "transport.listen=false is not supported (the transport always listens)".into(),
            ));
        }
        if self.routing.rib_mode != RibMode::Full {
            return Err(ConfigError::Invalid(
                "routing.rib_mode only supports \"full\"; cache/none are not implemented".into(),
            ));
        }
        for policy in &self.routing.policies {
            if matches!(policy.action, crate::route::Action::SetPathHint { .. }) {
                return Err(ConfigError::Invalid(format!(
                    "routing policy {} uses set_path_hint, which is not implemented",
                    policy.id
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
        if self.dataplane.enabled
            && self.node.overlay_ip.is_none()
            && self.node.ipam != IpamMode::Auto
        {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn overlay_ip_must_be_inside_network_cidr() {
        let toml = r#"
[node]
name = "a"
overlay_ip = "10.9.0.1"

[network]
name = "demo"
cidr = "10.7.0.0/16"
"#;
        assert!(Config::from_toml(toml).is_err());
    }

    #[test]
    fn non_loopback_api_requires_token() {
        let toml = r#"
[node]
name = "a"
[network]
name = "demo"
cidr = "10.7.0.0/16"
[api]
bind = "0.0.0.0:7777"
"#;
        assert!(Config::from_toml(toml).is_err());
        let with_token = toml.replace(
            r#"bind = "0.0.0.0:7777""#,
            "bind = \"0.0.0.0:7777\"\ntoken = \"t\"",
        );
        assert!(Config::from_toml(&with_token).is_ok());
    }

    #[test]
    fn non_loopback_controller_bind_requires_secret() {
        let toml = r#"
[node]
name = "c"
role = "controller"
[network]
name = "demo"
cidr = "10.7.0.0/16"
[control]
bind = "0.0.0.0:7800"
"#;
        assert!(Config::from_toml(toml).is_err());
        let with_secret = toml.replace(
            r#"bind = "0.0.0.0:7800""#,
            "bind = \"0.0.0.0:7800\"\nsecret = \"s\"",
        );
        assert!(Config::from_toml(&with_secret).is_ok());
    }

    #[test]
    fn explicit_network_id_is_supported() {
        let toml = r#"
[node]
name = "a"
overlay_ip = "10.7.0.1"

[network]
name = "demo"
id = "11111111-1111-4111-8111-111111111111"
cidr = "10.7.0.0/16"
"#;
        let config = Config::from_toml(toml).unwrap();
        assert_eq!(
            config.network.id.unwrap().to_string(),
            "11111111-1111-4111-8111-111111111111"
        );
    }

    const RAFT_BASE: &str = r#"
[node]
name = "c"
role = "controller"
[network]
name = "demo"
cidr = "10.7.0.0/16"
[control]
raft_dir = "/tmp/stellaris-raft-timing-test"
raft_secret = "raft-secret"
"#;

    #[test]
    fn raft_election_timeout_defaults_to_cross_region_value() {
        let config = Config::from_toml(RAFT_BASE).unwrap();
        let timing = config.control.raft_timing();
        assert_eq!(timing.election_timeout_min_ms, 1000);
        assert_eq!(timing.election_timeout_max_ms, 2000);
        assert_eq!(timing.heartbeat_interval_ms, 250);
        assert_eq!(timing.source, RaftTimingSource::DefaultCrossRegion);
        assert_eq!(timing, RaftTiming::default());
    }

    #[test]
    fn raft_election_timeout_is_configurable_in_toml() {
        let toml = format!("{RAFT_BASE}raft_election_timeout_ms = 300\n");
        let config = Config::from_toml(&toml).unwrap();
        let timing = config.control.raft_timing();
        assert_eq!(timing.election_timeout_min_ms, 300);
        assert_eq!(timing.election_timeout_max_ms, 600);
        assert_eq!(timing.heartbeat_interval_ms, 75);
        assert_eq!(timing.source, RaftTimingSource::Config);
    }

    #[test]
    fn raft_election_timeout_out_of_range_is_rejected() {
        for value in [0u64, 10, 49, 60_001] {
            let toml = format!("{RAFT_BASE}raft_election_timeout_ms = {value}\n");
            let error = Config::from_toml(&toml).unwrap_err().to_string();
            assert!(
                error.contains("raft_election_timeout_ms"),
                "value {value}: {error}"
            );
        }
        for value in [MIN_RAFT_ELECTION_TIMEOUT_MS, MAX_RAFT_ELECTION_TIMEOUT_MS] {
            let toml = format!("{RAFT_BASE}raft_election_timeout_ms = {value}\n");
            assert!(Config::from_toml(&toml).is_ok(), "value {value}");
        }
    }

    #[test]
    fn unimplemented_config_options_are_rejected() {
        let base = r#"
[node]
name = "a"
[network]
name = "demo"
cidr = "10.7.0.0/16"
"#;
        for (name, extra) in [
            ("transport.listen", "[transport]\nlisten = false\n"),
            ("routing.rib_mode", "[routing]\nrib_mode = \"cache\"\n"),
            (
                "set_path_hint",
                "[[routing.policies]]\nid = \"p\"\npriority = 1\n[routing.policies.match_]\n[routing.policies.action]\nkind = \"set_path_hint\"\nvalue = \"direct\"\n",
            ),
        ] {
            let toml = format!("{base}{extra}");
            let error = Config::from_toml(&toml).unwrap_err().to_string();
            assert!(
                error.contains(name.split('.').next().unwrap()),
                "{name}: {error}"
            );
        }
    }

    #[test]
    fn qos_class_zero_rates_are_rejected_on_both_paths() {
        for (field, value) in [
            ("rate_bps", "rate_bps = 0"),
            ("burst_bytes", "burst_bytes = 0"),
            ("queue_depth", "queue_depth = 0"),
            ("queue_bytes", "queue_bytes = 0"),
        ] {
            let toml = format!(
                r#"
[node]
name = "a"
[network]
name = "demo"
cidr = "10.7.0.0/16"
[qos]
enabled = true
[[qos.classes]]
name = "c"
dscp = 0
{value}
"#
            );
            let error = Config::from_toml(&toml).unwrap_err().to_string();
            assert!(error.contains(field), "{field}: {error}");
        }
    }

    #[test]
    fn discovery_requires_authentication_by_default() {
        let base = r#"
[node]
name = "a"
[network]
name = "demo"
cidr = "10.7.0.0/16"
[transport]
mdns = true
"#;
        let error = Config::from_toml(base).unwrap_err().to_string();
        assert!(error.contains("discovery"), "{error}");
        let with_controller = r#"
[node]
name = "a"
[network]
name = "demo"
cidr = "10.7.0.0/16"
[network.auth]
mode = "controller"
[control]
endpoint_id = "0101010101010101010101010101010101010101010101010101010101010101"
controller_keys = ["0202020202020202020202020202020202020202020202020202020202020202"]
[transport]
mdns = true
"#;
        assert!(Config::from_toml(with_controller).is_ok());
        let lab = base.replace(
            "[transport]",
            "[transport]\nallow_unauthenticated_discovery = true",
        );
        assert!(Config::from_toml(&lab).is_ok());
    }

    #[test]
    fn relay_settings_must_not_conflict() {
        let toml = r#"
[node]
name = "a"
[network]
name = "demo"
cidr = "10.7.0.0/16"
[transport]
disable_relay = true
relay_urls = ["https://relay.example.com"]
"#;
        let error = Config::from_toml(toml).unwrap_err().to_string();
        assert!(error.contains("relay"), "{error}");
    }

    #[test]
    fn relay_mode_semantics_are_explicit() {
        let base = r#"
[node]
name = "a"
[network]
name = "demo"
cidr = "10.7.0.0/16"
[transport]
"#;
        let custom_empty = format!("{base}relay_mode = \"custom\"\n");
        let error = Config::from_toml(&custom_empty).unwrap_err().to_string();
        assert!(error.contains("requires transport.relay_urls"), "{error}");
        let n0_with_urls =
            format!("{base}relay_mode = \"n0\"\nrelay_urls = [\"https://relay.example.com\"]\n");
        let error = Config::from_toml(&n0_with_urls).unwrap_err().to_string();
        assert!(error.contains("relay_urls is only valid"), "{error}");
        let custom = format!(
            "{base}relay_mode = \"custom\"\nrelay_urls = [\"https://relay.example.com\"]\n"
        );
        assert!(Config::from_toml(&custom).is_ok());
        let disabled = format!("{base}relay_mode = \"disabled\"\n");
        assert!(Config::from_toml(&disabled).is_ok());
    }

    #[test]
    fn raft_requires_a_non_empty_secret() {
        let toml = r#"
[node]
name = "c"
role = "controller"
[network]
name = "demo"
cidr = "10.7.0.0/16"
[control]
raft_dir = "/tmp/stellaris-raft-secret-test"
"#;
        let error = Config::from_toml(toml).unwrap_err().to_string();
        assert!(error.contains("raft_secret"), "{error}");
        let empty = toml.replace("[control]", "[control]\nraft_secret = \"\"");
        let error = Config::from_toml(&empty).unwrap_err().to_string();
        assert!(error.contains("raft_secret"), "{error}");
    }

    #[test]
    fn empty_credentials_are_rejected() {
        let base = r#"
[node]
name = "a"
[network]
name = "demo"
cidr = "10.7.0.0/16"
[api]
bind = "127.0.0.1:7777"
"#;
        for (field, toml) in [
            ("api.token", format!("{base}token = \"\"\n")),
            ("api.read_token", format!("{base}read_token = \" \"\n")),
            (
                "control.secret",
                format!("{base}[control]\nsecret = \"\"\n"),
            ),
        ] {
            let error = Config::from_toml(&toml).unwrap_err().to_string();
            assert!(error.contains(field), "{field}: {error}");
        }
    }

    #[test]
    fn raft_tls_files_must_be_paired() {
        let base = r#"
[node]
name = "c"
role = "controller"
[network]
name = "demo"
cidr = "10.7.0.0/16"
[control]
raft_dir = "/tmp/stellaris-raft-tls-test"
raft_secret = "raft-secret"
"#;
        let with_cert = format!("{base}raft_tls_cert = \"/tmp/cert.pem\"\n");
        assert!(Config::from_toml(&with_cert).is_err());
        let with_client = format!("{base}raft_tls_require_client_cert = true\n");
        assert!(Config::from_toml(&with_client).is_err());
        let ok = format!("{base}raft_tls_cert = \"/tmp/c.pem\"\nraft_tls_key = \"/tmp/k.pem\"\n");
        assert!(Config::from_toml(&ok).is_ok());
    }

    #[test]
    fn raft_peers_and_bind_are_validated() {
        let base = r#"
[node]
name = "c"
role = "controller"
[network]
name = "demo"
cidr = "10.7.0.0/16"
[control]
raft_dir = "/tmp/stellaris-raft-peer-test"
raft_secret = "raft-secret"
"#;
        let bad_bind = format!("{base}raft_bind = \"not-an-address\"\n");
        assert!(Config::from_toml(&bad_bind).is_err());
        let bad_peer = format!(
            "{base}raft_bind = \"127.0.0.1:5701\"\n[[control.raft_peers]]\nid = 1\naddr = \"nope\"\n"
        );
        assert!(Config::from_toml(&bad_peer).is_err());
        let dup = format!(
            "{base}raft_bind = \"127.0.0.1:5701\"\n[[control.raft_peers]]\nid = 1\naddr = \"127.0.0.1:1\"\n[[control.raft_peers]]\nid = 1\naddr = \"127.0.0.1:2\"\n"
        );
        assert!(Config::from_toml(&dup).is_err());
    }

    #[test]
    fn raft_timing_derivation_keeps_openraft_invariants() {
        for min in [
            MIN_RAFT_ELECTION_TIMEOUT_MS,
            150,
            1000,
            MAX_RAFT_ELECTION_TIMEOUT_MS,
        ] {
            let timing = RaftTiming::from_min(min, RaftTimingSource::Config);
            assert!(timing.heartbeat_interval_ms < timing.election_timeout_min_ms);
            assert!(timing.election_timeout_min_ms < timing.election_timeout_max_ms);
            assert_eq!(
                timing.election_timeout_max_ms,
                timing.election_timeout_min_ms * 2
            );
        }
        // Clamped below and above, so a stray value can never reach openraft.
        assert_eq!(
            RaftTiming::from_min(1, RaftTimingSource::Env).election_timeout_min_ms,
            MIN_RAFT_ELECTION_TIMEOUT_MS
        );
        assert_eq!(
            RaftTiming::from_min(u64::MAX, RaftTimingSource::Env).election_timeout_min_ms,
            MAX_RAFT_ELECTION_TIMEOUT_MS
        );
    }
}

#[cfg(test)]
mod deprecated_control_tests {
    use super::*;

    #[test]
    fn legacy_fanout_urls_are_rejected() {
        let toml = r#"
[node]
name = "c"
role = "controller"
state_dir = "/tmp/stellaris-raft-config-test"
[network]
name = "demo"
cidr = "10.7.0.0/16"
[control]
secret = "s"
urls = ["http://127.0.0.1:7800"]
"#;
        assert!(Config::from_toml(toml).is_err());
    }

    #[test]
    fn legacy_fanout_threshold_is_rejected() {
        let toml = r#"
[node]
name = "a"
overlay_ip = "10.7.0.1"
[network]
name = "demo"
cidr = "10.7.0.0/16"
[control]
controller_threshold = 2
"#;
        assert!(Config::from_toml(toml).is_err());
    }

    #[test]
    fn static_mode_requires_peers_and_allows_discovery() {
        let base = r#"
[node]
name = "a"
[network]
name = "demo"
cidr = "10.7.0.0/16"
[network.auth]
mode = "static"
"#;
        let error = Config::from_toml(base).unwrap_err().to_string();
        assert!(error.contains("static"), "{error}");
        let with_peer = format!(
            r#"{base}
[[peers]]
name = "b"
endpoint_id = "{}"
overlay_ip = "10.7.0.2"
[transport]
mdns = true
"#,
            hex::encode([2u8; 32])
        );
        assert!(Config::from_toml(&with_peer).is_ok());
    }

    #[test]
    fn ipam_auto_requires_controller_and_no_static_address() {
        let base = r#"
[node]
name = "a"
ipam = "auto"
[network]
name = "demo"
cidr = "10.30.0.0/16"
[network.auth]
mode = "controller"
[control]
url = "http://127.0.0.1:1"
controller_keys = ["0202020202020202020202020202020202020202020202020202020202020202"]
[dataplane]
enabled = true
"#;
        assert!(Config::from_toml(base).is_ok());
        let with_overlay = base.replace(
            "[node]\nname = \"a\"",
            "[node]\nname = \"a\"\noverlay_ip = \"10.30.0.2\"",
        );
        let error = Config::from_toml(&with_overlay).unwrap_err().to_string();
        assert!(error.contains("overlay_ip"), "{error}");
        let no_controller = base.replace("mode = \"controller\"", "mode = \"none\"");
        let error = Config::from_toml(&no_controller).unwrap_err().to_string();
        assert!(error.contains("controller"), "{error}");
        let static_without_overlay = r#"
[node]
name = "a"
[network]
name = "demo"
cidr = "10.30.0.0/16"
[dataplane]
enabled = true
"#;
        let error = Config::from_toml(static_without_overlay)
            .unwrap_err()
            .to_string();
        assert!(error.contains("overlay_ip"), "{error}");
    }

    #[test]
    fn ipam_pools_are_validated() {
        let base = r#"
[node]
name = "ctrl"
role = "controller"
[network]
name = "demo"
cidr = "10.30.0.0/16"
[control.ipam]
[[control.ipam.pools]]
id = "p"
cidr = "10.30.0.0/24"
lease_secs = 600
"#;
        assert!(Config::from_toml(base).is_ok());
        let outside = base.replace("cidr = \"10.30.0.0/24\"", "cidr = \"10.31.0.0/24\"");
        assert!(Config::from_toml(&outside).is_err());
        let zero_lease = base.replace("lease_secs = 600", "lease_secs = 0");
        assert!(Config::from_toml(&zero_lease).is_err());
        let too_large = base.replace("cidr = \"10.30.0.0/24\"", "cidr = \"10.0.0.0/8\"");
        assert!(Config::from_toml(&too_large).is_err());
        let overlap = format!(
            "{base}
[[control.ipam.pools]]
id = \"q\"
cidr = \"10.30.0.0/25\"
"
        );
        assert!(Config::from_toml(&overlap).is_err());
    }
}
