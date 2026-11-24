# Stellaris Linking — Implementation Architecture

> 版本：v0.1（2026-11-22）
> 状态：**设计文档**。本文包含 v1 目标设计与尚未实现的条目（如 Path 层、IPv4 重组、Byte-DRR、controller status/metrics、Postgres 等）。
> 当前实现状态与已实现/未实现清单以 [README.md](README.md) 顶部与 [AUDIT.md](AUDIT.md) 为准（2026-11-24 审计已修复 P0 与大部分 P1）。
> 目标：一个**完全掌控、相对可靠、可长期维护**的 L3 虚拟组网系统，Rust 实现，iroh/QUIC 传输，可选控制面，支持每节点路由查询与路由调节。
> 本文是实现的单一事实源；调研背景见 `stellaris-linking-architecture.md`、`stellaris-linking-routing-design.md`、`virtual-network-survey-2026-11.md`。

---

## 0. 范围与决策

### 0.1 v1 范围

| 能力 | v1 |
|---|---|
| Overlay | L3，IPv4 + IPv6 |
| 平台 | Linux、macOS（Windows 第二阶段） |
| 规模 | 1,000 节点 / 10,000 前缀（第二阶段 10k 节点分层） |
| 控制面 | `none` / `embedded` / `external` 三态 |
| 路由 | Intent / RIB / FIB / Path 四层；查询 + 调节 |
| 组网 | 单网络起步，多网络（多 TUN）M3 基础 |
| 安全 | TLS 1.3、Ed25519、签名 manifest、ACL、anti-spoof |
| 数据面 | TUN + 用户态 pipeline；QoS；exit node |
| UI | Web（React + OpenAPI），Tauri 可选 |
| 低功耗 | 预留 `gateway/leaf` 与 `LinkTransport`，v1 不实现 BLE/802.15.4 |

### 0.2 非目标（v1 明确不做）

- L2 广播/组播/ARP 完整模拟。
- BGP/OSPF 与外部路由器互操作（只做静态/汇总导入）。
- 移动端、浏览器直连、FIPS/等保。
- WireGuard 兼容、内核态数据面。
- BLE/802.15.4/LoRa 直连（只预留接口）。
- 多租户/多组织（external controller 第二阶段）。

### 0.3 架构决策（ADR）

| ID | 决策 | 理由 | 代价 |
|---|---|---|---|
| ADR-001 | **iroh 1.5 作为唯一传输依赖**，封装在 `stellaris-transport` | 打洞/relay/QUIC/身份/路径统计现成 | iroh API 演进；路径选择部分 unstable |
| ADR-002 | **Clean-room，不 fork/不复制 Tunnet** | MPL/AGPL、v0.9.1、路由模型太薄 | 自己写控制面/路由 |
| ADR-003 | **TUN + 用户态数据面**（`tun-rs`） | 完全掌控 FIB/ACL/QoS；接受一次特权安装 | 跨平台签名/驱动 |
| ADR-004 | **Intent / RIB / FIB / Path 四层** | 查询、调节、回滚、解释清晰 | 代码量增加，但边界清楚 |
| ADR-005 | **控制面三态，controller 是 agent 的角色** | 任意节点可当 controller，可迁移 | 角色/epoch/HA 复杂度 |
| ADR-006 | **控制协议 protobuf over iroh；管理 API HTTP/JSON** | 控制面不依赖公网 IP；UI/自动化友好 | 两套序列化/转换 |
| ADR-007 | **agent 用 SQLite；controller 用 Postgres** | 单机可靠、部署简单；集中式可扩展 | 两套 schema/migration |
| ADR-008 | **Rust 2024 / tokio / axum / utoipa / React** | 生态成熟、团队效率 | 前端 TS 维护 |
| ADR-009 | **0-RTT 禁用于数据面/控制面；keylog 生产禁用** | 0-RTT 无 FS、可重放 | 首包多 1-RTT |
| ADR-010 | **低功耗走 gateway/leaf，不让每个 MCU 跑 QUIC** | RAM/功耗/连接数限制 | 需要 gateway 角色（v2） |

---

## 1. Crate 布局与依赖

### 1.1 Workspace

```text
Cargo.toml                     # workspace, resolver = "2", edition = "2024"
rust-toolchain.toml            # channel = "1.91"（或 stable；iroh 要求 >=1.91）
crates/
  stellaris-types/             # ID、路由模型、配置、错误；无 I/O
  stellaris-proto/             # protobuf 消息、ALPN、版本常量；prost
  stellaris-crypto/            # Ed25519、签名/验签、manifest 校验
  stellaris-transport/         # iroh 封装：Endpoint、ConnPool、PathStats、Relay
  stellaris-fib/               # LPM、ECMP、FIB 编译/查找
  stellaris-routing/           # Intent、RIB、SPF、policy、route engine
  stellaris-dataplane/         # TUN、parser、ACL、QoS、encap/decap、NAT
  stellaris-control/           # manifest、角色、controller、snapshot、ACK、HA
  stellaris-agent/             # 编排、SQLite、生命周期、service
  stellaris-api/               # axum HTTP、OpenAPI、SSE、auth
  stellaris-cli/               # clap CLI
  stellaris-testkit/           # netns、模拟节点、故障注入
apps/
  dashboard/                   # React + Vite + TypeScript
  desktop/                     # Tauri（可选）
```

### 1.2 依赖方向

```text
types ──► crypto
types ──► fib
types ──► proto
types + proto ──► transport
types + fib ──► routing
types + fib + proto ──► dataplane
types + proto + crypto ──► control
all ──► agent ──► api / cli
```

规则：

- `types` 不依赖 tokio、iroh、axum；只放纯数据/错误。
- `transport` 不依赖 `routing`/`dataplane`；只暴露 `PacketTransport` trait 和路径统计。
- `dataplane` 不依赖 `control`；只依赖 `fib` + `types` + `proto`。
- `agent` 是唯一 wiring 层；其他 crate 不互相 `use` 具体实现。
- 禁止循环依赖；CI 用 `cargo-deny` + `cargo-machete` 检查。

### 1.3 关键依赖

| 用途 | crate | 备注 |
|---|---|---|
| 传输 | `iroh = 1.5` | 锁 minor；不泄漏类型 |
| TUN | `tun-rs = 2.8` | Linux/macOS/Windows |
| 异步 | `tokio` | multi-thread runtime |
| 解析 | `smoltcp`（wire）或 `etherparse` | 建议 `smoltcp::wire`，后续可复用栈 |
| LPM | `prefix-trie` | v4/v6 分开 |
| 序列化 | `serde`/`serde_json`/`toml` | API/config/storage |
| 协议 | `prost`/`prost-types` | 控制面 |
| HTTP | `axum` + `utoipa` | API/OpenAPI |
| DB | `sqlx`（SQLite/Postgres） | migration |
| 日志 | `tracing` + `tracing-subscriber` | JSON |
| 指标 | `metrics` + `metrics-exporter-prometheus` | `/metrics` |
| 错误 | `thiserror`（lib）/`anyhow`（bin） | |
| ID | `uuid`（v7）/`ed25519-dalek` | |
| 时间 | `time` | RFC3339 |
| 测试 | `cargo-nextest`、`insta`、`proptest` | |

---

## 2. 运行时模型

### 2.1 进程

| 进程 | 作用 | 何时启动 |
|---|---|---|
| `stellaris-agent` | 常驻 agent：数据面 + 路由 + 控制客户端 + API | 总是 |
| `stellaris-controller` | 独立控制面（external 模式） | 可选 |
| `stellaris` | CLI（连接 agent/controller 的本地 socket/API） | 按需 |
| `iroh-relay`（上游） | 自建 relay | 可选，独立部署 |

`embedded` 模式下，agent 通过 feature `controller` 启动 controller task；不单独跑 `stellaris-controller`。

### 2.2 Tokio 任务

```text
runtime (multi-thread)
├─ tun_reader              # 读 TUN，批量入 ingress 队列
├─ ingress_worker × N      # parse/anti-spoof/ACL/FIB/QoS
├─ peer_tx (per peer)      # Byte-DRR + iroh send_datagram
├─ peer_rx (per conn)      # iroh read_many_datagrams + ingress
├─ route_engine            # 订阅事件，重算 RIB/FIB，原子替换
├─ os_route_reconciler     # desired-state OS 路由
├─ control_client          # 连接 controller，sync/ACK/heartbeat
├─ controller_task         # embedded controller（可选）
├─ api_server              # axum
├─ reaper                  # 路由过期、dampening、连接清理
└─ metrics_server          # Prometheus（可与 api 合并）
```

### 2.3 并发原语

| 数据 | 机制 |
|---|---|
| FIB | `ArcSwap<Arc<Fib>>`；读无锁 |
| Manifest/Generation | `watch::Receiver` |
| 事件（API/UI） | `broadcast::Sender<Event>` |
| 每 peer 发送队列 | `mpsc::Sender<Bytes>`（有界） |
| 路由重算触发 | `mpsc::Sender<RouteEvent>` + debounce |
| 连接池 | `DashMap<NodeId, Connection>` / `Mutex<HashMap>` |
| 指标 | `metrics` 宏；避免热路径分配 |

### 2.4 启动/关闭顺序

启动：

1. 读配置/身份/密钥；
2. 打开 SQLite，加载 manifest/intents/fib_snapshot；
3. 创建 TUN（按网络）；
4. 启动 iroh endpoint（relay/custom）；
5. 启动 route engine，恢复 FIB；
6. reconcile OS 路由；
7. 连接 controller / 加入 direct 网络；
8. 启动 API/metrics；
9. ready。

关闭：

1. 停止接受新流量；
2. 保存 FIB/intents/generation；
3. 关闭 iroh endpoint（graceful）；
4. 删除本进程拥有的 OS 路由/NAT 规则；
5. 关闭 TUN；
6. flush 日志/指标。

> 任何一步失败都要可诊断；OS 路由清理必须只删自己 owner 标记的规则，避免误删 Tailscale/ZeroTier。

---

## 3. 核心数据模型

### 3.1 ID

```rust
#[derive(Clone, Copy, Eq, PartialEq, Hash, Ord, PartialOrd)]
pub struct NodeId([u8; 32]);   // Ed25519 public key

#[derive(Clone, Copy, Eq, PartialEq, Hash)]
pub struct NetworkId(Uuid);    // UUID v7

#[derive(Clone, Copy, Eq, PartialEq, Hash)]
pub struct RouteId(Uuid);      // UUID v7

#[derive(Clone, Copy, Eq, PartialEq, Hash, Ord, PartialOrd)]
pub struct Generation(u64);    // 单调递增

#[derive(Clone, Copy, Eq, PartialEq, Hash)]
pub struct Epoch(u64);         // controller 任期
```

### 3.2 路由

```rust
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
    pub generation: Generation,
    pub expires_at: Option<OffsetDateTime>,
    pub attrs: RouteAttributes,
}

pub enum RouteSource {
    Connected,
    Static,
    Controller,
    LinkState,
    Aggregate,
    Default,
}

pub enum RouteState {
    Active,
    Stale,
    Withdrawn,
    Filtered,
}

pub enum PathHint {
    Auto,
    Direct,
    Relay,
    AvoidRelay,
}

pub struct RouteAttributes {
    pub rtt_ms: Option<u16>,
    pub loss_ppm: Option<u32>,
    pub bandwidth_kbps: Option<u64>,
    pub energy_cost: Option<u32>, // v2: 低功耗
    pub region: Option<String>,
    pub tags: Vec<String>,
}
```

### 3.3 FIB

```rust
pub struct Fib {
    pub v4: PrefixMap<Ipv4Net, FibEntry>,
    pub v6: PrefixMap<Ipv6Net, FibEntry>,
    pub generation: Generation,
}

pub struct FibEntry {
    pub next_hops: SmallVec<[FibNextHop; 4]>,
    pub source: RouteSource,
}

pub struct FibNextHop {
    pub node: NodeId,
    pub weight: u16,
    pub path_hint: PathHint,
}
```

### 3.4 Intent

```rust
pub struct Intent {
    pub id: RouteId,
    pub network: NetworkId,
    pub scope: Scope,           // Local | Network
    pub change: RouteChange,
    pub generation: Generation,
    pub expires_at: Option<OffsetDateTime>,
    pub created_by: String,
    pub reason: String,
    pub created_at: OffsetDateTime,
}

pub enum Scope { Local, Network }

pub enum RouteChange {
    UpsertStatic(UpsertStatic),
    Delete { id: RouteId },
    Pin { prefix: IpNet, next_hop: NodeId, ttl: Option<Duration> },
    Unpin { prefix: IpNet },
    SetPolicy(RoutePolicy),
    SetLinkCost { peer: NodeId, cost: u32, energy: Option<u32> },
    SetPathPreference { peer: NodeId, hint: PathHint, weight: u16 },
    Drain { node: NodeId, grace: Duration },
    Reset { prefix: Option<IpNet> },
}
```

### 3.5 Manifest / 控制

```rust
pub struct Manifest {
    pub network: NetworkId,
    pub epoch: Epoch,
    pub generation: Generation,
    pub controllers: Vec<NodeId>,
    pub members: Vec<Member>,
    pub ipam: Ipam,
    pub acl: AclVersion,
    pub issued_at: OffsetDateTime,
    pub expires_at: OffsetDateTime,
    pub signature: Signature,
}

pub struct Member {
    pub node: NodeId,
    pub ip: IpAddr,
    pub role: Role,
    pub caps: Capabilities,
    pub tags: Vec<String>,
}

pub enum Role { Member, Controller, Relay, Leaf }

pub struct Capabilities {
    pub can_route: bool,
    pub can_controller: bool,
    pub can_relay: bool,
    pub rib_mode: RibMode,
}

pub enum RibMode { Full, Cache, None }
```

### 3.6 序列化约定

- **API/配置/存储**：`serde` + JSON/TOML。
- **控制面 wire**：`prost` protobuf；不与 API 结构复用。
- **错误**：`thiserror` 枚举；API 映射为 `{code, message, details, tx_id}`。
- **时间**：`time::OffsetDateTime`，RFC3339。
- **IP**：`ipnet::IpNet` / `IpAddr`；JSON 用字符串。

---

## 4. 数据面

### 4.1 TUN

- 每个网络一个 TUN（v1 单网络；M3 多 TUN 基础）。
- 名称：`stellaris0`、`stellaris1`…；macOS 必须 `utunN`，由内核选。
- MTU：连接建立后按 `max_datagram_size()` 计算，上限 1280；详细规则见 §4.4。
- Linux 启用 multi-queue/offload（可选）；macOS 用 `utun`；Windows 用 WinTun（第二阶段）。
- TUN 创建需要 root/CAP_NET_ADMIN；agent 以特权启动后降权（Linux），或由 systemd 服务运行。

### 4.2 出站 pipeline

```text
TUN read
  → parse IPv4/IPv6
  → anti-spoof? (出站不需要)
  → ACL outbound
  → FIB LPM
  → TTL check
  → QoS classify/enqueue
  → encap MeshHeader
  → iroh send_datagram
```

### 4.3 入站 pipeline

```text
iroh datagram recv
  → verify connection/peer
  → parse MeshHeader
  → network lookup
  → TTL decrement / loop check
  → anti-spoof: src ∈ peer allowed prefixes
  → ACL inbound
  → if dst local: write TUN
  → else: FIB forward (gateway/exit)
```

### 4.4 MTU / 分片 / MSS

- `max_datagram_size()` 来自 iroh 连接；不同 peer/路径不同。
- TUN MTU 全局：`min(1280, min(max_datagram_size over active peers) - HEADER_LEN - SAFETY)`。
- `HEADER_LEN = 16`；`SAFETY = 32`。
- 如果 < 576：拒绝启动/告警；如果 < 1280：记录并禁用 IPv6 或实现分片。
- **IPv4**：实现 reassembly（有界、超时）；转发时如超 MTU 可分片。
- **IPv6**：源端分片或发送 ICMPv6 Packet Too Big；不允许中间分片。
- **TCP MSS clamp**：SYN/SYN-ACK 改为 `MTU - 40`（v4）/`-60`（v6）。
- 记录 `datagram_too_large`/`frag_dropped` 指标；不要静默丢。

### 4.5 MeshHeader

```text
 0                   1                   2                   3
+-------+-------+-------+-------+-------+-------+-------+-------+
| ver   | flags | ttl   | rsv   | network_hash (u32)            |
+-------+-------+-------+-------+-------+-------+-------+-------+
| flow_hash (u32)               | reserved (u32)                |
+-------------------------------+-------------------------------+
| IP packet ...
+---------------------------------------------------------------+
```

- `ver=1`；`flags`：bit0=control，bit1=ECN，其余保留。
- `network_hash`：`xxhash64(network_id)[..4]`；manifest 保证无碰撞（或启动时检测）。
- `flow_hash`：5 元组哈希，用于 ECMP/QoS；0 表示未计算。
- `ttl`：默认 64；每跳减一；0 丢弃（可选 ICMP time exceeded）。
- 头部固定 16 字节（4 字节字段 + 4 字节 network_hash + 4 字节 flow_hash + 4 字节 reserved）；`#[repr(C)]`，网络字节序。

### 4.6 FIB 查找与 ECMP

- `prefix-trie` 分别查 v4/v6；取最长前缀。
- 候选按 admin distance/local_pref/metric 选；`pin` 限定 next hop。
- ECMP：按 `flow_hash`/5 元组哈希，权重归一化；同一 flow 固定成员。
- 每 flow 缓存（可选，LRU 4k）；成员变化时失效。
- FIB 通过 `ArcSwap` 原子替换；数据面每包 load 一次。

### 4.7 Anti-spoof

- 每个 peer 维护 `allowed_src: Vec<IpNet>`：
  - 自己的 mesh IP/32；
  - 它通告的 subnet 前缀（仅当 `can_route`）；
  - 显式 ACL 允许的 NAT 源（v2）。
- 入站源 IP 不在集合 → 丢弃 + `spoof_drop` 指标 + 限流日志。
- 转发节点也要检查：源 IP 必须属于入站 peer 的通告前缀，防止 transit spoof。

### 4.8 ACL

- 每网络一份规则；匹配：src/dst prefix、protocol、port、peer tag、direction。
- v1 默认 **同网络 allow、跨网络 deny**；可配置 default deny。
- 无状态（stateless）；需要 stateful 时第二阶段加 conntrack。
- 规则编译为有序列表；规则数 <1k 时线性扫描；后续 trie/bitmap。
- 拒绝时返回 ICMP admin prohibited（可配置）；计数。

### 4.9 QoS

- 分类：
  - ICMP、DNS（53）、TCP SYN/FIN/RST、纯 ACK → `Latency`；
  - 大包（>= MTU-80）→ `Bulk`；
  - 其余 → `Normal`。
- 每 peer 三条队列（cap 64/256/512）；Byte-DRR，quantum 8×/4×/1× MTU。
- 队列满：先丢 bulk，再 normal，最后 latency；计数。
- 可选 per-peer/prefix 令牌桶限速；v1 只做队列，不做复杂整形。

### 4.10 NAT / exit / subnet gateway

- exit node：开启 IP forwarding；Linux nftables 表 `stellaris_nat`；macOS pf anchor `com.stellaris/nat`；Windows WinNAT（第二阶段）。
- 规则带 owner 标记；启动时只清理自己的表/anchor；不要 `flush ruleset`。
- subnet gateway：v1 只做 exit + 静态子网路由；LAN 侧 ARP/NDP 转发 v2。
- NAT 状态由内核 conntrack；agent 只装规则。

### 4.11 多网络

- v1：每个网络一个 TUN；FIB/ACL/manifest 按网络隔离。
- `network_hash` 在 MeshHeader 中；一个 peer 连接可复用，按网络分流。
- 地址冲突：启动时检查本机路由/其他 VPN；冲突则拒绝该网络并告警。
- 跨网络默认隔离；显式 policy 才允许。

### 4.12 错误处理

| 错误 | 行为 |
|---|---|
| TUN 创建失败 | 启动失败，明确提示权限/驱动 |
| datagram too large | 丢包 + 指标 + 告警；尝试分片 |
| FIB 无匹配 | 丢包 + ICMP unreachable（限流） |
| anti-spoof 失败 | 丢包 + 指标 + 限流日志 |
| ACL deny | 丢包/ICMP + 计数 |
| iroh 连接断开 | 标记 peer down；路由撤销；重连 backoff |
| OS 路由安装失败 | 回滚 FIB/Intent；告警 |

---

## 5. 路由引擎

### 5.1 组件

```text
IntentStore ──┐
LinkState  ───┼──► Rib ──► FibCompiler ──► ArcSwap<Fib>
Controller ───┘         │
Policy ─────────────────┘
```

### 5.2 路由来源与优先级

| 来源 | admin_distance | 说明 |
|---|---:|---|
| Connected | 0 | 直连/本地 |
| Static | 1 | 人工 Intent |
| Controller | 20 | 控制面 |
| LinkState | 100 | SPF |
| Default | 255 | 兜底 |

同前缀：LPM → filter → admin_distance ↑ → local_pref ↓ → metric ↑ → ECMP。
`pin` 只限制同前缀的 next hop，不绕过 LPM。

### 5.3 SPF（none 模式）

- 每个节点洪泛 `LinkState`：origin、sequence、links（peer/cost/rtt/loss）、prefixes、ttl、signature。
- 接受条件：sequence 更大、签名有效、ttl>0；老化。
- Dijkstra 从 self 出发；ECMP；路径带 node 列表防环。
- 聚合：area 边界汇总；v1 扁平，1k 节点；v2 分层。
- 触发：link/peer/prefix 变化；debounce 200ms；限制每秒重算次数。

### 5.4 Controller 算路（embedded/external）

- 成员上报 link metrics/prefixes；controller 构图、算路、应用 policy。
- 生成 `RouteSnapshot`：每个 prefix 的 next_hops/weights/metric/generation。
- 节点应用 FIB，ACK `generation + applied_hash`。
- 成员自报数据做边界/时间戳校验；关键链路用双向探测交叉验证。

### 5.5 RoutePolicy

```rust
pub struct RoutePolicy {
    pub id: PolicyId,
    pub priority: u32,
    pub match_: Match,
    pub action: Action,
}

pub struct Match {
    pub prefix: Option<IpNet>,
    pub peer: Option<NodeId>,
    pub tag: Option<String>,
    pub source: Option<RouteSource>,
    pub region: Option<String>,
}

pub enum Action {
    Accept,
    Deny,
    SetAdminDistance(u8),
    SetLocalPref(u32),
    SetMetric(u32),
    SetPathHint(PathHint),
    SetWeight(u16),
}
```

- 先匹配先执行；默认 allow（可配置 default deny）。
- `explain` 必须显示命中的 policy 和修改前后属性。

### 5.6 RouteAdjust 事务

1. `dry_run`：计算新 Intent/RIB/FIB，返回 diff/affected_nodes/warnings；
2. 校验：prefix、next hop 成员/在线、环路、prefix ownership、限额；
3. 提交：写 Intent store → generation+1；
4. 原子替换 FIB；reconcile OS 路由；
5. 失败回滚；写 audit；
6. network scope 由 controller 推送，节点 ACK；controller 记录 applied/drift。

### 5.7 Explain

`GET /v1/routes/explain?dst=...` 返回：

- selected：prefix/next_hop/source/admin_distance/metric/path/transport；
- candidates：每个候选的 eligible/reason；
- matched_policies；
- generation；
- 可选 `verbose=true`。

### 5.8 收敛/抖动/聚合

- 路由抖动：hold-down + penalty；超过阈值抑制；恢复逐步。
- 聚合：`Aggregate` 来源；more-specific 优先；聚合路由不覆盖明细。
- 限额：每节点 10k 前缀（可配）；ECMP 8；超限拒绝并告警。
- 收敛目标：1k 节点常规变更 <5s；节点故障 <30s（预算，M3 实测）。

---

## 6. 控制面

### 6.1 三态/角色

```text
control_mode = none | embedded | external
role         = member | controller | relay | leaf
```

| 模式 | controller 在哪 | 谁算路 | UI/API |
|---|---|---|---|
| none | 无 | 每节点 SPF | 本地/聚合 |
| embedded | 某个 agent 节点 | controller | controller |
| external | 独立 `stellaris-controller` | controller | controller |

- controller 是 agent 的 feature/task，不是另一套数据模型。
- 任意节点可 `promote`，但必须现有 controller quorum 或离线 admin key 签名。
- `leaf` 不能 controller/relay；`capabilities` 强制。
- controller 能力可拆分：`membership | routing | policy | api`；v1 同进程，v2 可拆。

### 6.2 Agent 状态机

```text
Idle → Joining → Syncing → Running → Degraded → Stopped
                      ↑         │
                      └─────────┘ (re-sync)
```

| 状态 | 行为 |
|---|---|
| Idle | 读配置，未加入 |
| Joining | 连接 controller / 引导节点；认证 |
| Syncing | 拉 manifest/snapshot；编译 FIB |
| Running | 数据面 up；心跳/ACK |
| Degraded | controller/relay 丢失；保留最后 FIB；数据面继续 |
| Stopped | 清理 |

### 6.3 Controller 状态机

```text
Starting → Follower → Leader → Draining → Stopped
                ↑         │
                └─────────┘ (election)
```

- v1：单 controller + 冷备；无 Raft；DB lease/epoch。
- 已实现：3 节点 openraft；leader 处理写，follower 转发。
- `epoch` 单调；旧 controller 写入被 fence。
- 写路径：DB transaction → generation+1 → snapshot/delta → notify agents。
- 读路径：snapshot cache/DB。

### 6.4 Manifest / Snapshot / Delta

- manifest：成员/IPAM/ACL/版本/epoch，controller 签名；不放全量路由。
- snapshot：全量路由 + generation + checksum；zstd。
- delta：`base_generation` + 变更列表；agent 若 gap 则请求全量。
- ACK：`generation`, `applied_hash`, `error`；controller 记录 drift。

### 6.5 控制协议

详见 `PROTOCOL.md`。摘要：

- ALPN `stellaris/control/1`；protobuf length-delimited。
- `Hello` 认证：network/node/epoch/nonce/signature。
- `SyncRequest/Snapshot/Delta`、`RouteIntent/RouteAck`、`Heartbeat/Revoke`。
- 控制流与数据流分开 ALPN。
- 0-RTT 禁用。

### 6.6 HA / 故障

| 故障 | 行为 |
|---|---|
| controller 宕机 | 节点保留最后 manifest/FIB；数据面继续；新变更暂停 |
| controller 迁移 | epoch+1；节点拉新 manifest；旧写被拒 |
| 脑裂 | 无 quorum 拒绝写；节点只接受更高 epoch |
| manifest 过期 | 只读安全模式；不接新 peer；宽限期可配 |
| agent 重启 | SQLite 恢复；reconcile；同步 generation |
| relay 故障 | iroh 重选；路由不变；告警 |

---

## 7. 存储与配置

### 7.1 Agent SQLite

```sql
CREATE TABLE meta (key TEXT PRIMARY KEY, value BLOB NOT NULL);

CREATE TABLE manifests (
  network_id TEXT PRIMARY KEY,
  epoch INTEGER NOT NULL,
  generation INTEGER NOT NULL,
  json BLOB NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE intents (
  id TEXT PRIMARY KEY,
  network_id TEXT NOT NULL,
  scope TEXT NOT NULL,
  change_json BLOB NOT NULL,
  generation INTEGER NOT NULL,
  expires_at TEXT,
  created_by TEXT NOT NULL,
  reason TEXT NOT NULL,
  created_at TEXT NOT NULL
);

CREATE TABLE fib_snapshots (
  network_id TEXT PRIMARY KEY,
  generation INTEGER NOT NULL,
  json BLOB NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE audit (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  at TEXT NOT NULL,
  actor TEXT NOT NULL,
  action TEXT NOT NULL,
  detail_json BLOB NOT NULL,
  result TEXT NOT NULL
);
```

- WAL；`synchronous=NORMAL`；迁移用 `sqlx::migrate!`。
- 启动时恢复；FIB snapshot 是缓存，不能替代 Intent。

### 7.2 Controller Postgres

```text
networks(id, name, cidr, epoch, generation, manifest_json)
members(network_id, node_id, ip, role, caps_json, tags, status)
route_intents(id, network_id, scope, change_json, generation, expires_at, created_by)
route_policies(id, network_id, priority, match_json, action_json)
applied_status(network_id, node_id, generation, applied_hash, error, updated_at)
audit_log(id, network_id, actor, action, old_json, new_json, result, created_at)
controllers(id, endpoint_id, epoch, leader, last_seen)
```

### 7.3 配置

```toml
[node]
name = "edge-1"
role = "member"                 # member | controller | relay | leaf
control_mode = "none"           # none | embedded | external
state_dir = "/var/lib/stellaris"

[network]
name = "lab"
cidr = "10.7.0.0/16"
secret_file = "/etc/stellaris/network.secret"

[control]
url = ""                        # external/embedded controller endpoint
listen = true

[transport]
relay_urls = ["https://relay.example.com"]
listen = true
discovery = ["mdns", "static"]  # v1: mdns/static；dht 可选

[routing]
rib_mode = "full"               # full | cache | none
max_routes = 10000
ecmp_max = 8
latency_first = true

[dataplane]
tun_name = "stellaris0"
qos = true
nat = false
mtu = 1280

[api]
bind = "127.0.0.1:0"
token_file = "/etc/stellaris/api.token"
```

优先级：默认值 → 配置文件 → 环境变量（`STELLARIS_*`）→ CLI flag。
密钥文件 0600；支持 OS keychain（v2）。

---

## 8. API / CLI / UI

### 8.1 HTTP API

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/v1/status` | 节点/网络/角色/generation |
| GET | `/v1/peers` | peer/path/RTT |
| GET | `/v1/routes?view=intent\|rib\|fib` | 路由表 |
| GET | `/v1/routes/lookup?dst=` | LPM |
| GET | `/v1/routes/explain?dst=` | 解释选中原因 |
| GET | `/v1/paths?peer=` | iroh 路径 |
| GET | `/v1/events` | SSE |
| POST | `/v1/routes` | 新增/更新 |
| PATCH | `/v1/routes/{id}` | 修改 |
| DELETE | `/v1/routes/{id}` | 删除 |
| POST | `/v1/routes/{id}/pin` | pin |
| POST | `/v1/routes/{id}/drain` | drain |
| POST | `/v1/policy` | 策略 |
| POST | `/v1/links/{peer}/cost` | 链路代价 |
| POST | `/v1/paths/{peer}/preference` | 路径偏好 |
| GET | `/v1/routes/history` | 历史 |
| POST | `/v1/routes/rollback` | 回滚 |
| GET | `/metrics` | Prometheus |

- 本地默认 Unix socket + 可选 TCP；远程通过 overlay/反代。
- 认证：local token / bearer；controller 支持 OIDC（v2）。
- RBAC：viewer/operator/admin/controller。
- 错误：`{code, message, details, tx_id}`。
- 幂等：`Idempotency-Key`；并发：`If-Match: generation`。

### 8.2 CLI

```bash
stellaris agent run --config /etc/stellaris/config.toml
stellaris status
stellaris peer list
stellaris route list --view rib
stellaris route add 192.168.1.0/24 via node_b --metric 10 --dry-run
stellaris route pin 10.7.0.0/16 via node_c --ttl 1h
stellaris route explain 10.7.0.5
stellaris route drain node_b --grace 5m
stellaris link cost node_b 100
stellaris path prefer node_b direct
stellaris route history
stellaris route rollback 42
stellaris diag > diag.json
```

- 所有命令支持 `--json`；退出码 0/1/2（成功/失败/用法）。
- CLI 通过本地 socket 调 API，不直接操作内核。

### 8.3 UI

React + Vite + TypeScript + TanStack Query；OpenAPI 生成 client；SSE 更新。

页面：

1. **Overview**：网络健康、peer 数、route 数、controller/relay 状态。
2. **Topology**：节点/链路、direct/relay、RTT、链路 cost 编辑、drain。
3. **Routes**：Intent/RIB/FIB 三 tab；搜索/过滤；diff；dry-run；apply；rollback。
4. **Explain**：dst 查询、候选、淘汰原因、transport path。
5. **Peers**：状态、path、RTT、流量。
6. **Diagnostics**：NAT 类型、MTU、relay、controller、日志导出。
7. **Settings**：网络/ACL/controller/API token。

UI 托管：controller 或本地 agent 静态资源；Tauri 可选。

---

## 9. 安全

### 9.1 威胁模型

| 威胁 | 影响 | 控制 |
|---|---|---|
| 网络窃听 | 流量泄露 | TLS 1.3 E2E；relay 不可读 |
| 恶意成员 |  spoof/扫描/路由注入 | anti-spoof、ACL、prefix ownership、capabilities |
| 被控 controller | 重定向/黑洞 | controller 最小权限、审计、离线 admin key、manifest 透明日志（v2） |
| 恶意 relay | 元数据/DoS | 自建 relay、认证、限流；E2E 加密 |
| 设备丢失 | 身份冒用 | 撤销/轮换；manifest 移除 |
| 0-RTT 重放 | 重复操作 | 数据面/控制面禁用 0-RTT |
| 供应链 | 依赖漏洞 | cargo-deny/audit、锁文件、SBOM |
| 本地 API 暴露 | 未授权调节 | Unix socket 权限、token、bind localhost |

### 9.2 密钥与签名

- 节点身份：Ed25519；私钥文件 0600；支持 keychain（v2）。
- controller manifest/route intent 签名：Ed25519；公钥在 manifest/信任根。
- `Hello` 签名 transcript：`b"stellaris-control-v1" || network_id || node_id || epoch || nonce || controller_id`。
- 撤销：manifest 移除 + revocation list；节点拒绝握手。
- 轮换：新 key 签名 transition；旧 key 保留验证窗口。

### 9.3 传输

- iroh TLS 1.3；0-RTT 禁用；keylog 禁用。
- 自建 relay；`RelayMode::Custom`；relay 认证/限流。
- 不依赖 n0 公共 relay 作为生产。
- 前向安全：1-RTT/PSK-DHE 有；0-RTT 无；经典 FS 非 PQ。

### 9.4 防路由注入

- 只有 `can_route` 的成员可通告前缀；prefix ownership 校验。
- controller 校验 link/prefix 报告；异常限幅。
- static/pin 需要 admin；network scope 必须 controller。
- ACL 默认拒绝跨网络。

---

## 10. 可观测性

### 10.1 指标

```text
stellaris_peer_up{peer}
stellaris_peer_rtt_ms{peer}
stellaris_peer_path{peer,path="direct|relay"}
stellaris_route_count{view="intent|rib|fib"}
stellaris_fib_generation
stellaris_route_changes_total{reason}
stellaris_packets_total{direction,result}
stellaris_bytes_total{direction}
stellaris_drops_total{reason}
stellaris_qos_queue_depth{peer,class}
stellaris_controller_connected
stellaris_controller_generation
stellaris_relay_selected{url}
stellaris_manifest_epoch
```

### 10.2 日志

- JSON；`trace_id`/`span_id`；路由变更 info；包丢弃 debug + 采样。
- 审计日志独立表/文件；不可变（append-only）。
- 诊断包：`stellaris diag` 导出配置（脱敏）、状态、路由、peer、日志片段。

### 10.3 健康

- `/healthz`：进程存活。
- `/readyz`：TUN/FIB/controller（按模式）就绪。
- 告警：controller 不可达、relay 失败、路由抖动、MTU 黑洞、manifest 过期。

---

## 11. 测试与 CI

### 11.1 测试金字塔

| 层 | 内容 |
|---|---|
| 单元 | LPM、选择、policy、ECMP、MTU、ACL、编码/解码 |
| 属性 | 无环路、回滚一致、FIB 与 RIB 一致、幂等 |
| 集成 | netns + veth + nftables；3/10 节点；direct/relay；NAT 矩阵 |
| 混沌 | kill controller/relay、分区、时钟偏移、重复请求、manifest 过期 |
| 规模 | 1k 节点模拟、10k 前缀、churn、收敛/内存 |
| 模糊 | packet parser、protobuf decode |
| 跨平台 | Linux 全量；macOS/Windows 编译 + 冒烟 |

### 11.2 CI 门禁

- `cargo fmt --check`
- `cargo clippy --all-targets -- -D warnings`
- `cargo nextest run`
- `cargo deny check`
- `cargo audit`
- `buf lint` / protobuf breaking check
- OpenAPI diff
- docs build
- 依赖许可证检查

### 11.3 测试工具

- `stellaris-testkit`：netns、veth、NAT、relay、模拟节点、故障注入。
- `insta` 快照（API/JSON）；`proptest` 路由；`criterion` 基准。
- 所有集成测试可 `--nocapture` 诊断。

---

## 12. 性能预算

> 初始预算，M0/M3 实测后调整；不是 SLA 承诺。

| 指标 | 目标 |
|---|---|
| FIB 查找 | p99 < 1 µs（10k 前缀） |
| 单节点吞吐 | ≥500 Mbps（4 vCPU，QUIC，MTU 1280） |
| 包处理延迟 | 用户态增加 <1 ms（p50） |
| 路由收敛 | 1k 节点常规变更 <5s；故障 <30s |
| 内存 | 10k 路由 <250 MB RSS |
| controller snapshot | 1k 节点 <1s |
| 启动恢复 | <5s（SQLite + reconcile） |

---

## 13. 风险与未决

| 风险 | 影响 | 缓解 |
|---|---|---|
| iroh API 演进 | 升级成本 | 锁 1.5.x；封装；feature flag |
| 自定义 PathSelector unstable | 路径调节受限 | v1 只做偏好/观测；必要时 patch |
| QUIC 性能/MTU | 吞吐/大包 | 基准；MTU 自适应；MSS clamp |
| NAT 类型复杂 | 直连失败 | iroh 打洞 + 自建 relay；NAT 矩阵 |
| 路由收敛/抖动 | 大规模不稳 | 聚合/分层/dampening；先 1k |
| controller HA | 脑裂 | epoch + openraft quorum |
| 跨平台签名/驱动 | 安装失败 | Linux 先行；Windows 单独里程碑 |
| 安全审计 | 生产准入 | 威胁模型 + 外部审计 |

未决（需要产品确认）：

1. 目标规模：1k 还是 10k？
2. Windows 优先级？
3. per-flow 策略路由是否 v1？
4. `none` 模式是否需要网络级调节？（当前设计：否）
5. 多租户是否 v1（external 单租户 v1）？
6. 许可证：开源 core / 商业版？

---

## 14. 参考

- iroh：https://github.com/n0-computer/iroh
- iroh 兼容性：https://docs.iroh.computer/compatibility
- iroh 安全：https://docs.iroh.computer/concepts/security-privacy
- tun-rs：https://github.com/tun-rs/tun-rs
- openraft：https://github.com/databendlabs/openraft
- axum：https://github.com/tokio-rs/axum
- utoipa：https://github.com/juhaku/utoipa
- 设计背景：`stellaris-linking-architecture.md`、`stellaris-linking-routing-design.md`、`virtual-network-survey-2026-11.md`
