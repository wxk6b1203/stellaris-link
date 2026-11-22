# stellaris-linking：路由查询、路由调节与可靠控制面（设计草案）

> 设计时间：2026-11-22
> 前提：接受「特权建 TUN + 用户态数据面」；目标不是做一个 demo，而是一个**可完全掌控、相对可靠、可长期维护**的 Rust 产品。
> 本文回答四件事：**要不要扩展 Tunnet、iroh 怎么用、路由查询/调节怎么设计、整体怎么排期**。
> 最终实现架构/协议/计划见：[ARCHITECTURE.md](ARCHITECTURE.md)、[PROTOCOL.md](PROTOCOL.md)、[PLAN.md](PLAN.md)。

---

## 0. 决策清单

| # | 决策 | 选择 | 理由 |
|---|---|---|---|
| 1 | 是否扩展 Tunnet | **不扩展**，clean-room 自研 | MPL/AGPL 许可、v0.9.1 太年轻、路由模型只有 per-IP/LPM/exit，没有 metric/preference/policy，改造成本高于收益 |
| 2 | 传输 | **iroh 1.5 作为依赖**，封装成 `transport-iroh` | 打洞/relay/QUIC/身份/路径统计都现成；自研 NAT 穿透不现实 |
| 3 | 数据面 | **TUN（tun-rs）+ 自研 packet pipeline** | 完全掌控 FIB/ACL/QoS/转发；不把路由逻辑塞进 Tunnet |
| 4 | 路由模型 | **Intent / RIB / FIB / Path 四层分离** | 查询、调节、审计、回滚都清晰；避免“改一条路由=改内核表”的混乱 |
| 5 | 控制面 | **none / embedded / external 三态**，controller 是 agent 的角色 | 满足“可以没有/可以指定某个节点/可以独立服务” |
| 6 | 路由查询 | 每节点只读 `RouteQuery` API + overlay RPC | 支持“本节点有 RIB/没有 RIB/代理到 controller” |
| 7 | 路由调节 | 事务化 `RouteIntent` + `RoutePolicy` + `LinkCost` + `PathPreference` | 既能加/删/改路由，也能调链路代价、pin 下一跳、drain、ECMP |
| 8 | UI | OpenAPI + TypeScript client；一套 UI 覆盖三态 | UI 不是难点；难的是统一 API 和控制面 |
| 9 | 工期 | 2～3 人：6～9 个月可用 MVP，12～18 个月生产级 | 传输/打洞/relay 复用 iroh，主要投入在路由/控制面/跨平台/测试 |
| 10 | 目标规模 | 第一阶段 1k 节点 / 10k 前缀；第二阶段 10k 节点分层 | 先证明收敛/内存/故障恢复，再谈 10k |

---

## 1. 目标、假设、非目标

### 1.1 目标

- 每节点可查询：`RIB`、`FIB`、候选路由、选中原因、传输路径（direct/relay）、RTT/丢包。
- 每节点可调节：静态路由、metric/preference、pin 下一跳、ECMP 权重、链路代价、drain、路由策略、路径偏好。
- 控制面三态：无控制面 / 节点兼任 controller / 独立控制面服务；角色可提升/降级/迁移。
- 完全掌控：代码、数据模型、协议、部署、升级、审计；不依赖闭源控制台。
- 相对可靠：签名 manifest、epoch fencing、事务/回滚、HA、故障注入测试。

### 1.2 假设

- 第一版平台：Linux + macOS（Windows 第二阶段）；移动端后置。
- 网络规模：第一阶段 ≤1,000 节点、≤10,000 前缀；第二阶段再做 10k+ 分层。
- 允许一次特权安装（TUN/驱动/服务）；不要求纯免 root。
- 传输以 QUIC/iroh 为主；不要求 WireGuard 兼容（可作为后续可选数据面）。
- 单租户/单组织优先；多租户后置。

### 1.3 非目标（第一版）

- 不做 L2 广播/组播/ARP 的完整模拟（L3 overlay 为主）。
- 不做 BGP/OSPF 与外部路由器的完整互操作（可导入静态/汇总路由）。
- 不做移动端、浏览器直连、FIPS/等保合规。
- 第一版不做 BLE/802.15.4/LoRa 直连；只预留 gateway/leaf 角色与 `LinkTransport` 抽象，UDP/IP 先行（详见 §13）。
- 不做 WireGuard 兼容、内核态数据面。
- 不做跨公网的大规模 relay 网络运营（自建 relay，容量按需）。

---

## 2. 参考项目的取舍

### 2.1 为什么不在 Tunnet 上改

Tunnet 是很好的**行为参考**，但不适合作为产品底座：

| 维度 | 现状 | 影响 |
|---|---|---|
| 许可 | agent/runtime/SDK：MPL-2.0；control plane/management/dashboard：AGPL-3.0-only；protocol/clients：Apache-2.0 | 改 agent 要按 MPL 公开修改文件；改控制面并对外提供网络服务要按 AGPL 提供源码；商业闭源需商业许可 |
| 成熟度 | v0.9.1（2026-09），约 244 stars，0.x | API/数据模型可能变；生产依赖风险高 |
| 路由模型 | `RoutingTable` 是 per-IP + subnet LPM + exit node；没有 admin distance/metric/preference/ECMP/policy | 你要的“路由调节”需要重写核心路由层，不是加几个 API |
| 控制面 | Managed 是独立 control plane + Bun/Elysia 管理 API + TanStack Dashboard + Postgres | 技术栈异构；要完全掌控需同时维护 Rust/TS/Bun |
| 扩展方式 | 上游活跃、架构仍在演进 | 你的改动会长期冲突；不适合做“完全掌控”的产品 |

**结论：不 fork、不复制代码；只借鉴它的**：
- desired-state OS route reconciliation（`system_routes.rs` 的 owned/reconcile 思路）；
- per-peer Byte-DRR QoS（`qos.rs`）；
- multi-network 冲突检测（`conflict.rs`）；
- snapshot/ACK 的控制面形状；
- Direct 模式的 invite/CRDT 思路。

### 2.2 iroh 能提供什么、不能提供什么

**能提供（本地 iroh 1.5.0，MIT/Apache-2.0）：**
- 按公钥拨号、QUIC、打洞、relay 回退；
- `send_datagram`/`read_datagram`（IP 包走 datagram）；
- `Connection::paths()`/`paths_stream()`/`PathEvent`：看 direct/relay、RTT、selected path；
- `RelayMode::Custom`：自建 relay；
- `Endpoint::builder(...).alpns(...)`：自定义协议；
- 连接身份 = endpoint 公钥，天然适合做节点身份。

**不能直接提供：**
- IP 路由/RIB/FIB/ACL/NAT/exit node——这些要自己做。
- **稳定的自定义路径选择**：`Endpoint::path_selector` 目前 gated behind `unstable-custom-transports`；`PathSelection` 一次只能选一条路径。
- 生产级公网 relay：默认 relay 是 n0 的，产品必须自建 `RelayMode::Custom`。
- 多路径聚合/ECMP：QUIC 连接内部不做多路径负载均衡。

**策略：**
- iroh 作为 `transport-iroh` crate 的唯一依赖，锁 1.5.x；不把 iroh 类型泄漏到路由/控制面。
- MVP 用 iroh 默认路径选择（biased RTT、relay 兜底、sticky）；**路径偏好**只做“peer/relay set”级别，direct/relay 强制作为实验特性。
- 如果必须强制 direct/relay：开 `unstable-custom-transports` + 实现 `PathSelector`，或维护一个很小的 iroh patch；必须隔离在 feature flag 后面，并接受升级成本。
- 自建 relay：`RelayMode::Custom` + 自己的 `iroh-relay` 部署；不要把控制面/数据面绑到 n0 公共服务。

### 2.3 EasyTier / ZeroTier 的参考点

- **EasyTier**：链路状态同步、子网路由自动下发、`--latency-first` 双下一跳、multi-instance；可参考“无控制面时的自动路由”行为，但不要抄 LGPL 代码。
- **ZeroTier**：controller 是任意节点、local JSON API、Managed Routes；可参考“controller 角色/本地 API 形状”，但 controller 许可非自由，不能作为依赖。
- **Tailscale/NetBird**：API/ACL/UX 参考；控制面中心化，不适合“无控制面”模式。

> 结论：EasyTier/ZeroTier/Tunnet 都只做**行为参考**，不作为代码底座；底座用 iroh + 自研 routing/control/dataplane。

---

## 3. 总体架构

```text
┌───────────────────────────── agent ─────────────────────────────┐
│  TUN (tun-rs)                                                    │
│    │ IP packet                                                   │
│    ▼                                                             │
│  parser ──► ACL ──► FIB lookup ──► QoS ──► encap ──► transport   │
│    │                         │                         │         │
│    │                         │                         ├─ iroh direct
│    │                         │                         └─ iroh relay
│    ▼                         ▼                                   │
│  RouteQuery API          link metrics / path stats               │
│    │                         │                                   │
│  RouteEngine ◄──── RouteIntent / Snapshot ──── controller         │
│    │                         │                                   │
│  Intent store / RIB / FIB    │                                   │
│    │                         │                                   │
│  local UI (optional)         │                                   │
└──────────────────────────────┼───────────────────────────────────┘
                               │
              ┌────────────────┴────────────────┐
              │ controller (embedded/external)   │
              │ - membership / IPAM / ACL        │
              │ - route computation              │
              │ - signed manifest / snapshots    │
              │ - RouteIntent / audit            │
              │ - UI/API (OpenAPI)               │
              │ - HA (openraft / lease)          │
              └────────────────┬────────────────┘
                               │
                         relay (self-hosted)
```

### 3.1 分层

| 层 | 职责 | 不做什么 |
|---|---|---|
| `transport-iroh` | 连接、打洞、relay、datagram、路径统计 | 不做路由决策 |
| `dataplane` | TUN、解析、ACL、FIB、QoS、encap/decap、NAT | 不做控制面 |
| `routing` | Intent/RIB/FIB、SPF/ECMP、策略、校验 | 不直接碰 iroh |
| `control` | manifest、角色、快照、ACK、HA、审计 | 不碰内核路由 |
| `api` | HTTP/gRPC/CLI/OpenAPI | 不实现路由算法 |
| `ui` | 拓扑、路由工作台、诊断 | 不直连内核 |

---

## 4. 路由模型：Intent / RIB / FIB / Path

### 4.1 为什么要四层

- **Intent**：人或 controller 想要什么（静态路由、pin、policy、link cost）。可审计、可回滚。
- **RIB**：路由算法算出来的候选集（link-state/controller）。可查询、可解释。
- **FIB**：数据面真正用的下一跳/ECMP 组。可原子替换。
- **Path**：传输层实际选的 direct/relay 路径和 RTT。可观测，但第一版只做有限调节。

> 只改 FIB 不留 Intent，无法解释“为什么”；只存 Intent 不算 RIB，无法处理拓扑变化；只算 RIB 不编译 FIB，数据面无法执行。

**RIB 可选，FIB 必需**：

| `rib_mode` | 本节点有什么 | 查询怎么答 |
|---|---|---|
| `full` | 链路状态库 + RIB + FIB | 本地直接答，含候选/路径 |
| `cache` | controller 推送的 RIB 缓存 + FIB | 本地缓存答，带 generation/TTL |
| `none` | 只有 FIB（默认/聚合路由） | 返回 `501 rib_disabled`，或 `?proxy=true` 转 controller |

> `none` 只表示“不做全局 RIB”，不表示“不转发”。数据面永远有 FIB。

### 4.2 数据结构

```rust
pub struct RouteEntry {
    pub id: RouteId,
    pub network_id: NetworkId,
    pub prefix: IpNet,
    pub source: RouteSource,
    pub origin: NodeId,          // 谁发起
    pub next_hop: NextHop,
    pub admin_distance: u8,      // 越小越优先
    pub local_pref: u32,         // 越大越优先
    pub metric: u32,             // 越小越优先
    pub weight: u16,             // ECMP 权重
    pub pin: bool,               // 固定下一跳
    pub state: RouteState,       // Active/Stale/Withdrawn/Filtered
    pub generation: u64,
    pub expires_at: Option<SystemTime>,
    pub attributes: RouteAttributes,
}

pub enum RouteSource {
    Connected,   // 直连/本地
    Static,      // 人工静态
    Controller,  // controller 下发
    LinkState,   // SPF 计算
    Aggregate,   // 聚合
    Default,     // 默认/exit
}

pub struct NextHop {
    pub node: NodeId,
    pub path_hint: PathHint,     // Auto/Direct/Relay/AvoidRelay
    pub weight: u16,
}

pub enum PathHint { Auto, Direct, Relay, AvoidRelay }

pub struct RouteAttributes {
    pub rtt_ms: Option<u16>,
    pub loss_ppm: Option<u32>,
    pub bandwidth_kbps: Option<u64>,
    pub region: Option<String>,
    pub tags: Vec<String>,
}
```

`PathHint` 语义（第一版是 best-effort）：

| hint | 行为 | 失败时 |
|---|---|---|
| `Auto` | iroh 默认：直连优先、relay 兜底、sticky | 不保证 |
| `Direct` | 优先直连；没有直连时允许 relay | 告警 |
| `Relay` | 优先 relay；没有 relay 时允许直连 | 告警 |
| `AvoidRelay` | 只允许直连；没有直连则不建流 | 明确报错/黑洞（可配置） |

> iroh 默认 `PathSelector` 是内部实现；真正强制 `Direct`/`Relay` 需要 `unstable-custom-transports` 或小 patch。第一版把 `PathHint` 当“偏好/观测”，不要承诺硬隔离；`AvoidRelay` 如果要做硬保证，必须走 feature flag + 测试。

### 4.3 来源优先级

默认 `admin_distance`：

| 来源 | distance | 说明 |
|---|---:|---|
| Connected | 0 | 直连，最可信 |
| Static | 1 | 人工路由，覆盖自动 |
| Controller | 20 | 控制面意图 |
| LinkState | 100 | SPF 计算 |
| Default | 255 | 兜底 |

同前缀选择顺序：

1. **最长前缀匹配**（LPM）先决定候选前缀；
2. 过滤：`state != Active`、过期、policy deny、下一跳不可达；
3. `admin_distance` 升序；
4. `local_pref` 降序；
5. `metric` 升序；
6. 多个等价 → ECMP（按 `weight`，5 元组哈希）；
7. `pin=true` 时只保留指定 next hop（仍要校验可达/不环路）；
8. 没有候选 → 默认路由/exit node；再没有 → drop + ICMP unreachable。

> `pin` 不绕过最长前缀，只绕过“同前缀的自动选路”。紧急 `force` 可以作为单独的高危操作（需 admin + 审计），第一版不建议开放。

### 4.4 FIB 编译

```rust
pub struct FibEntry {
    pub prefix: IpNet,
    pub ecmp: Vec<FibNextHop>,   // 至少一个
    pub generation: u64,
    pub source: RouteSource,
}

pub struct FibNextHop {
    pub node: NodeId,
    pub iface: IfaceId,          // TUN
    pub weight: u16,
    pub path_hint: PathHint,
    pub encap: Encap,            // iroh endpoint id / relay hint
}
```

- FIB 用 `prefix-trie`（IPv4/IPv6 分开）或等价 LPM 结构；
- 每次 RIB 变化只重建受影响的 prefix；
- `ArcSwap<Fib>` 原子替换；数据面读旧 FIB 不阻塞；
- 同时生成 OS 路由（TUN 路由/子网路由），用 desired-state reconcile 应用，失败可回滚。
- 注意：overlay 前缀的 OS 路由通常只需 `prefix -> TUN`；调整 next hop 主要改 FIB，不必反复改内核路由。只有 local bypass/blackhole/策略路由才需要独立 OS 路由表（Linux `ip rule`/table，macOS `pf`/route，Windows `NRPT`/WFP）。

### 4.5 路由调节操作

统一成 `RouteChange`，全部支持 `dry_run`、`reason`、`idempotency_key`、`if_match_generation`：

```rust
pub enum RouteChange {
    UpsertStatic(UpsertStatic),
    Delete { id: RouteId },
    Pin { prefix: IpNet, next_hop: NodeId, expires_at: Option<SystemTime> },
    Unpin { prefix: IpNet },
    SetPolicy(RoutePolicy),
    SetLinkCost { peer: NodeId, cost: u32 },
    SetPathPreference { peer: NodeId, hint: PathHint, weight: u16 },
    Drain { node: NodeId, grace: Duration },
    Reset { prefix: Option<IpNet> },   // 回到计算路由
}
```

语义：

| 操作 | 效果 | 风险控制 |
|---|---|---|
| `UpsertStatic` | 插入/更新静态 Intent，distance=1 | 校验前缀/下一跳；默认 24h 过期；可回滚 |
| `Pin` | 同前缀固定 next hop | 校验 next hop 在线/不环路；可设 TTL；高危审计 |
| `SetLinkCost` | 改链路代价，影响 SPF/controller 算路 | 限幅；drain 用 max cost |
| `SetPathPreference` | 对该 peer 偏好 direct/relay | 第一版 best-effort；依赖 iroh 路径选择能力 |
| `Drain` | 逐步把流量移走，再撤销该节点路由 | grace 期；只影响新流；可取消 |
| `Reset` | 删除静态/pin，回到计算路由 | 保留审计；可 diff |

### 4.6 校验、事务、回滚

**校验（apply 前）：**
- prefix 规范化（network/broadcast 处理）；拒绝非法/超长前缀；
- next hop 必须是本网络成员；可选 `allow_offline`；
- 不允许 next hop = self；路径中不能包含 self（防环）；
- next hop 必须“拥有”该前缀，或显式 `force`（第一版禁用）；
- 同一前缀多来源冲突 → 按优先级解析并给出 warning；
- 路由数/前缀数限额；ECMP 成员数限额；
- 策略 deny 的前缀不能通过 static 绕过（可配置）。

**事务（apply）：**
1. 计算新 Intent 集 → 新 RIB → 新 FIB（不落地）；
2. `dry_run` 返回 diff、受影响节点、预计收敛时间；
3. 提交：写 Intent store（SQLite/Postgres）→ 递增 generation；
4. 原子替换 FIB；应用 OS 路由；
5. 若 OS 路由失败：回滚 FIB/Intent，返回错误；
6. 记录 audit（who/when/why/old/new/result）。

**回滚：**
- 不是“反向操作”，而是生成一个新的 generation，把 Intent 集恢复到上一个版本；
- 保留完整历史，支持 `route history`/`route rollback <generation>`。

### 4.7 路由策略（RoutePolicy）

```rust
pub struct RoutePolicy {
    pub id: PolicyId,
    pub priority: u32,          // 越小越先匹配
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

- 先匹配先执行；未匹配走默认策略（默认 allow，可配置 default deny）。
- Policy 只改“候选/属性”，不直接写 FIB；最终仍由 4.3 的算法选路。
- `explain` 必须显示命中的 policy id 和修改前后的属性。
- Policy 变更也要走事务/审计；不能绕过 `dry_run`。

### 4.8 ECMP、哈希与粘性

- 哈希输入：`src_ip, dst_ip, src_port, dst_port, protocol, network_id`；没有端口（ICMP）用 type/code。
- 先按权重归一化选 ECMP 成员；同一 flow 固定同一成员，避免乱序。
- 成员 health check 失败时临时移除；恢复后按新权重重新哈希（允许少量 flow 迁移）。
- 路由变化时尽量保持已有 flow 的成员不变；只有成员集合变化才重哈希。
- 每 flow 缓存（LRU）可以省 CPU，但要有上限和老化；不要缓存到影响故障切换。
- ECMP 成员数上限（如 8）；超过则按权重截断并告警。

### 4.9 路由调节状态机

```text
Draft → Validated → Applying → Active → Expired
                         └──► Failed → RolledBack
```

- `Draft`：UI/CLI 编辑，未提交。
- `Validated`：`dry_run` 通过，有 diff/warning。
- `Applying`：已写 Intent，等待 FIB/OS 路由/节点 ACK。
- `Active`：所有目标节点 ACK；UI 显示 applied。
- `Expired`：TTL 到期自动撤销。
- `Failed`：应用失败，自动回滚或等待人工处理。
- 任何状态都可 `RolledBack` 到上一个 generation。

---

## 5. 控制面：三态、角色、协议

### 5.1 三态

```text
control_mode = none | embedded | external
role         = member | controller | relay
```

| 模式 | 控制面 | 路由计算 | 适用 |
|---|---|---|---|
| `none` | 无 | 每节点 SPF/路径向量 | 小中规模、无服务器、临时网络 |
| `embedded` | 某个成员节点兼任 controller | controller 算，推 FIB | 有服务器但不想独立部署；controller 可迁移 |
| `external` | 独立服务（可多租户） | controller 算 | 企业/多网络/集中运维 |

`none` 模式的加入/成员：
- 创建者生成 genesis manifest（network_id、CIDR、创建者签名、初始成员），签一次；
- invite code 带 `network_id + secret + creator endpoint_id`；新节点用 invite 向创建者/任一成员申请；
- 成员表用 CRDT/gossip 复制（可参考 iroh-docs，或自己实现简单的 signed member log）；
- 撤销：签名 revocation 列表；成员收到后拒绝握手；
- 没有 controller，所以网络级 route adjustment 不支持；本地 static/pin 只影响本节点。

**关键：controller 不是特殊二进制，而是 agent 的一个角色（feature gate）。** 这样“任意节点可当 controller”才是真的可切换，而不是换一套部署。

controller 的能力可以进一步拆分（规模化时）：

```text
controller_caps = membership | routing | policy | api_ui
```

- MVP：一个 controller 进程做全部四件事。
- 规模化：membership 与 routing 可以分开（例如 3 节点 membership quorum + 2 个 routing worker）；API/UI 可以独立部署。
- 拆分后仍用同一套 manifest/epoch；不要出现两个“事实源”。

### 5.2 manifest

controller 签名的唯一事实源：

```json
{
  "network_id": "n_...",
  "epoch": 7,
  "generation": 42,
  "controllers": ["ed25519:..."],
  "members": [{"node_id": "ed25519:...", "ip": "10.7.0.5", "role": "member"}],
  "ipam": {"cidr": "10.7.0.0/16"},
  "acl": [{"src": "tag:prod", "dst": "tag:db", "ports": ["tcp/5432"], "action": "allow"}],
  "route_generation": 128,
  "issued_at": "2026-11-22T00:00:00Z",
  "expires_at": "2026-11-23T00:00:00Z",
  "signature": "base64..."
}
```

- manifest 只放“成员/策略/IPAM/版本”，**不放全量路由**；路由用单独的 `RouteSnapshot`/`RouteDelta`。
- `epoch` 防旧 controller 复活；`generation` 防旧快照覆盖。
- 成员缓存最后 manifest；controller 失联时继续用未过期配置。

### 5.3 控制协议（over iroh）

控制面也走 iroh，不依赖公网 IP/域名：

```text
ALPN: stellaris/control/1
双向流 + length-delimited protobuf
```

消息：

```text
Hello { version, network_id, node_id, epoch, nonce, signature }
JoinRequest / JoinResponse
SyncRequest { known_generation }
SyncResponse { full_snapshot | delta }
RouteIntent { intent_id, change, generation, signature }
RouteAck { generation, applied_hash, errors }
Heartbeat { generation, route_checksum }
Revoke { node_id, epoch, signature }
RouteQuery { dst } / RouteQueryResponse { ... }
```

- 连接建立后先 `Hello`，校验成员身份/epoch/签名；不通过直接断开。
- controller 推送 `RouteIntent`/`RouteDelta`；agent 应用后 `RouteAck`。
- controller 记录每个 agent 的 `applied_generation`/`applied_hash`；UI 显示 drift。
- 大快照用 zstd 压缩；增量用 delta；超过阈值回退全量。
- 控制流和数据流分开 ALPN，避免大流量影响控制。

controller 持久化（Postgres，示意）：

```text
networks(id, name, cidr, epoch, generation, manifest_json)
members(network_id, node_id, ip, role, tags, status)
route_intents(id, network_id, scope, change_json, generation, expires_at, created_by)
route_policies(id, network_id, priority, match_json, action_json)
applied_status(network_id, node_id, generation, applied_hash, error, updated_at)
audit_log(id, network_id, actor, action, old_json, new_json, result, created_at)
```

### 5.4 HA / 角色迁移

- **MVP**：单 controller + 冷备；manifest/DB 定期备份；节点保留最后快照。
- **生产**：3 controller + openraft；leader 处理写；follower 只读/转发；quorum 才允许变更。
- **角色迁移**：`promote` 新节点 → epoch+1 → 新 controller 从 DB/快照恢复 → 节点拉新 manifest → 旧 controller 写被 fence。
- **授权**：`promote`/`demote` 必须由现有 controller quorum 或离线 admin key 签名；节点不能自封 controller；所有角色变更进 audit。
- **脑裂**：没有 quorum 的 controller 拒绝写；节点只接受更高 epoch 的 manifest。
- **controller 宕机**：数据面继续；新加入/路由变更暂停；manifest 过期进入只读安全模式。

### 5.5 路由调节在三种模式下的语义

| 模式 | 本地 static | 网络级 Intent | 说明 |
|---|---|---|---|
| `none` | 本地生效 | 不支持（或签名 intent + gossip，后置） | 第一版明确“本地调节” |
| `embedded` | 本地生效，可覆盖 | controller 推送，所有节点生效 | 推荐 |
| `external` | 本地生效，可覆盖 | controller 推送，多网络 | 企业 |

> 如果 `none` 模式也必须网络级调节，需要增加“签名 RouteIntent 的 gossip 复制 + 冲突解决”，复杂度高；建议第一版不做，或只支持“创建者签名的一次性 intent”。

---

## 6. 数据面

### 6.1 packet pipeline

```text
TUN read
  → parse IPv4/IPv6 + TCP/UDP/ICMP
  → anti-spoof (src IP belongs to peer)
  → ACL (per network)
  → FIB LPM
  → TTL decrement / loop check
  → QoS classify/enqueue
  → encap MeshHeader + IP packet
  → iroh datagram send
```

接收：

```text
iroh datagram recv
  → verify peer/network
  → parse MeshHeader
  → TTL/loop
  → anti-spoof
  → ACL
  → if dst local: write TUN
  → else: FIB forward
```

### 6.2 MeshHeader

第一版尽量小：

```rust
#[repr(C)]
struct MeshHeader {
    version: u8,
    flags: u8,
    ttl: u8,
    network_id: u32,   // 网络索引/哈希
    flow_hash: u32,    // 可选，ECMP
}
```

- 源/目的节点不需要放：IP 包 + 连接身份足够；转发时查 FIB。
- `ttl` 防环；每跳减一；到 0 发 ICMP time exceeded（可选）。
- `flow_hash` 用于 ECMP/多队列；没有则用 5 元组哈希。

### 6.3 MTU / 分片 / MSS

- TUN MTU 默认 **1280**（IPv6 最小 MTU；Tunnet 也用 1280）。
- **不要硬编码 1280**：连接建立后读 `conn.max_datagram_size()`；TUN MTU 取 `min(1280, max_datagram_size - header - safety)`。
- TUN MTU 是全局的，但不同 peer/路径的 max 可能不同：按最差路径取保守值，或对超限的包逐包分片；不要因为一个坏 peer 把全网 MTU 永久降到 576。
- 如果 `max_datagram_size < 1280 + header`：IPv4 可在 agent 内分片/重组；IPv6 必须源端分片或暂时禁用 IPv6（IPv6 不允许中间路由器分片）。不要让大包静默丢弃——记录并告警 `datagram_too_large`。
- QUIC datagram 的可用 payload 受路径 MTU 限制；iroh 会做 MTU 探测，但第一版按 1280 设计。
- IPv4：允许分片/DF；收到 ICMP frag needed 时更新 PMTU；必要时在 agent 内做分片/重组。
- IPv6：不允许路由器分片；必须靠 PMTU/ICMPv6 Packet Too Big；TUN MTU 1280 是安全值。
- TCP MSS clamp：`MSS = MTU - 40`（IPv4）/ `-60`（IPv6），在 SYN/SYN-ACK 上改；否则大包会被黑洞。
- 这是第一版必须做的，不是优化项。

### 6.4 QoS

- 解析 TCP/UDP/ICMP；分类 Latency/Normal/Bulk（参考 Tunnet 的 Byte-DRR 思路，但不复制代码）。
- 每 peer 三条队列；Byte-DRR 调度；队列满时优先丢 bulk，再 normal，最后 latency。
- 每 peer/prefix 限速；DSCP 映射；控制报文优先。
- 不要用单一 FIFO：否则大流量会饿死 ping/SSH。

### 6.5 NAT / exit / subnet gateway

- exit node：开启 IP forwarding + MASQUERADE（Linux nftables、macOS pf、Windows WinNAT）。
- subnet gateway：转发到 LAN；需要 ARP/NDP 或 raw socket；第一版可只做 exit + 静态子网路由，subnet gateway 第二阶段。
- NAT 状态与 conntrack 由内核管理；agent 只负责安装/清理规则。
- 所有规则打上 owner 标记（表名/comment），避免和 Tunnet/Tailscale 冲突；启动时只清理自己的规则。

### 6.6 多网络

- 每个 network 独立：虚拟 CIDR、FIB、ACL、DNS、manifest。
- 一个 agent 可加入多个 network；TUN 可以一个多地址，或多个 TUN；第一版建议一个 TUN + 多地址，简化路由。
- 地址冲突：创建时检测本机路由/其他 VPN；冲突时报错/降级（参考 Tunnet `conflict.rs` 的思路）。
- 跨网络默认隔离；需要显式策略才能互通。

### 6.7 Relay 选择

- 每个 network 配置 relay 集合（自建），用 `RelayMode::Custom`；不要依赖 n0 公共 relay。
- 节点选 home relay（最近/最低 RTT）；relay 故障时 iroh 自动重选，路由不变。
- `PathHint::Relay` 只是偏好；真正固定某个 relay 需要 custom path selector 或 patch。
- RouteQuery 的 `transport` 返回 relay URL/region，便于排障和容量规划。
- relay 只转发加密流量，不应能看到明文；容量/带宽单独监控。

---

## 7. 路由协议

### 7.1 `none` 模式：link-state

- 每个节点洪泛 `LinkState`：

```rust
struct LinkState {
    origin: NodeId,
    sequence: u64,
    links: Vec<Link>,       // peer, cost, rtt, loss, capacity
    prefixes: Vec<Prefix>,  // prefix, metric, flags
    ttl: u8,
    signature: Signature,
}
```

- 收到更新：sequence 更大才接受；TTL 防环；checksum；年龄。
- SPF（Dijkstra）算最短路径树；ECMP；前缀挂到 origin。
- 路由聚合：area 边界汇总；只通告前缀，不通告所有 peer。
- 规模控制：`lazy-p2p`（有流量才打洞）、relay 不参与计算、限制洪泛频率、dampening。
- 第一版可以先做“扁平 link-state + 1k 节点”，10k 再做 area。

### 7.2 `embedded/external`：controller 算路

- 成员上报：邻居、RTT、丢包、容量、可达前缀。
- 上报是自报数据：controller 做时间戳/边界/一致性校验；关键路径用双向探测或被动统计交叉验证，避免单节点谎报/坏数据带偏全网。
- controller 构图；按 `link cost`/latency/loss 算最短路；ECMP；HA gateway。
- 应用策略：prefix filter、region preference、max latency、avoid relay。
- 生成 `RouteSnapshot`：每个 prefix 的 next-hop 列表 + weight + metric + generation。
- 节点只执行 FIB；可选缓存 RIB（`rib_mode=cache`）。

### 7.3 混合

- controller 算 baseline；本地 static/pin 覆盖同前缀。
- controller 失联：保留最后 FIB；可选 fallback 到本地 link-state（如果开启）。
- 本地 link-state 与 controller 同时存在时，用 `admin_distance` 明确优先级；不要“谁先到用谁”。

### 7.4 聚合/分层/规模

- 聚合：`10.7.0.0/16` 汇总子网；more-specific 仍然优先；聚合路由标记 `Aggregate`，不覆盖明细。
- 分层：area/cluster；area border 节点汇总；controller 可按 area 分片。
- 限额：每节点 RIB/FIB 上限、每 peer 前缀上限、ECMP 成员上限；超限拒绝并告警。
- 收敛目标：1k 节点、常规变更 <5s；大规模路由抖动要 dampening。

---

## 8. API / CLI / UI

### 8.1 RouteQuery API

本地（Unix socket）和 overlay（mTLS）同一套 schema：

```http
GET /v1/status
GET /v1/peers
GET /v1/routes?view=intent|rib|fib&family=ipv4|ipv6
GET /v1/routes/lookup?dst=10.7.0.5
GET /v1/routes/explain?dst=10.7.0.5
GET /v1/paths?peer=...
GET /v1/events        # SSE/WebSocket
```

`status` 至少包含：

```json
{
  "node_id": "ed25519:...",
  "network_id": "n_...",
  "role": "member",
  "control_mode": "embedded",
  "rib_mode": "cache",
  "generation": 42,
  "controller": "ed25519:...",
  "uptime_secs": 3600
}
```

`explain` 响应（核心）：

```json
{
  "dst": "10.7.0.5",
  "selected": {
    "prefix": "10.7.0.0/16",
    "next_hop": "node_b",
    "source": "link-state",
    "admin_distance": 100,
    "metric": 20,
    "path": ["node_a", "node_b"],
    "transport": {"path": "direct", "rtt_ms": 12}
  },
  "candidates": [
    {"next_hop": "node_c", "metric": 35, "eligible": false, "reason": "higher metric"},
    {"next_hop": "node_d", "metric": 20, "eligible": true, "reason": "ecmp"}
  ],
  "generation": 42
}
```

- 本地 socket 用文件权限 + bearer；overlay 用 mTLS；只读；限流。
- 不返回密钥/PSK/证书私钥；只返回路由/拓扑/统计。
- `explain` 允许 `?verbose=true` 返回候选淘汰原因，便于 UI。

### 8.2 RouteAdjust API

```http
POST   /v1/routes
PATCH  /v1/routes/{id}
DELETE /v1/routes/{id}
POST   /v1/routes/{id}/drain
POST   /v1/routes/{id}/pin
POST   /v1/policy
POST   /v1/links/{peer}/cost
POST   /v1/paths/{peer}/preference
POST   /v1/routes/reset
GET    /v1/routes/history
POST   /v1/routes/rollback
```

请求示例：

```json
{
  "prefix": "192.168.1.0/24",
  "via": "node_b",
  "scope": "local",
  "admin_distance": 1,
  "metric": 10,
  "weight": 100,
  "pin": true,
  "expires_at": "2026-11-23T00:00:00Z",
  "reason": "maintenance window",
  "dry_run": true,
  "if_match_generation": 42,
  "idempotency_key": "req-123"
}
```

`scope`：
- `local`：只改本节点；agent 本地 API 默认。
- `network`：改全网，必须走 controller（`embedded/external`）；需要 admin，`none` 模式返回 400（第一版）。
- controller API 默认 `network`；agent 收到 `network` 请求时转发给 controller 或拒绝，不要偷偷本地生效。

响应：

```json
{
  "tx_id": "tx-...",
  "generation": 43,
  "dry_run": true,
  "diff": {
    "added": [{"prefix": "192.168.1.0/24", "via": "node_b"}],
    "removed": [],
    "affected_nodes": ["node_a", "node_b"]
  },
  "warnings": ["next hop is currently offline; route will be installed but inactive"]
}
```

### 8.3 CLI

```bash
stellaris route list --view intent|rib|fib
stellaris route add 192.168.1.0/24 via node_b --metric 10 --dry-run
stellaris route update <id> --metric 20
stellaris route delete <id>
stellaris route pin 10.7.0.0/16 via node_c --ttl 1h
stellaris route unpin 10.7.0.0/16
stellaris route explain 10.7.0.5
stellaris route drain node_b --grace 5m
stellaris link cost node_b 100
stellaris path prefer node_b direct
stellaris route history
stellaris route rollback 42
```

### 8.4 UI

一套 OpenAPI + TypeScript client，覆盖三态：

- **拓扑**：节点/链路/relay；链路 cost 可编辑；drain 按钮；路径高亮。
- **路由工作台**：Intent/RIB/FIB 三个 tab；搜索/过滤；diff；dry-run；apply；rollback。
- **Explain**：选中原因、候选、传输路径、RTT/丢包。
- **事件/审计**：谁在何时改了什么，结果如何。
- **诊断**：NAT 类型、relay、MTU、丢包、路由收敛时间。

UI 托管：
- controller 模式：controller 提供静态资源 + API；
- 单机/`none`：本地 agent 提供单机视图；
- 桌面：Tauri 包一层，不重写 UI。

> 管理 API 默认只绑 localhost/内网；远程访问通过 overlay 或 SSO 反向代理；不要把管理 API 裸奔在公网。

---

## 9. 可靠性与安全

### 9.1 事务/幂等/审计

- 每个变更：`tx_id`、`idempotency_key`、`if_match_generation`、`reason`、`actor`。
- 重复请求返回同一结果；generation 不匹配返回 409。
- 所有变更写 audit；保留 N 天；支持导出。
- 失败可回滚；回滚也是一次新变更，不修改历史。

### 9.2 失败模式

| 失败 | 行为 |
|---|---|
| controller 宕机 | 保留最后 manifest/FIB；数据面继续；新变更暂停 |
| controller 脑裂 | 无 quorum 拒绝写；节点只接受更高 epoch |
| relay 故障 | iroh 重新选 relay；路由不变；告警 |
| peer 故障 | link-state 撤销/controller 标记 down；FIB 切 ECMP/备份；dampening |
| 路由抖动 | hold-down/dampening；限制更新频率 |
| OS 路由安装失败 | 回滚 FIB/Intent；保留旧路由；告警 |
| manifest 过期 | 只读安全模式；不接新 peer；可配置宽限 |
| agent 重启 | 从 SQLite 恢复 Intent/FIB；reconcile OS 路由；向 controller 同步 generation |

Agent 本地持久化（SQLite + WAL）：`intents`、`fib_snapshot`、`manifest`、`generation`、`applied_hash`；启动时先恢复再 reconcile，避免“启动即断网”。

**可靠性目标（建议，不是 SLA 承诺）：**

| 场景 | 目标 |
|---|---|
| controller 宕机 | 已建立 direct 连接不受影响；数据面继续；新变更暂停 |
| controller 故障发现 | <60s（心跳/租约） |
| relay 故障 | iroh 自动重选；<30s；已有流可能短暂中断 |
| 路由收敛（1k 节点） | 常规变更 <5s；节点故障 <30s |
| agent 重启 | <5s 恢复 FIB/OS 路由；不要求保持已有 TCP |
| 配置回滚 | 一次操作内完成；旧 generation 可查 |

### 9.3 安全

- 身份：Ed25519 endpoint key；manifest 签名；节点准入。
- 传输：QUIC/TLS 1.3；控制面/数据面都走 iroh；不裸 UDP。
- 网络隔离：network_id + 成员校验；跨网络默认拒绝。
- 防 spoof：入站源 IP 必须属于该 peer（mesh IP/子网路由）；否则丢弃。
- 路由注入：只有授权 origin 能通告前缀；controller 校验 prefix ownership；static 需要 admin。
- 重放：nonce/timestamp/epoch；manifest 过期。
- 撤销：manifest 移除 + 拒绝握手；controller 记录。
- 审计：所有路由变更、登录、ACL 变更。
- 最小权限：viewer/operator/admin/controller 角色；本地 socket 权限。

### 9.4 可观测性

- 指标：每 prefix/peer 的包/字节/丢包/RTT；路由变更次数/收敛时间；controller 延迟；relay 流量。
- 日志：结构化；路由变更加 old/new/reason。
- Trace：每个包的采样 trace（可选）；explain 足够排障。
- 告警：controller 不可达、relay 不可用、路由抖动、MTU 黑洞、证书过期。

---

## 10. 测试计划

### 10.1 单元/属性

- LPM、优先级、ECMP、pin、policy、聚合、环路检测。
- 属性测试：任意拓扑/路由集，不产生环路；可达性单调；回滚可恢复。
- 模糊测试：packet parser、控制协议解码。

### 10.2 集成

- Linux netns + veth + nftables，模拟 3/10/100 节点。
- NAT 类型：full cone/restricted/port-restricted/symmetric；CGNAT；UDP 被封。
- relay：直连失败回退；relay 故障切换。
- 多网络：地址冲突、隔离、跨网策略。
- 路由调节：add/update/delete/pin/drain/rollback；dry-run 与实际一致。

### 10.3 混沌/规模

- kill controller/relay；网络分区；时钟偏移；重复请求；manifest 过期。
- 1k 节点模拟（离散事件或容器）；10k 前缀；路由 churn；收敛时间/内存。
- 长稳：24h 流量 + 随机故障。

### 10.4 跨平台

- Linux（主）、macOS（utun/route/pf）、Windows（WinTun/IP Helper/WFP）。
- CI：Linux 全量；macOS/Windows 编译 + 关键集成；发布前手工冒烟。

---

## 11. 里程碑与团队

### 11.1 里程碑（2～3 人）

| 阶段 | 时间 | 交付 | 验收 |
|---|---|---|---|
| M0 | 2 周 | 设计/威胁模型/iroh+tun-rs spike | 两节点 IP 隧道 ping 通 |
| M1 | 6 周 | TUN、FIB、静态路由、RouteQuery（只读）、CLI | `route list/lookup/explain` 可用 |
| M2 | 6 周 | Intent/RIB、RouteAdjust、policy、dry-run/rollback | 路由 add/pin/drain 可回滚 |
| M3 | 8 周 | `none` link-state、多网络、ACL、QoS | 3 节点无控制面组网 |
| M4 | 8 周 | `embedded` controller、manifest/epoch、HA 基础 | 任意节点当 controller |
| M5 | 8 周 | UI、打包、指标、故障注入 | 内测版 |
| 生产 | 12～18 个月 | 安全审计、1k 节点、跨平台、HA | 生产 SLA |

### 11.2 团队

- 2 名 Rust（数据面/路由、控制面）；
- 1 名平台/网络（TUN/NAT/跨平台/relay，兼职或全职）；
- 1 名前端（OpenAPI/UI，兼职）；
- 1 名 QA/安全（兼职）。

### 11.3 建议的代码结构

```text
crates/
  stellaris-common      # 类型、协议、错误
  stellaris-transport   # iroh 封装、路径统计、relay
  stellaris-dataplane   # TUN、parser、ACL、QoS、encap
  stellaris-routing     # Intent/RIB/FIB、SPF、policy
  stellaris-control     # manifest、controller、snapshot、HA
  stellaris-agent       # 进程/服务、配置、reconcile
  stellaris-api         # axum/gRPC、OpenAPI
  stellaris-cli         # CLI
  stellaris-testkit     # netns/模拟/故障注入
apps/
  dashboard             # TS/Svelte/React
  desktop               # Tauri
```

### 11.4 第一版 MVP 范围（建议冻结）

**必须：**
- Linux + macOS；TUN；iroh direct/relay；3 节点组网。
- Intent/RIB/FIB；static add/delete/pin/drain；`explain`。
- `none` + `embedded`（单 controller，无 HA）。
- RouteQuery HTTP + CLI；UI 的路由表/Explain/拓扑。
- 基础 ACL、基础 QoS、exit node。
- 10 节点 netns 测试 + NAT 矩阵（full cone/restricted/symmetric）。

**后置：**
- `external` 多租户、3 controller HA、1k 节点。
- Windows、移动端、subnet gateway、per-flow policy。
- WireGuard 兼容、内核态数据面、L2。

---

## 12. 风险与未决问题

### 12.1 风险

| 风险 | 影响 | 缓解 |
|---|---|---|
| iroh API 不稳定/路径选择 gated | 路径调节受限、升级成本 | 锁 1.5.x；封装；路径调节 feature flag；必要时小 patch |
| QUIC 数据面性能/MTU | 吞吐/大包黑洞 | 1280 MTU + MSS clamp；benchmark；后续 WireGuard 可选 |
| NAT 类型复杂 | 直连失败/relay 成本 | iroh 打洞 + 自建 relay；NAT 矩阵测试 |
| 路由收敛/抖动 | 大规模不稳定 | 聚合/分层/dampening；先 1k 再 10k |
| controller HA/脑裂 | 配置不一致 | epoch + quorum + 只读安全模式 |
| 跨平台签名/驱动 | 安装失败 | 先 Linux/macOS；Windows 单独里程碑 |
| 安全审计 | 生产准入 | 早期威胁模型；渗透测试；外部审计 |
| 范围膨胀 | 延期 | 非目标清单；先 L3/exit，后 L2/移动端 |

### 12.2 需要你确认的问题

1. 目标规模：1k 节点够不够？还是要直接冲 10k？
2. 平台优先级：Linux 先行，还是 macOS/Windows 必须同步？
3. 路由调节范围：per-prefix 够，还是要 per-flow（源/目的/端口）策略路由？
4. `none` 模式是否需要网络级路由调节，还是只做本地调节？
5. 是否需要 WireGuard 兼容/内核态数据面？
6. 是否多租户/多组织？
7. UI 是 Web 优先，还是桌面（Tauri）优先？
8. 是否有合规/等保/FIPS 要求？

---

## 13. 低功耗/嵌入式与多协议

> 这一节回答三个问题：**iroh 能不能上低功耗设备、要不要支持多种链路协议、前向安全到底有没有。**

### 13.1 结论

- **能，但不能“每个低功耗节点都跑完整 iroh/QUIC”。** iroh 已经能在 ESP32/RP2350 上作为完整 QUIC endpoint 运行，但 RAM/flash/功耗约束很硬；更合理的是 **core / gateway / leaf 两层**。
- **多协议不是“全都要”，而是“传输抽象 + 网关适配”。** iroh 原生支持 UDP/IP、Wi-Fi/LAN、Ethernet、BLE、Tor、Nym；802.15.4/Thread、LoRaWAN、CAN/RS485 通过 border router/gateway 或自定义 transport 接入。
- **前向安全：正常 1-RTT 有；0-RTT 没有/被削弱；是经典 FS，不是后量子 FS。** iroh 只用 TLS 1.3；完整握手和 PSK-DHE resumption 都有 FS；`into_0rtt()` 明确“weakened security / replay”，VPN 数据面不要用。

### 13.2 iroh 在 MCU 上的真实边界

根据 iroh 官方兼容性页（2026-11）：

| 设备 | RAM/Flash | 能力 |
|---|---|---|
| ESP32-WROVER / ESP32-S3 / ESP32-C61 / ESP32-P4 | 有 PSRAM | 完整 relay + address lookup，可被公网/浏览器访问 |
| ESP32 / ESP32-S3 / ESP32-C6（无 PSRAM，约 512 KiB SRAM） | 无 PSRAM | **仅 LAN-direct**；relay client 和 pkarr lookup 放不下；可用长 ticket 或 mDNS 发现 |
| Flash < 8 MiB | 小 flash | 需要 iroh 的 reduced-dependency build；4 MiB 开发板可调优塞下 |
| RP2350 | 带 WiFi/PSRAM | 可跑完整 iroh；官方做了 Rust std 移植 + FreeRTOS/lwIP |

其他限制：

- **FreeRTOS 已支持**；但 **iroh 完整 no_std 还是大工程**；`noq`（QUIC 实现）移植到 no_std/Embassy 相对可行，但仍是项目级工作，不是开箱即用。
- **QUIC 是有状态的**：握手、连接 ID、丢包检测、keepalive 都要 RAM/CPU/电；电池设备不能像服务器那样维持大量长连接。
- **BLE 不是免费的**：`iroh-ble-transport` 目前是 experimental（custom transport API 也 unstable，需要 `unstable-custom-transports` feature），支持 macOS/iOS/Android/Linux，**ESP32 还未支持**；单连接约 100 kbps，手机侧通常只能同时带 3～5 个 BLE 连接，且该 crate 是 **AGPL-3.0**（商业许可可谈）。
- **不要把 BLE 当高吞吐链路**：适合遥测/控制/小包；大文件/视频别走 BLE mesh。
- **iroh BLE transport 是 GATT 点对点（central/peripheral），不是 BLE Mesh 的 many-to-many flooding**。真正的 BLE Mesh / Thread 网络要用原生协议 + border router/gateway 接入 overlay，不要指望 iroh 把 BLE Mesh 变成 IP mesh。

### 13.3 角色模型：core / gateway / leaf / micro

| 角色 | 跑什么 | 职责 | 不能做什么 |
|---|---|---|---|
| **core** | 完整 agent（可 controller/relay） | 路由计算、控制面、RouteQuery、UI/API | 无 |
| **gateway**（border router） | 完整 iroh + leaf 侧协议 | 代理 leaf 加入 overlay；广告 leaf 前缀；RouteQuery 代理；本地 NAT/ACL | 不应把 leaf 当 transit |
| **leaf**（MCU/传感器） | BLE/CoAP/802.15.4/Modbus 等 | 采集/执行；默认路由到 gateway；`rib_mode=none` | **不能当 controller/relay**；不保存全局 RIB |
| **micro**（ESP32 带 WiFi） | 精简 iroh endpoint | LAN-direct 小网；可选 leaf 网关 | 不做大规模路由/控制面 |

规则：

- **controller / relay 只允许 core 或 gateway**；leaf 的能力位里直接禁止。
- leaf 的“加入网络”是加入 gateway，由 gateway 代理它的 overlay 身份/前缀；leaf 不需要理解 manifest/epoch。
- gateway 是 leaf 的默认路由 + RouteQuery 代理；leaf 的 `rib_mode=none` 返回 `501` 时，客户端应查 gateway。
- gateway 要按区域做冗余（2+），leaf 可重连到备用 gateway；overlay 只广告聚合后的 leaf 前缀，用 ECMP/HA 切换，不要让 leaf 自己参与选路。
- 如果 leaf 需要被其他节点主动访问，gateway 广告 `leaf-prefix` 或做端口映射；不要让 leaf 参与 SPF。

### 13.4 多协议策略

| 链路 | 支持方式 | 适用 | 注意 |
|---|---|---|---|
| UDP/IP（Wi-Fi/Ethernet/蜂窝） | iroh 原生 | 主流 | IPv4/IPv6 都要测 |
| BLE | `iroh-ble-transport`（experimental） | 手机/桌面近场、低功耗 | AGPL；ESP32 未支持；100 kbps；连接数少 |
| 802.15.4 / Thread | **border router + gateway** | 传感器网 | iroh 不原生跑在 802.15.4 上；OpenThread 边界路由器转 IP |
| LoRaWAN | **gateway + store-and-forward** | 远距离低功耗 | 不适合交互式/大流量；延迟分钟级 |
| CAN / RS485 / Modbus | **gateway** | 工业 | 网关做协议转换 + ACL |
| Tor / Nym | iroh 原生 transport | 隐私 | 延迟/带宽差，不适合数据面主力 |

实现上抽象成 `LinkTransport`：

```rust
#[async_trait]
pub trait LinkTransport {
    fn mtu(&self) -> u16;
    fn max_connections(&self) -> usize;
    fn power_profile(&self) -> PowerProfile; // AlwaysOn / DutyCycled / Sleepy
    fn reliability(&self) -> Reliability;    // Reliable / BestEffort
    async fn send(&self, peer: LinkPeer, packet: Bytes) -> Result<()>;
    async fn recv(&self) -> Result<(LinkPeer, Bytes)>;
}
```

> 这里要区分两层“协议”：**overlay payload** 是 IPv4/IPv6（内含 TCP/UDP/ICMP）；**underlay link** 是 UDP/IP、BLE、Tor 等。iroh 不承载 Ethernet/ARP；如果要 L2（广播/组播/ARP），那是另一个数据面（ZeroTier/VpnCloud 之类），不要硬塞进 iroh。

路由 metric 可以带 **energy cost / duty cycle**，让 `SetLinkCost` 能把电池节点标成“避免 transit”。这比“所有链路都当同质 IP”更符合低功耗 mesh。

### 13.5 安全边界与前向安全

**前向安全（FS）结论：**

- iroh 只启用 **TLS 1.3**（`iroh/src/tls/verifier.rs` 里 `PROTOCOL_VERSIONS = [TLS13]`）。
- 完整握手使用 TLS 1.3 的 (EC)DHE（X25519），会话密钥是临时的；静态 Ed25519 只做身份认证，不直接当会话密钥。
- 会话复用：rustls 的 TLS 1.3 客户端只提供 `psk_dhe: true`（没有纯 PSK），所以 **resumption 仍然有 FS**。
- 如果自定义 crypto provider，必须保留 TLS 1.3 + (EC)DHE/PSK-DHE；不要退化成纯 PSK，否则 FS 不成立。
- **0-RTT 是例外**：iroh 的 TLS 配置启用了 early data，但只有应用显式调用 `into_0rtt()` 才会发 0-RTT；默认连接是 1-RTT。`iroh/src/endpoint/connection.rs` 明确写 `into_0rtt()` “at the cost of weakened security”“vulnerable to replay attacks”。VPN 数据面、路由变更、控制面都不要用 0-RTT；如果要用，只用于幂等的只读请求。
- 这是**经典前向安全**，不是后量子：X25519/Ed25519 面对“先存后解”的量子攻击不安全。需要 PQ 时，要等 rustls/iroh 的 hybrid X25519+ML-KEM 稳定（noq 已有 `__rustls-post-quantum-test` 之类实验 feature，但不要当生产保证）。
- **relay 看不到明文**：iroh 的端到端加密在 QUIC/TLS 层，relay 只转发密文；但 relay 能看到连接元数据（谁和谁、何时、流量大小）。
- **控制面 manifest 签名不是加密**：签名只保证真实性；传输机密性靠 QUIC/TLS；落盘的 manifest/审计日志不是 FS，需要静态加密。
- 调试用的 `SSLKEYLOGFILE`/keylog 会记录 pre-master key，等于破坏该会话的 FS；生产环境禁止开启。

**leaf 侧的特殊问题：**

- 如果 leaf 用 BLE/CoAP 到 gateway，**overlay 的 E2E 加密只到 gateway**；gateway 能看到 leaf 的明文。gateway 必须是信任边界。
- 如果 threat model 不信任 gateway，需要 leaf 跑轻量 E2E（DTLS 1.3/Noise）到远端 peer，gateway 只转发；这会把复杂度/功耗加回 leaf。
- BLE 配对/链路加密不一定有 FS；要单独确认。对高敏感数据，建议 leaf 侧至少做 DTLS 1.3/Noise，或只让 gateway 处理低敏感遥测。
- leaf 不能当 controller/relay；路由调节只能 local 或经 gateway 代理，避免被攻破的 leaf 影响全网。

### 13.6 对路由/控制面的影响

- leaf 的 `rib_mode=none`：只有默认路由/FIB，没有全局 RIB；`RouteQuery` 返回 501 或 `?proxy=true` 到 gateway。
- gateway 广告 leaf 前缀（`/32` 或聚合），controller/SPF 只看到 gateway 这个 next hop；不要为每个 leaf 建全网路由。
- `SetLinkCost` 支持 `energy` 维度；`Drain` 可以按“电池节点/低电量”触发。
- UI 拓扑分两层：core/gateway 的 overlay 图 + gateway 下的 leaf 列表；leaf 的 route query 由 gateway 代理。
- 规模：低功耗 mesh 可能 10k+ leaf，但 overlay 路由只到 gateway（几百到几千），不要让 leaf 数量进 SPF。

> 一句话：**iroh 能上 MCU，但低功耗 mesh 的正解是“gateway 代理 + leaf 轻协议”，不是“每个传感器跑 QUIC 全网状”。**

---

## 14. 参考

**本地代码**
- `/Users/wxk/Documents/Project/iroh`：`iroh/src/endpoint.rs`（connect/accept/datagram）、`endpoint/connection.rs`（paths/send_datagram）、`socket/remote_map/remote_state.rs`（PathSelector）、`socket/remote_map/remote_state/path_watcher.rs`（PathEvent/PathStats）、`endpoint.rs`（RelayMode）。
- `/Users/wxk/Documents/Project/Tunnet`：`crates/tunnet-core/src/routing.rs`（per-IP/LPM/exit）、`crates/tunnet-agent/src/system_routes.rs`（desired-state reconcile）、`crates/tunnet-agent/src/qos.rs`（Byte-DRR）、`crates/tunnet-agent/src/conflict.rs`（冲突检测）、`crates/tunnet-control/src/snapshot.rs`（快照）、`proto/tunnet/agent.proto`（snapshot/peer path）。
- `wireguard-go/tun/netstack`：用户态 TCP/IP 参考。
- `tailscale/net/netcheck`、`portmapper`、`derp`：NAT/relay 参考。
- `frp/pkg/nathole`：NAT 分类/打洞参考。

**外部**
- iroh：https://github.com/n0-computer/iroh ；NAT 穿透：https://docs.iroh.computer/concepts/nat-traversal
- iroh 兼容性（ESP32/RP2350/FreeRTOS）：https://docs.iroh.computer/compatibility
- iroh BLE transport：https://docs.iroh.computer/transports/bluetooth ；代码：https://github.com/mcginty/iroh-ble-transport
- ESP32 示例：https://github.com/n0-computer/iroh-esp32-examples ；智能风扇：https://github.com/n0-computer/iroh-smart-fan
- noq（QUIC/嵌入式）：https://docs.rs/noq
- iroh 安全与隐私：https://docs.iroh.computer/concepts/security-privacy
- 前向安全/0-RTT 代码：`iroh/src/tls/verifier.rs`、`iroh/src/tls.rs`、`iroh/src/endpoint/connection.rs`
- tun-rs：https://github.com/tun-rs/tun-rs
- openraft：https://github.com/databendlabs/openraft
- axum：https://github.com/tokio-rs/axum
- utoipa：https://github.com/juhaku/utoipa
- EasyTier：https://github.com/EasyTier/EasyTier
- ZeroTier controller：https://docs.zerotier.com/controller/
- Tunnet：https://github.com/tunnetio/Tunnet
