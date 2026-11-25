# IPAM 设计规划（控制面地址分配）

> 状态：**P1–P5 已实现，并完成 4 台真实主机验证**（2026-11-25）。
> DHCP 明确不做（§9）。
> 关联：[MEMBERSHIP-AUTH.md](MEMBERSHIP-AUTH.md)、[OPENRAFT-HA.md](OPENRAFT-HA.md)、
> [PROTOCOL.md](PROTOCOL.md)、[README.md](README.md)。

---

## 0. 目标与非目标

### 目标

1. controller 成为 overlay 地址的唯一权威：地址池、CIDR、保留地址、租约全部在
   Raft 状态机内，三副本强一致。
2. membership 与地址解耦：入网审批决定"能不能加入"，IPAM 决定"分到哪个地址"；
   改地址不需要重新入网。
3. 支持 IPv4 与 IPv6（overlay 主机地址 `/32`、`/128`），一个网络可配置多个池；
   Phase 1 的池必须落在 `network.cidr` 内（多网段需要 §16 的数据面扩展）。
4. 兼容现有静态配置：没配 IPAM 时行为完全不变。
5. 提供可运维的 CRUD 与租约查询/续租/释放 API，以及 metrics。
6. agent 支持 `ipam = "auto"`：从凭据拿到地址后自动配置 TUN，重启复用上次地址。

### 非目标（本阶段）

- **不考虑 DHCP**（overlay 成员与 LAN 主机都不做，理由见 §9）。
- 不做 NAT / 公网地址池 / 端口映射。
- 不做跨网络地址共享（地址池属于单个 network）。

---

## 1. 现状与缺口

| 现状 | 位置 | 问题 |
|---|---|---|
| `node.overlay_ip` 手工配置，启动时必须存在 | [config.rs](crates/stellaris-types/src/config.rs)、[dataplane.rs](crates/stellaris-agent/src/dataplane.rs#L206) | 无法自动分配；改地址要改配置重启 |
| agent 本地校验 overlay 属于 `network.cidr` | [config.rs](crates/stellaris-types/src/config.rs#L734) | controller 不校验 |
| controller enroll/approve 原样接受上报的 overlay | [controller.rs](crates/stellaris-agent/src/controller.rs) | 不校验 CIDR、不查重；两个节点可抢同一个 IP |
| 凭据携带 overlay_ip | [credential.rs](crates/stellaris-agent/src/credential.rs) | 已具备"下发地址"的通道，但 agent 不采用（仍用 config） |
| `network.cidr` 只有一个 | config | 多池/多网段需要扩展 |
| 地址变更 | `POST /v1/ipam/leases/{node}/reassign` | 进程内重配 TUN；旧地址隔离；见 [IPAM-RECONFIG.md](IPAM-RECONFIG.md) |

结论：**下发通道（凭据）已经存在，缺的是地址池/租约模型与 agent 采用地址。**

---

## 2. 术语

- **Pool（地址池）**：一个 CIDR + 可选范围/排除项，地址分配的单位。
- **Reservation（保留）**：管理员为某个 node 固定的地址，不过期、不参与自动分配。
- **Lease（租约）**：controller 分配给某个 node 的地址 + 有效期；续租延长。
- **Quarantine（隔离期）**：租约释放后一段时间内不复用该地址，避免旧节点还配着它。
- **Static overlay**：继续支持 `node.overlay_ip` 手写；不进入池时仅做校验/查重。

---

## 3. 数据模型

放在 `controller_model.rs`（确定性、只依赖命令字段，不读时钟）：

```rust
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct AddressPool {
    pub id: String,                 // 稳定 slug，例如 "overlay-v4"
    pub cidr: IpNet,                // 池所属网段
    /// 可分配区间（闭区间）；None 表示整个 CIDR 去掉网络/广播地址。
    pub range: Option<(IpAddr, IpAddr)>,
    /// 保留/排除的子网段（例如网关、VIP）。
    #[serde(default)]
    pub exclude: Vec<IpNet>,
    /// 租约时长（秒）；0 表示永不过期（不推荐）。
    #[serde(default = "default_lease_secs")]
    pub lease_secs: u64,
    /// 释放后隔离时长（秒），默认 60。
    #[serde(default = "default_quarantine_secs")]
    pub quarantine_secs: u64,
    /// 分配策略：v4 默认 LowestFree，v6 默认 HashProbe。
    #[serde(default)]
    pub strategy: AllocStrategy,
    /// 可选 AZ/站点亲和：节点 zone 匹配时优先从这个池分配。
    #[serde(default)]
    pub zone: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, Default)]
pub enum AllocStrategy {
    #[default]
    LowestFree,
    HashProbe,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Lease {
    pub node: NodeId,
    pub ip: IpAddr,
    pub pool: String,
    pub issued_at: u64,
    pub expires_at: u64,            // 0 = 保留地址，不过期
    pub reserved: bool,             // 管理员保留
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Reservation {
    pub node: NodeId,
    pub ip: IpAddr,
    pub pool: String,
    pub note: Option<String>,
}
```

ControllerModel 新增：

```rust
#[serde(default)] pub pools: BTreeMap<String, AddressPool>,
#[serde(default)] pub leases: BTreeMap<IpAddr, Lease>,      // ip -> lease
#[serde(default)] pub node_leases: BTreeMap<NodeId, IpAddr>,
#[serde(default)] pub reservations: BTreeMap<NodeId, Reservation>,
#[serde(default)] pub quarantine: BTreeMap<IpAddr, u64>,    // ip -> until
```

不变量（`apply` 内维护，单测覆盖）：

1. `leases` 的 key 唯一 ⇒ 一个 IP 只能有一个 lease；
2. `node_leases` 与 `leases` 双向一致；
3. `reservations` 的 IP 不得出现在 `leases` 里被别人占用；
4. `quarantine` 的 IP 不参与自动分配，直到时间到期（到期由命令清理）；
5. `snapshot_bytes()` 必须包含以上所有字段（保证三副本一致）。

---

## 4. Raft 命令

所有变更都走 `ControllerCommand`，leader 写入；`apply` 只依赖命令字段，保证确定性：

```rust
CreatePool { pool: AddressPool },
UpdatePool { pool: AddressPool },
DeletePool { id: String, force: bool, now: u64 },
ReserveAddress { reservation: Reservation, now: u64 },
ReleaseAddress { node: NodeId, now: u64 },
RenewLease { node: NodeId, now: u64 },
/// 审批时携带 leader 预分配的地址（见 §5 的分配时机）。
ApproveAdmission { node, member: MemberRecord },   // 复用现有命令
```

- **分配时机**：由 leader 先读当前 model，按算法算出 IP，再以
  `ApproveAdmission{member.overlay_ip: Some(ip)}` 或 `UpsertMember` 写入；`apply`
  再做一次唯一性断言，若冲突则记录 `last_ipam_error`（不 panic，避免副本分叉）。
  Raft 保证同一时刻只有一个 leader，因此不会有两个分配同时成功。
- **删除池**：有活跃 lease 时返回 409；`force=true` 时把该池所有 lease 释放并隔离。
- **过期回收**：leader 每 5s（沿用 LSA housekeeping 任务）提交
  `ExpireLeases { now }` 批量命令，把 `expires_at <= now` 的 lease 移到
  `quarantine`。不要依赖每个节点本地时钟删除。
- **保留地址**：`ReserveAddress` 直接写 `reservations` + 一条 `reserved=true` 的
  lease（`expires_at=0`），并从自动分配中排除。

---

## 5. 分配算法

### 5.1 LowestFree（IPv4 默认）

```text
for ip in pool.range (或 cidr 去掉网络/广播):
    skip if excluded
    skip if ip in leases
    skip if ip in reservations
    skip if ip in quarantine (未到期)
    return ip
```

- 确定性、可预测，适合小型网络；
- 池耗尽返回 `IpamError::Exhausted`；
- 需要池大小可控（建议单个 v4 池 ≤ /16，避免长时间扫描；可用 `next_hint` 游标优化）。

### 5.2 HashProbe（IPv6 默认）

IPv6 池通常是 /64，不能线性扫描：

```text
host_bits = 128 - cidr.prefix_len()
seed = blake3(network_id || pool.id || node_id)
start = u128::from(seed[..16]) % 2^host_bits
probe start, start+1, ... (最多 min(host_count, 1024) 次)
```

- 确定性、O(1) 记忆、天然分散；
- 冲突时线性探测；1024 次仍失败则视为耗尽；
- 若池显式给了 `range`，则在 range 内探测。

### 5.3 分配优先级

1. 已有 lease 且未过期 → 续租，返回原 IP（稳定优先）；
2. 有 reservation → 用保留地址；
3. 否则按策略分配。

---

## 6. 生命周期

```text
enroll(auto) ──► 待审(202) ──approve──► 分配 IP ──► 凭据(含 IP) ──► agent 配置 TUN
     │                                        │
     └──── 已预注册 ──────────────────────────┘
```

| 事件 | 行为 |
|---|---|
| 预注册成员（`members` 无 overlay） | controller 启动时按 node 排序、池内最低空闲依次分配；结果写入 model，快照一致 |
| 新节点 enroll + approve | leader 预分配 → `ApproveAdmission` → 凭据带 IP |
| 节点续签凭据 | `RenewLease` 延长 `expires_at`；IP 不变 |
| 租约过期 | leader 批量回收 → 进隔离期 → 节点下次 enroll 可能拿到新 IP |
| revoke | 释放 lease → 隔离 → tombstone（凭据同时失效） |
| 地址变更（管理员改池/保留） | 新 revision 凭据 → agent 重配 TUN；旧地址进隔离 |
| 池删除（force） | 所有 lease 释放并隔离 |
| controller 宕机 | agent 用缓存凭据里的 IP 继续工作（见 §8） |
| 池耗尽 | enroll/approve 返回 409/503 + `ipam_exhausted` 指标；agent 退避重试 |

**隔离期的作用**：撤销后旧节点可能还配着该 IP；凭据撤销已让 peer 拒绝它的流量，
但为避免"新节点复用同一 IP 与旧节点残留路由冲突"，释放后默认 60s 不复用。

---

## 7. HTTP API

鉴权沿用现有约定：管理端点要求 `x-stellaris-secret: <admin_secret>`；成员只能读自己的租约。

| 方法 | 路径 | 权限 | 说明 |
|---|---|---|---|
| GET | `/v1/ipam/pools` | member/admin | 列出池 + 使用量 |
| POST | `/v1/ipam/pools` | admin | 创建池（校验 CIDR、重叠、范围） |
| PATCH | `/v1/ipam/pools/{id}` | admin | 改范围/排除/租期（已分配地址不受影响） |
| DELETE | `/v1/ipam/pools/{id}?force=` | admin | 删除池；有活跃 lease 默认 409 |
| GET | `/v1/ipam/leases` | admin | 全部租约（可按 pool/node 过滤） |
| GET | `/v1/ipam/leases/{node}` | member(自己)/admin | 单个租约 |
| POST | `/v1/ipam/leases/{node}/renew` | member(自己)/admin | 续租 |
| POST | `/v1/ipam/leases/{node}/release` | admin | 立即释放 + 隔离 |
| POST | `/v1/ipam/reservations` | admin | 给节点保留固定地址 |
| DELETE | `/v1/ipam/reservations/{node}` | admin | 取消保留 |
| POST | `/v1/ipam/allocate` | admin | 立即给某节点分配（用于预注册后补地址） |

请求/响应示例：

```json
POST /v1/ipam/pools
{
  "id": "overlay-v4",
  "cidr": "10.7.0.0/16",
  "range": ["10.7.0.10", "10.7.0.250"],
  "exclude": ["10.7.0.1/32"],
  "lease_secs": 3600,
  "quarantine_secs": 60,
  "strategy": "lowest_free"
}
→ 201 {"pool": {...}, "size": 241, "allocated": 0}
```

错误码：

- `400` CIDR/range 非法、范围不在 CIDR 内、排除项越界；
- `409` 池 ID 重复、池有活跃 lease、IP 被占用、地址不在池内；
- `503` 无 leader / Raft 写失败；
- `507`（或 409 + code）池耗尽。

---

## 8. Agent 侧自动地址

### 8.1 配置

```toml
[node]
name = "a"
# overlay_ip 省略，或继续手写（静态优先）
ipam = "auto"          # 新增；默认 "static"
```

校验：

- `ipam = "auto"` 必须配 `network.auth.mode = "controller"`（地址必须由 controller 签发，
  否则无法防抢注）；
- `ipam = "auto"` 与 `node.overlay_ip` 同时存在 → 报错（避免歧义）；
- controller 侧若没有任何池，`auto` 节点 enroll 返回明确错误。

### 8.2 启动顺序（需要小重构）

当前 [dataplane.rs](crates/stellaris-agent/src/dataplane.rs#L206) 在启动时强依赖
`config.node.overlay_ip` 创建 TUN。改成：

1. 从 `state_dir/credential.json` 读取缓存凭据；
2. 若有有效凭据 → 用凭据里的 `overlay_ip` 启动 TUN；
3. 若没有 → 先启动 control client，等待首次凭据（超时 30s 后告警，持续重试）；
4. 拿到凭据后：
   - 若 TUN 未创建 → 用新地址创建；
   - 若已用缓存地址创建但地址变了 → `ip addr replace`（Linux）/`ifconfig`（macOS），
     并 flush 该接口的路由缓存；
5. `node.overlay_ip` 在内存中改为 `RwLock<Option<IpAddr>>`，提供 `local_overlay()`，
   替换 dataplane/link_state 里对 config 的读取。

> 备选（更省事但体验差）：先要求运维在池里预留地址并写进配置，只做 controller 侧
> IPAM + 校验；这可以作为 Phase 1，自动采用留到 Phase 2。

### 8.3 持久化与重启

- 凭据已落盘 `credential.json`，其中含 `overlay_ip` 和 `not_after`；
- agent 重启后先用缓存地址启动数据面，再后台续签；
- controller 不可达时保持缓存地址直到凭据过期；过期后数据面继续用旧地址但 peer
  会拒绝其凭据（fail-closed），需要 controller 恢复后续签。

### 8.4 地址变更（已实现）

`POST /v1/ipam/leases/{node}/reassign`（admin）可显式指定新 IP，或从池中自动选
（排除旧地址）。controller 在一个 Raft 命令里释放旧租约（旧地址按 quarantine 隔离）、
分配新租约、更新 member overlay 并 bump revision；agent 收到新凭据后调用
`DataplaneHandle::reconfigure` 在进程内 flush/add TUN 地址，LSA 下一次 tick 发布新地址。
详见 [IPAM-RECONFIG.md](IPAM-RECONFIG.md)。

限制：Linux 的 `ip` 路径；切换瞬间在途 TCP 会断；静态 `overlay_ip` 不参与。

---

## 9. 为什么不实现 DHCP（明确排除）

overlay 成员的地址由 controller 分配并随凭据下发，DHCP 在这个模型里没有位置：

- 成员是 L3 overlay 端点，没有链路层广播域；DHCP 的发现/租约协商没有对象。
- DHCP 本身不认证；凭据是签名能力。引入 DHCP 会多出一个未认证的地址权威源，
  与"只有 controller 能分配地址"冲突。
- 地址必须进 Raft、可审计、与 node key 绑定，DHCP 报文不适合做权威源。
- 续租、过期、撤销已经由 lease + 凭据 revision 覆盖，不需要 DHCP lease 语义。

因此本项目**不实现 DHCPv4/DHCPv6 服务器或客户端**，也不会提供"给节点身后 LAN
主机分配地址"的 DHCP 功能。若某个部署确实需要为下游主机发地址，请在该节点上
独立运行 dnsmasq/Kea 等 DHCP 服务，与 Stellaris overlay IPAM 无关。

> 如果"DHCP"指的是"由控制面动态下发 overlay 地址"，那就是本文的 IPAM；
> 它已经覆盖这个需求，不需要 DHCP 协议。

---

## 10. 迁移与兼容

- 没有池、没有 `ipam = "auto"`：行为与现在完全一致；`node.overlay_ip` 仍是必填。
- 有池但节点仍写静态 `overlay_ip`：controller 校验"在池内且未被占用"，否则拒绝 enroll。
- 配置升级：
  - `network.cidr` 保留（用于 TUN 掩码/on-link 过滤/NAT 源网段）；Phase 1 要求所有池
    都在它内部。跨网段（多个 CIDR）需要 §16 的数据面改动，不能只靠 IPAM；
  - 新增 `control.ipam.enabled`（默认 false）避免误启用；
  - 新增 `node.ipam = "auto" | "static"`。
- 旧 controller / 旧 agent 混跑：`ipam` 字段 `#[serde(default)]`，旧端忽略；但
  auto 节点连旧 controller 会拿不到地址 → 明确报配置错误，不要静默回退。

---

## 11. 失败模式与可观测性

| 失败 | 检测 | 行为 |
|---|---|---|
| 池耗尽 | `allocated == size` | enroll/approve 409 `ipam_exhausted`；agent 退避重试并告警 |
| 两节点同 IP | `leases` 唯一索引 | 第二个分配失败，不覆盖 |
| 池与静态地址冲突 | enroll 校验 | 拒绝并提示具体 IP |
| controller 不可达 | agent 重试 | 用缓存凭据地址；过期后 fail-closed |
| 租约时钟漂移 | 过期批量命令 | 以 controller 时间为准 |
| 删除池时有活跃租约 | 409 | 需 `force=true` 并显式确认 |
| 池重叠 | 创建时校验 | 默认拒绝；`allow_overlap=true` 留给实验 |

Metrics（controller `/metrics` 已有 Prometheus 风格）：

```text
stellaris_ipam_pool_size{pool="overlay-v4"}        241
stellaris_ipam_allocated{pool="overlay-v4"}         37
stellaris_ipam_free{pool="overlay-v4"}             204
stellaris_ipam_leases_expiring_total                2
stellaris_ipam_alloc_failures_total{reason="exhausted"} 0
stellaris_ipam_quarantined                         1
```

审计日志：分配/释放/保留/删除池都写 `stellaris_audit`（operator、node、ip、pool、原因）。

---

## 12. 安全

- 地址只能由 controller 签发；agent 不能自选（`ipam=auto` 时忽略本地值）。
- 地址与 node key 绑定在凭据里，peer 验证；冒用地址需要 controller 签发凭据。
- 管理 API 必须 admin secret；成员只能读自己的 lease。
- 池/租约进 Raft，防单副本篡改；快照签名覆盖。
- 隔离期防止地址复用与残留路由冲突。
- 注意 DoS：大量 enroll 可耗尽池；需要限流/审批默认开启。
- 不要给未认证节点分配地址：enroll 仍需签名 + 审批（或预注册）。

---

## 13. 测试计划

### 单元（controller_model）

- 池创建/重叠/范围/排除校验；
- LowestFree 分配顺序、跳过保留/隔离、耗尽；
- HashProbe 确定性与冲突探测；
- 租约过期批量回收、隔离到期；
- revoke 释放 + 隔离；
- 三副本 `snapshot_bytes()` 一致；
- 分配/释放/保留的幂等性。

### controller API

- CRUD 鉴权（member vs admin）；
- 预注册无 overlay 的自动分配；
- approve 分配 + 凭据带 IP；
- 重复 IP / 池外地址拒绝；
- 删除有活跃 lease 的池 → 409，force 后释放；
- 池耗尽错误码。

### agent

- `ipam = "auto"` 无 `overlay_ip` 启动 → 等凭据 → TUN 配好；
- 重启复用 `credential.json` 地址；
- 凭据续签/地址变更 → TUN 重配 + LSA 新地址；
- controller 不可达时保持旧地址；
- 非 controller 模式配 auto → 配置报错。

### 主机/网络（本地 + 深圳/乌兰察布）

- 本机 loopback：controller + 2 agent，自动分配 + 凭据 + 握手（无 TUN）；
- Linux netns：2–4 个 netns，一个池，自动地址，mesh ping；
- 4 台真实主机（深圳 2 + 乌兰察布 2）：一个 controller + 3–4 个成员，
  自动分配、mesh/链式、撤销后地址隔离、controller 重启后 agent 保持地址；
- 池耗尽/扩容场景。

---

## 14. 分阶段实施

| 阶段 | 内容 | 产出 | 估算 |
|---|---|---|---|
| P1 ✅ | model + 命令 + 确定性算法 + 单测 | `controller_model` 扩展、池/租约/隔离 | 1.5 天 |
| P2 ✅ | API CRUD + 预注册/审批分配 + controller 校验（CIDR/唯一） | `/v1/ipam/*`、enroll/approve 集成 | 1.5 天 |
| P3 ✅ | agent `ipam=auto` + 缓存凭据地址 + TUN 延迟配置 | dataplane 重构、状态机 | 2 天 |
| P4 ✅ | 文档、示例、状态字段 | 运维可见性 | 0.5 天 |
| P5 ✅ | 本地 + 4 主机实测 | TEST-RESULTS | 1 天 |

总计 P1–P5 约 **6.5 天**；可与 static 模式并行（互不依赖）。实现中还修复了 auto 节点的 LSA
使用旧配置地址的问题（此前 LSA overlay 为空，controller 拒绝、peer 无法发现）。

---

## 15. 代码改动清单（实施时按此拆 PR）

| 文件 | 改动 |
|---|---|
| `crates/stellaris-types/src/config.rs` | 新增 `node.ipam`（static/auto）、`control.ipam`（enabled/默认池/租期）；校验 auto 必须 controller 模式、不得与 `node.overlay_ip` 同时出现 |
| `crates/stellaris-agent/src/controller_model.rs` | `AddressPool`/`Lease`/`Reservation`；`pools`/`leases`/`node_leases`/`reservations`/`quarantine` 字段；`CreatePool`/`UpdatePool`/`DeletePool`/`ReserveAddress`/`ReleaseAddress`/`RenewLease`/`ExpireLeases` 命令；`apply` 分配算法；`snapshot_bytes` 覆盖新字段；单测 |
| `crates/stellaris-agent/src/controller.rs` | `/v1/ipam/*` 路由与 handler；enroll/approve 集成（无 overlay 时分配）；housekeeping 任务提交 `ExpireLeases`；`/v1/model` 输出 pools/leases；admin 鉴权 |
| `crates/stellaris-agent/src/control_client.rs` | enroll 请求携带 `overlay_ip: None` + auto 标志；`install_credential` 时把 overlay 写入 `state.local_overlay`；续签失败/池耗尽日志与退避 |
| `crates/stellaris-agent/src/lib.rs` | `AgentState.local_overlay: Arc<RwLock<Option<IpAddr>>>`、`local_overlay()`/`set_local_overlay()`；启动时优先用缓存凭据 |
| `crates/stellaris-agent/src/dataplane.rs` | `local_ip()` 改为读 `state.local_overlay()`；TUN 创建延迟到有地址时；新增 `reconfigure_tun(ip)`（Linux `ip addr replace`，macOS `ifconfig`）；路由 reconciler 使用新 overlay |
| `crates/stellaris-agent/src/link_state.rs` / `wire.rs` | 自报 `overlay_ip` 从 `local_overlay()` 读取，地址变更后重新发布 LSA |
| `crates/stellaris-agent/src/api.rs` | `/v1/status` 增加 ipam/lease 信息；`/metrics` 增加 §11 的指标 |
| `crates/stellaris-agent/src/controller_raft.rs` | 无需改动（新命令走 serde 枚举；注意旧快照反序列化默认值） |
| `scripts/test-real-ipam.sh` | 4 主机：一个 controller + 3 成员自动分配、mesh ping、撤销后地址隔离、controller 重启 |
| 文档 | README 配置、MEMBERSHIP 交叉引用、PROTOCOL 的 enroll/lease 字段、TEST-RESULTS |

兼容性注意事项：

- `ControllerCommand` 新增变体会进入 `commands.jsonl` 重放；旧版本无法回放新命令，
  升级后不支持回滚到旧二进制（与现有命令的兼容策略一致）。
- 快照里新增字段全部 `#[serde(default)]`，旧 agent 忽略；但旧 agent 不认 auto，
  必须同时升级。
- `ApproveAdmission` 的 `member.overlay_ip` 仍是显式字段：自动分配由 leader 填好再写，
  避免在 `apply` 里做可能失败的分配。

## 16. 多地址、多网段与多 AZ

### 16.1 一个节点多个 IP？

核心模型是"一个节点一个 primary overlay 地址"，凭据里只有 `overlay_ip`。不建议
把多地址做成 first-class：

- 数据面、MeshHeader、LSA、anti-spoof 都以单个 `overlay_ip` 为主键；
- 真正的多地址需要同时改凭据、LSA、TUN 地址、源地址选择、路由和 anti-spoof，
  收益（VIP/anycast）可以用更轻的方式实现。

推荐做法：

- **额外地址/VIP** 用成员的 `prefixes` 表达（IPAM 可分配，也可静态 grant）；
  接收方向：LSA 宣告该前缀，路由指向该节点；发送方向：该节点本地把 VIP 配到
  接口/策略路由，凭据的 prefixes 允许它作为源地址。不需要改协议。
- **双栈** 用两个 network（一个 v4、一个 v6，进程支持多个 `--config`），
  而不是一个 network 里两个地址；这样凭据、网络隔离、TUN 都保持单地址假设。

### 16.2 一个 network 多个网段？

IPAM 的数据模型支持多个池（不同 CIDR），但**数据面目前只认一个 `network.cidr`**：

| 依赖点 | 现在 | 多网段需要 |
|---|---|---|
| TUN 掩码 | `network.cidr.prefix_len()` | 每个池一个 TUN 地址/掩码，或用 host route |
| on-link 过滤 | 路由 reconciler 排除 `network.cidr` 内的前缀 | 按"所有 overlay 池"判断 |
| NAT 源网段 | `network.cidr` | 多个源网段 |
| 配置校验 | overlay/peer 必须在 `network.cidr` 内 | 允许属于任一池 |

因此：

- **Phase 1**：多池可以，但都在同一个 `network.cidr` 内（例如 /16 里分多个 range）；
- **真正多网段**：扩展 `network.cidrs: Vec<IpNet>`（TUN 多地址、过滤、NAT、校验），
  与 IPAM 解耦，单独一个 PR；IPAM 的池可以指向不同 CIDR；
- **隔离优先用多 network**：不同 `network.id`、独立 controller/凭据/TUN，
  已经支持（进程可跑多个 config），比同网络多网段更安全清晰。

### 16.3 两个 AZ

推荐**一个 network 跨 AZ**，用现有 zone 机制，而不是两个 network：

- `node.zone` + `routing.cross_zone_penalty` / `prefer_same_zone` 已实现；
- LSA/SPF 自动跨 AZ 选路，ECMP 可用；controller 3 节点跨 AZ 已验证；
- IPAM 池可加 `zone` 字段：节点 enroll 时带 zone，分配优先同 zone 池，
  降低跨 AZ 地址带来的运维歧义（地址本身仍是虚拟的，不改变语义）；
- 不需要 BGP/OSPF：LSA 就是路由协议；AZ 只是路径代价与地址池亲和。

### 16.4 需要别的协议吗？

不需要：

| 需求 | 现有机制 |
|---|---|
| 成员地址下发 | controller API + 签名凭据（本文 IPAM） |
| 路由 | 签名 LSA 洪泛 + 本地 SPF |
| 认证 | controller 凭据 / static peers 白名单 |
| 租约/过期 | IPAM lease + 凭据 revision |
| 多 AZ | zone 标签 + 路径代价 |

只有这些场景会引入新协议，且都**不在当前范围**：接外部网络跑 BGP、给 LAN 主机
发地址跑 DHCP、二层扩展跑 VXLAN/EVPN。

## 17. 待定问题

1. 地址池是否允许 `0.0.0.0/0` 这类超大 v4 池？建议拒绝（> /16）或强制给 range。
2. 地址变更时是否保持旧地址一段时间双栈并存？当前实现是立即切换（旧地址 quarantine），
   不做双地址 grace；零中断需要双 grant/双地址，列入后续。
3. 预注册无 overlay 的分配顺序：按 node id 排序（确定性），是否要允许配置优先级？
4. 租约续期频率：跟凭据续签（TTL/3）还是独立心跳？建议跟凭据，减少 Raft 写。
5. 多网络场景：地址池按 network 隔离，还是允许共享池？建议按 network 隔离。
6. 隔离期默认值 60s 是否足够（取决于撤销传播 ≤10s + 重连间隔 2s）？可配置。
