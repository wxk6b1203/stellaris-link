# stellaris-linking：控制面三态 + 每节点路由查询 + Rust 自研可行性

> 调研/设计时间：2026-11-22
> 前提：接受「特权建 TUN + 用户态数据面」或「预装驱动/助手」；不要求纯免 root。
> 目标：给你一个能落地的判断：**现成用什么、缺什么、自研现不现实、怎么排期**。
> 路由查询/调节的详细设计见：[stellaris-linking-routing-design.md](stellaris-linking-routing-design.md)。
> 最终实现架构/协议/计划见：[ARCHITECTURE.md](ARCHITECTURE.md)、[PROTOCOL.md](PROTOCOL.md)、[PLAN.md](PLAN.md)。

---

## 0. 直接结论

1. **你的新需求可以归结为一个明确产品形态**：  
   **控制面三态**（无控制面 / 某个节点兼任 controller / 独立控制面服务）  
   + **每节点可暴露路由查询 API**（RIB 可选、FIB 必需）  
   + **一套 OpenAPI 驱动的 UI**（不依赖厂商控制台）。

2. **形态上最接近的是 Tunnet**（Rust，v0.9.1，244 stars）：
   - Direct 模式：完全无控制面，iroh-docs CRDT + Mainline DHT；
   - Managed 模式：独立 control plane + management API + Dashboard；
   - 每节点 `tunnet route list`，支持 subnet/exit/HA gateway；
   - TUN + QUIC/iroh，MPL/Apache/AGPL 分组件许可。
   - **但**：非常年轻，控制面是独立服务，不是“任意节点可当 controller”；每节点路由查询主要走 CLI（Managed 侧有管理 REST，但不是统一的每节点查询 API）。

3. **成熟度更高、第二接近的是 EasyTier**（Rust，v2.7.1，约 1.5 万 stars）：
   - 真正无中心、OSPF 式链路状态、每节点 `easytier-cli route`、多实例、GUI/Web 控制台；
   - **但**：没有 controller 角色，核心 RPC 未见鉴权，规模/审计未验证，LGPL。

4. **ZeroTier 是“controller 角色”的最佳参考**：任意节点可当 controller，本地 JSON API，多网络，Central UI/API；但 C++、controller 非自由许可、无前向保密。

5. **从头用 Rust 构建是现实的，但边界要清楚**：
   - 复用 `iroh`（P2P QUIC + 打洞 + relay）、`tun-rs`（跨平台 TUN）、`axum/utoipa`（API/UI）、`openraft`（controller HA）；
   - 2～3 人：**4～6 个月做出可用 MVP，12～18 个月生产级**；
   - 1 人：只建议做垂直场景，不要做通用产品；
   - 不要自研 crypto、NAT 穿透、TUN 驱动、DHT/CRDT——这些都有现成的。

6. **推荐路径**：
   - 想最快验证：先跑 Tunnet Direct + Managed 各一套，读它的 agent/route/control 代码；
   - 想产品化且要完全掌控：**greenfield Rust**，用 `iroh + tun-rs`，按本文的三态控制面设计；
   - 想省时间但接受 LGPL：fork EasyTier，补 controller 角色 + 路由查询 HTTP API + UI；
   - 不建议 fork Nebula：它是 Go、静态路由、没有控制面/路由 API，改造成本高于收益。

---

## 1. 需求重新定义

| # | 需求 | 设计含义 | 难点 |
|---|---|---|---|
| 1 | 每节点暴露路由查询能力 | 本地 API：`/routes`、`/routes/lookup`、`/peers`、`/paths` | 统一 schema；RIB 可有可无；鉴权 |
| 2 | 路由表可以要或者不要 | **RIB 可选，FIB 必需**（见 1.1） | 不要把“没有 RIB”误解成“没有转发表” |
| 3 | 控制面可选 | `none / embedded / external` 三态 | 角色切换、快照、故障回退 |
| 4 | 控制面可以角色指定 | 任意节点可被提升为 controller，可降级/迁移 | 选举、签名、epoch fencing、脑裂 |
| 5 | UI 不太麻烦 | 一套 OpenAPI；本地 agent + controller 聚合；Web/Tauri | 不要让 UI 依赖某个平台 |
| 6 | 接受特权建接口 | TUN + 用户态数据面；安装一次 | macOS 签名/公证、Windows 驱动/服务 |
| 7 | 多网组网 | 多网络实例/多租户；路由隔离 | 网段冲突、策略隔离 |
| 8 | 安全 | 身份、加密、ACL、撤销、审计 | 控制面密钥、前向保密、重放 |
| 9 | 大规模 | 路由聚合、分层、lazy P2P、relay 集群 | O(N) 状态、收敛、中继带宽 |
| 10 | 智能路由 | 直连优先、relay 回退、延迟/丢包度量、ECMP/HA | 抖动/羊群效应 |

### 1.1 先纠正一个常见设计错误：RIB ≠ FIB

- **FIB（转发信息库）**：每个节点必须有，至少要有“默认路由/下一跳”，否则包无法转发。
- **RIB（路由信息库）**：可以有，也可以没有；它决定“是否在本节点做路由计算/保存全网拓扑”。

所以“路由表可以要或者不要”应实现为：

| `rib_mode` | 本节点有什么 | 路由查询怎么答 | 适用 |
|---|---|---|---|
| `full` | 链路状态库 + 计算的 RIB + FIB | 本地直接答，含路径/备选 | 无控制面 / 小中规模 |
| `cache` | controller 推送的 RIB 缓存 + FIB | 本地缓存答，带 generation/TTL | 控制面模式，节点想加速 |
| `none` | 只有 FIB（默认/聚合路由） | 返回 `501 rib_disabled`，或代理到 controller | 瘦节点/边缘设备 |

> 关键：`none` 只表示“不做全局 RIB”，不表示“不转发”。数据面永远有 FIB。

---

## 2. 三态控制面设计

### 2.1 三种模式

```text
control_mode = none | embedded | external
```

| 模式 | 控制面在哪 | 谁算路由 | 成员/配置来源 | UI |
|---|---|---|---|---|
| `none` | 没有 | 每个节点链路状态/路径向量 | 签名 manifest + gossip/CRDT | 每节点本地 UI（可选聚合） |
| `embedded` | 某个成员节点兼任 controller | controller 算，推 FIB；成员上报链路质量 | controller 签名快照 | controller 提供 UI/API |
| `external` | 独立服务（可多租户） | 同上 | Postgres + controller | 独立 Dashboard + API |

### 2.2 角色模型

```text
role = member | controller | relay
```

- `controller` 不是特殊二进制，而是 agent 的一个角色（同一进程/同一包）；可用 feature gate 关闭控制面代码，关闭时不监听控制端口。
- 任意节点可被提升：`stellarisctl promote <node-id> --network <id>`。
- controller 可以降级/迁移；旧 controller 的写操作被 **epoch fencing** 拒绝。
- `relay` 是可选角色：只转发，不参与路由计算；可独立部署。
- 控制面角色由 **签名配置** 指定，不靠“先到先得”。

### 2.3 网络清单（manifest）

controller 签名的唯一事实源：

```json
{
  "network_id": "n_...",
  "epoch": 7,
  "version": 42,
  "controllers": ["ed25519:..."],
  "members": [
    {"node_id": "ed25519:...", "ip": "10.7.0.5", "role": "member", "tags": ["prod"]}
  ],
  "routes": [
    {"prefix": "192.168.1.0/24", "via": "10.7.0.5", "metric": 10}
  ],
  "acl": [{"src": "tag:prod", "dst": "tag:db", "ports": ["tcp/5432"], "action": "allow"}],
  "ipam": {"cidr": "10.7.0.0/16"},
  "issued_at": "2026-11-22T00:00:00Z",
  "expires_at": "2026-11-23T00:00:00Z",
  "signature": "base64..."
}
```

- 成员缓存最后一份 manifest；controller 失联时继续用未过期配置，新加入/变更冻结。
- manifest 带 `epoch`，防止旧 controller 复活后覆盖新状态。
- 无控制面模式：manifest 由创建者签名，成员通过 invite/CRDT 逐步扩展；或每个成员本地维护、靠 gossip 合并。

### 2.4 故障与一致性

| 场景 | 行为 |
|---|---|
| controller 宕机 | 成员保留最后 manifest；P2P 数据面继续；新成员/路由变更暂停 |
| controller 迁移 | 新 controller epoch+1，成员拉新 manifest；旧 controller 写入被拒 |
| 脑裂 | 需要多数派（openraft）或人工 fence；宁可拒绝写入，不要双写 |
| 成员被撤销 | manifest 移除 + 撤销列表；旧节点即使知道地址也握手失败 |
| manifest 过期 | 进入只读/安全模式；不允许新 peer，但已建立连接可继续（可配置） |

---

## 3. 每节点路由查询 API

### 3.1 端点

本地 agent 暴露（Unix socket + 可选 TCP/overlay）：

```http
GET /v1/status
GET /v1/peers
GET /v1/routes?table=rib|fib&family=ipv4|ipv6
GET /v1/routes/lookup?dst=10.7.0.5
GET /v1/paths?dst=10.7.0.5
GET /v1/diagnostics
GET /v1/events            # SSE/WebSocket
```

### 3.2 响应示例

`GET /v1/status`：

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

`GET /v1/routes/lookup?dst=10.7.0.5`：

```json
{
  "dst": "10.7.0.5",
  "source": "local-rib",
  "generation": 42,
  "match": {
    "prefix": "10.7.0.0/16",
    "next_hop": "10.7.0.1",
    "iface": "stellaris0",
    "metric": 10,
    "path": ["ed25519:a", "ed25519:b", "ed25519:c"],
    "expires_at": "2026-11-22T00:10:00Z"
  },
  "alternatives": [
    {"next_hop": "10.7.0.9", "metric": 30, "path": ["ed25519:a", "ed25519:d"]}
  ]
}
```

`rib_mode = none` 时：

```json
{
  "error": "rib_disabled",
  "message": "this node has no RIB; query the controller or retry with ?proxy=true",
  "controller": "https://control.example.com"
}
```

### 3.3 设计要点

- **只读**：查询 API 不修改路由；修改走 controller/CLI。
- **本地 + overlay 同一套 schema**：本地走 Unix socket；overlay 走 mTLS 的 `RouteQuery` gRPC/HTTP，让其他节点/控制器能查询本节点的 RIB/FIB；默认关闭，按 ACL 限流。
- **鉴权**：本地 socket 用文件权限 + bearer；overlay 用 mTLS；禁止匿名公网暴露。
- **generation/ETag**：UI 可以长轮询/SSE，避免全量刷新。
- **source 字段**：`local-rib` / `cache` / `controller` / `static`，让 UI 能显示“这条路由从哪来、是否过期”。
- **path 字段**：返回节点 ID 路径，便于和拓扑图对齐；没有 RIB 时可返回空。
- **proxy=true**：瘦节点把查询代理给 controller；controller 不可达则返回 503。

### 3.4 UI 怎么不麻烦

1. 所有 API 用 `utoipa` 生成 OpenAPI；
2. 用 OpenAPI 生成 TypeScript client；
3. UI 只做三件事：拓扑图、路由表/查询、诊断；
4. UI 可以静态托管在 controller，也可以由本地 agent 托管单机视图；
5. 不要为每个平台写原生 UI；Tauri 包一层即可。

---

## 4. 传输/数据面：三条路线

### 4.1 路线 A（推荐 MVP）：QUIC + iroh

- `iroh` 1.5：按公钥拨号、QUIC、打洞、relay 回退；数据用 QUIC datagram 承载 IP 包。
- TUN 由 `tun-rs` 创建；MTU 以 **1280** 为上限，实际按 `max_datagram_size()` 调整（不要硬编码，详见路由设计 §6.3）。
- 加密/身份由 QUIC/TLS + iroh endpoint key 提供；不需要 WireGuard。
- 优点：NAT 穿透/relay/加密/多路复用都现成；MVP 最快。
- 缺点：QUIC 开销、TCP-over-QUIC 的拥塞交互、relay 带宽；不是 WireGuard 兼容。
- 适用：先把“控制面/路由/UI”跑通，性能后续再优化。

> 低功耗/多协议/前向安全：iroh 可跑 ESP32/RP2350、FreeRTOS；无 PSRAM 只能 LAN-direct；BLE transport 仍 experimental 且 AGPL；TLS 1.3 正常握手有 FS，0-RTT 例外。详见路由设计 §13。

### 4.2 路线 B（性能优先）：WireGuard + 自建 NAT 穿透

- `boringtun` 0.7（BSD-3）或内核 WireGuard；UDP 承载，性能更好。
- NAT 穿透要自己做 STUN/ICE/打洞/relay；可参考 `frp/pkg/nathole`、`tailscale/net/netcheck`/`portmapper`。
- 优点：标准、性能、生态；缺点：工作量大，relay/TURN 要自己运维。
- 注意：boringtun README 明确 master 在重构，建议锁 crates.io 0.7.1 并评估维护风险。

### 4.3 路线 C（混合）

- iroh 负责发现/信令/控制，WireGuard 负责数据面直连 UDP；relay 仍走 iroh/QUIC。
- 复杂点：如何把 iroh 打洞得到的 UDP 五元组交给 WireGuard；不建议 MVP 做。

> 建议：**先 A 后 B**。把传输抽象成 `PacketTransport` trait，UI/路由/控制面不依赖具体传输。

---

## 5. 路由协议

### 5.1 `none` 模式：链路状态或路径向量

- 每个节点周期性洪泛 `LinkState`：邻居、可达前缀、metric、sequence、TTL。
- 用 Dijkstra 算最短路径；路由聚合；split horizon；避免环路。
- 规模控制：分层（area/cluster）、只通告前缀不通告所有 peer、`lazy-p2p`、relay 只转发不参与计算。
- 可参考 EasyTier 的 `SyncRouteInfo`/OSPF 式设计（但不要直接抄代码，LGPL）。

### 5.2 `embedded/external` 模式：controller 算路

- 成员上报：邻居、链路 RTT/丢包、可达前缀、容量。
- controller 算路：最短路径/ECMP/HA gateway；生成 FIB 快照；签名下发。
- 成员只执行 FIB，可选缓存 RIB（`rib_mode=cache`）。
- 路由查询：本地缓存答，或代理 controller；UI 从 controller 拿全局视图。

### 5.3 智能路由

- 直连优先：iroh 直连成功则不走 relay；失败回退。
- 度量：RTT、丢包、relay 成本、带宽；带 hysteresis 防抖。
- 多路径：ECMP/HA gateway；按流哈希，避免乱序。
- 观测：每条路由记录 `source/generation/last_change/reason`，UI 可解释“为什么走这条”。

---

## 6. Rust 技术栈（2026-11 版本）

| 层 | crate/项目 | 版本 | 许可 | 用途/注意 |
|---|---|---|---|---|
| P2P/传输 | **iroh** | 1.5.0 | MIT/Apache-2.0 | 公钥拨号、QUIC、打洞、relay；首选 |
| QUIC | quinn | 0.11.12 | MIT/Apache-2.0 | 不用 iroh 时的底层 |
| TUN | **tun-rs** | 2.8.18 | Apache-2.0 | 跨平台 TUN/TAP、iOS/Android、WinTun、offload |
| 用户态栈 | smoltcp | 0.14.0 | 0BSD | 无 TUN/代理模式；后续再做 |
| 用户态栈 | netstack-smoltcp | 0.2.5 | MIT/Apache-2.0 | TUN 包 ↔ TCP 流；参考 |
| WireGuard | boringtun | 0.7.1 | BSD-3-Clause | 可选；维护低、README 说在重构 |
| Noise | snow | 0.10.0 | Apache-2.0/MIT | 需要 Noise 时 |
| controller HA | openraft | 0.10.1 | MIT/Apache-2.0 | 3 controller 选举/日志 |
| API | axum | 0.8.9 | MIT | HTTP/WebSocket |
| OpenAPI | utoipa | 6.0.0 | MIT/Apache-2.0 | 生成 schema/TS client |
| gRPC | tonic/prost | 最新 | MIT/Apache-2.0 | 需要 gRPC 时 |
| Linux 路由 | rtnetlink | 0.24.0 | MIT | 增删路由/地址 |
| Windows | wintun | 0.5.1 | MIT | WinTun DLL 绑定 |
| UI | Tauri / Leptos / SvelteKit | 稳定版 | MIT/Apache | Web/Tauri 二选一 |
| 观测 | tracing/opentelemetry/prometheus | 最新 | MIT/Apache | 日志/指标/追踪 |
| 参考 | tailscale-rs | 0.7.x | 见仓库 | WIP；NAT 穿透未完成，勿生产依赖 |
| 参考 | wren-ospf / wren-babel | 0.3.1 | GPL-2.0+ | 只读协议参考，勿链接进闭源产品 |
| 参考 | Tunnet | 0.9.1 | MPL/AGPL/Apache | 最贴近的 Rust 架构参考 |

> 版本会变；落地时锁 `Cargo.lock`，并做一次依赖审计（尤其 iroh/QUIC/TUN）。

---

## 7. 参考架构

```text
┌────────────────────────── agent ──────────────────────────┐
│  TUN (tun-rs)                                             │
│    │  IP packet                                          │
│    ▼                                                      │
│  packet pipeline ──► ACL ──► FIB lookup ──► transport     │
│    │                                   │        │         │
│    │                                   │        ├─ iroh/QUIC datagram
│    │                                   │        └─ relay fallback
│    ▼                                   ▼                  │
│  route query API (axum)            link metrics           │
│    │                                   │                  │
│  control client ◄──── manifest/snapshot ──── controller    │
│    │                                   │                  │
│  local UI (optional)                   │                  │
└────────────────────────────────────────┼──────────────────┘
                                         │
                    ┌────────────────────┴────────────────────┐
                    │ controller (embedded or external)        │
                    │  - membership/IPAM                       │
                    │  - route computation                     │
                    │  - signed manifest / snapshot            │
                    │  - UI/API (OpenAPI)                      │
                    │  - HA: openraft (optional)               │
                    └────────────────────┬────────────────────┘
                                         │
                                   relay (optional)
```

数据流（直连）：

```text
App → TUN → agent → FIB → iroh direct → peer agent → TUN → App
```

数据流（relay）：

```text
App → TUN → agent → FIB → iroh relay → peer agent → TUN → App
```

---

## 8. 里程碑（2～3 人）

| 阶段 | 时间 | 交付 | 验收 |
|---|---|---|---|
| M0 | 1～2 周 | iroh + tun-rs 两节点 IP 隧道 | 两机互 ping/curl |
| M1 | 4～6 周 | 身份、静态 peer、FIB、`/routes` API、CLI | 路由查询/直连可用 |
| M2 | 8～12 周 | Direct 模式（manifest/gossip/CRDT）、NAT/relay、多网络、基础 ACL | 无控制面 3 节点组网 |
| M3 | 12～16 周 | embedded controller、路由计算/下发、角色提升/迁移、external 模式 | 任意节点当 controller，故障回退 |
| M4 | 16～24 周 | UI（拓扑/路由/诊断）、Linux/macOS/Windows 打包、自动更新、指标 | 可演示/内测 |
| 生产 | 12～18 个月 | 安全审计、1000+ 节点、relay 运维、HA、文档 | 生产 SLA |

> 如果只做 1～2 个平台、只做 Direct 模式，M0～M2 可以压缩到 2～3 个月；但“生产级”仍建议按 12 个月估算。

### 8.1 团队

- 2 名 Rust 工程师（数据面/控制面）；
- 1 名网络工程师（NAT/路由/规模，兼职即可）；
- 1 名前端（OpenAPI/可视化，兼职）；
- 1 名 QA/运维（跨平台/relay/升级）。

### 8.2 最容易低估的工作

1. **NAT 矩阵**：对称 NAT、CGNAT、UDP 被封、双栈；relay 兜底和超时。
2. **跨平台**：macOS 签名/公证/Network Extension、Windows 服务/WinTun、Linux systemd/capabilities。
3. **路由收敛**：1000 节点、频繁抖动、分区恢复、路由环路。
4. **安全**：controller 密钥、manifest 撤销、重放、前向保密、审计。
5. **运维**：relay 带宽、controller HA、灰度升级、回滚、可观测性。

---

## 9. 自研 vs 复用：怎么选

| 路线 | 时间 | 优点 | 风险 |
|---|---|---|---|
| **Greenfield Rust**（iroh + tun-rs） | MVP 4～6 个月 | 完全贴合三态控制面/路由 API/UI；许可干净；可产品化 | 需要自己写控制面/路由/跨平台；iroh 版本风险 |
| **Tunnet（只参考，不 fork）** | 1～2 周读代码/跑 POC | 验证 Direct/Managed 架构、路由 CLI、Dashboard 行为 | v0.9.1/244 stars；路由模型只有 per-IP/LPM/exit；MPL/AGPL；不适合做产品底座 |
| **Fork EasyTier** | 加 controller/API/UI 约 3～6 个月 | 无中心 + OSPF 自动路由 + 多实例，成熟度更高 | LGPL；RPC 无鉴权；规模/审计未验证；无 controller 角色 |
| **用 ZeroTier/NetBird** | 1～2 周 | 现成、成熟 | 不是 Rust；controller 许可 / 中心强制；无法完全按你的控制面模型改 |

### 9.1 推荐

- **如果“控制面三态 + 每节点路由查询 API + UI”是产品核心**：  
  **Greenfield Rust**，用 `iroh + tun-rs + axum/utoipa`，Tunnet 作为参考实现；先做 `none` + `embedded` 两态，`external` 后置。
- **如果要最快看到可运行系统**：  
  先跑 **Tunnet Direct**（无控制面）和 **Tunnet Managed**（控制面+UI），把它当**行为参考/测试 oracle**；不要把 fork 作为产品路线——许可、成熟度、路由模型（只有 per-IP/LPM/exit，没有 metric/policy）都不满足你的 route adjustment 需求。
- **如果“无中心 + 自动路由”比“controller 角色”更重要**：  
  fork **EasyTier**，补 HTTP 路由查询 API + 可选 controller + UI；LGPL 合规先找法务。
- **如果只是要一个能用的企业 overlay**：  
  ZeroTier（controller 许可）或 NetBird/Tailscale；不要自研。

---

## 10. 结论：现实吗？

**现实，但“从头”要限定为“新写产品代码”，不是新写协议栈。**

- 复用：iroh（P2P/打洞/relay）、tun-rs（TUN）、axum/utoipa（API）、openraft（HA）、smoltcp（后续无 TUN）。
- 自写：三态控制面、角色/epoch/manifest、路由查询 API、路由计算/聚合、UI、跨平台打包。
- 2～3 人 4～6 个月可做出可用 MVP；12～18 个月生产级；1 人只做垂直场景。
- 最大风险不是“写不出来”，而是 NAT/跨平台/路由收敛/安全/运维这五件事的长期投入。

**一句话**：  
**Tunnet 证明了这个架构在 Rust 里可行；EasyTier 证明了无中心自动路由可行；ZeroTier 证明了 controller 角色可行。把它们三者合起来，就是你要做的东西——市面上还没有一款同时做到。**

---

## 11. 参考

**最贴近的 Rust 项目**
- Tunnet：https://github.com/tunnetio/Tunnet
- Tunnet 文档：https://docs.tunnet.io/
- Direct 模式：https://docs.tunnet.io/modes/direct/
- Managed 模式：https://docs.tunnet.io/modes/managed/
- `tunnet route`：https://docs.tunnet.io/cli/route.html
- 自托管：https://docs.tunnet.io/self-hosting/

**Rust 组件**
- iroh：https://github.com/n0-computer/iroh ；NAT 穿透：https://docs.iroh.computer/concepts/nat-traversal
- tun-rs：https://github.com/tun-rs/tun-rs
- smoltcp：https://github.com/smoltcp-rs/smoltcp
- boringtun：https://github.com/cloudflare/boringtun
- tailscale-rs：https://github.com/tailscale/tailscale-rs
- openraft：https://github.com/databendlabs/openraft
- axum：https://github.com/tokio-rs/axum
- utoipa：https://github.com/juhaku/utoipa
- wren-ospf / wren-babel：https://docs.rs/wren-ospf

**架构/模型参考**
- ZeroTier controller：https://docs.zerotier.com/controller/
- EasyTier 去中心/路由：https://easytier.cn/guide/network/decentralized-networking.html
- Tailscale userspace/tsnet：https://tailscale.com/docs/concepts/userspace-networking
- NetBird Management/Signal/Relay：https://docs.netbird.io/about-netbird/how-netbird-works

**本地参考仓库**
- `wireguard-go/tun/netstack`：用户态 TCP/IP + TUN 的 Go 参考
- `tailscale/tsnet`、`tailscale/wgengine/netstack`、`tailscale/net/netcheck`、`portmapper`、`derp`
- `frp/pkg/nathole`：NAT 分类/打洞
- `cloudflared/carrier`：QUIC/WS 隧道
- `ZeroTierOne/node/Bond.hpp`、`Topology.hpp`：多路径/拓扑
- `ZeroTierOne/service/OneService.cpp`：本地 JSON API 形状
