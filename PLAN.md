# Stellaris Linking — Execution Plan

> 版本：v0.1（2026-11-22）
> 配套：`ARCHITECTURE.md`、`PROTOCOL.md`
> 目标：从 0 到可内测 MVP；按 2～3 人团队排期。

---

## 当前实现状态（2026-11-22）

- [x] Cargo workspace / 6 crates / fmt+clippy+test 绿。
- [x] `stellaris-types`：NodeId/NetworkId/RouteId、RouteEntry、Config。
- [x] `stellaris-fib`：LPM、admin distance/local_pref/metric、ECMP、pin。
- [x] `stellaris-routing`：Intent/RIB/FIB、static/pin/unpin/drain/reset、dry-run、持久化。
- [x] `stellaris-agent`：HTTP API、CLI、token 鉴权、identity 持久化。
- [x] iroh 1.5 静态 peer 传输：direct/relay 路径、RTT、datagram。
- [x] TUN dataplane（IPv4、TTL、anti-spoof、transit、自适应 MTU）；Docker 双容器 1000B ping 实测通过。
- [x] Subnet gateway（a→b→c，c 无 agent）：b 广告前缀，a 路由 via b，b 转发；Docker 实测 1000B ping 通过。
- [x] 非 overlay 前缀 OS route reconciler（watch 事件驱动 + 30s fallback）。
- [x] Web UI（peers/routes/add/pin/delete/explain）。
- [x] AZ 同 zone `local_pref` 加成（静态/controller 路由）+ zone 展示。
- [x] Linux NAT/MASQUERADE（subnet gateway，Docker 实测）。
- [x] controller：network-scope 静态路由 + epoch/member manifest + HMAC 签名 + ACK 持久化 + member 2s 同步；HTTP、iroh control protocol、多 controller active-active fanout。
- [x] controller-mediated link-state：member 上报 LSA，controller SPF 计算路由（手动集成测试通过）。
- [x] 分布式 LSA：iroh control stream 洪泛 + 本地 SPF + Ping/Pong 故障收敛 + LSA underlay 地址自动发现 peer（3 节点 demo/FAILOVER 通过）。
- [x] controller manifest 携带 underlay addrs，member 无静态 peer 自动发现/连接（demo 通过）。
- [x] 跨 AZ link penalty + 同 AZ local_pref + RTT 驱动的 LSA link metric（5s 刷新）+ LSA 30s TTL + 等代价 ECMP。
- [x] ACL（方向/五元组/peer/zone/优先级）与 QoS DSCP + token-bucket + egress 优先级队列/queue_depth；`GET/PUT /v1/policy`；`/v1/status` counters。
- [x] RoutePolicy engine（Accept/Deny/SetLocalPref/SetMetric/SetWeight），AZ region/zone 匹配 + 同区优先/跨区 failover 测试。
- [x] `/metrics` Prometheus counters/gauges；ACL deny 审计日志；ACL 每规则命中数。
- [x] QoS 字节速率整形 `rate_bps/burst_bytes`。
- [x] controller + 3 members 本机联调（ACK/snapshot/LSA）。
- [x] controller + 3 TUN 节点真实 Linux netns 联调：双向 0% loss、1000B。
- [x] 双 controller threshold 本机联调。
- [x] 数据面 source grant 强制（member/transit capability）。
- [x] 多网络进程级隔离 + overlay CIDR 校验 + 设计文档；不同 network id 同 PSK 拒绝。
- [x] UDP broadcast bootstrap discovery（定向广播 + PSK 认证），Linux netns 实测通过。
- [x] `transport.bind_ip`：TUN 场景绑定 underlay，避免 iroh underlay QUIC 走进 TUN。
- [x] 事件驱动 OS route reconciler（watch + 30s fallback）。
- [x] PSK 入网认证 + allowlist；controller Ed25519 snapshot 签名；controller 侧 member/prefix grant；一次性 join token；member 侧 LSA prefix grant 强制；signed membership manifest；真实 3 节点 TUN/LSA transit 通过。
- [x] manifest threshold/多 controller 聚合；join token 过期/撤销。
- [ ] ACL/QoS 审计日志、复杂整形。
- [ ] 完整 controller（openraft quorum/leader election）、mDNS/广播发现、ACL/QoS 复杂整形/队列配置、多网络、Windows、macOS NAT。

下一阶段：安全/成员认证 → 真实 3 节点验证 → bootstrap/discovery → 多网络 → openraft HA（见 PRIORITIES.md / OPENRAFT-HA.md）。

---

## 0. 团队与分工

| 角色 | 人数 | 负责 |
|---|---:|---|
| Rust / 数据面 | 1 | TUN、parser、FIB、ACL、QoS、NAT、性能 |
| Rust / 路由+控制面 | 1 | Intent/RIB/SPF、route adjust、manifest、controller、HA |
| 平台/API/UI | 1 | iroh 封装、API、CLI、React UI、打包、CI |
| QA/安全 | 0.5 | netns/混沌/规模测试、威胁模型、审计 |
| 产品/运维 | 0.5 | 范围、验收、部署、文档 |

> 1 人团队：只做 Linux + UDP/IP + 单网络 + 无 UI，时间 ×2。

---

## 1. 里程碑

| 阶段 | 周期 | 目标 | 验收 |
|---|---|---|---|
| **M0** | 2 周 | 基础工程 + 两节点 IP 隧道 | 两机互 ping；MTU/吞吐有数据；CI 绿 |
| **M1** | 6 周 | 数据面 + FIB + 静态路由 + RouteQuery | `route list/lookup/explain` 可用；3 节点 netns |
| **M2** | 6 周 | Intent/RIB + RouteAdjust + policy | add/pin/drain/rollback/dry-run；diff 正确 |
| **M3** | 8 周 | `none` link-state + 多网络 + ACL/QoS/exit | 10 节点无控制面；ACL/NAT 测试 |
| **M4** | 8 周 | `embedded` controller + manifest/epoch + ACK | 任意节点 promote；controller 故障回退 |
| **M5** | 8 周 | UI + 打包 + 指标 + 混沌 | 内测 demo；100 节点；安装包 |
| **生产** | 12～18 个月 | 1k 节点、HA、Windows、安全审计 | 生产准入 |

总计约 **38 周（9 个月）** 到 MVP；生产级另算。

### 1.1 关键依赖

```text
M0 ──► M1 ──► M2 ──► M3
              │       │
              └──► M4 ┴──► M5
```

- M2 的 Intent 模型必须先定，否则 M3/M4 返工。
- M4 的 manifest/epoch 依赖 M2 的 generation/事务。
- UI 可以在 M2 后并行，但不要早于 API schema 冻结。

---

## 2. Epic 与规模

| Epic | 内容 | 规模 | Owner | 依赖 | 退出标准 |
|---|---|---|---|---|---|
| E0 Foundation | workspace、types、proto、CI、配置 | M | 全员 | — | `cargo nextest`/clippy/deny 绿 |
| E1 Transport | iroh 封装、连接池、路径统计、relay | L | 平台 | E0 | 两节点 datagram 互通；path 事件可见 |
| E2 Dataplane | TUN、parser、MeshHeader、FIB、ACL、QoS、NAT | L | 数据面 | E0/E1 | 3 节点 ping/curl；ACL 生效 |
| E3 Routing | Intent/RIB、选择、SPF、policy、explain | L | 路由 | E0/E2 | route adjust + rollback |
| E4 Control | manifest、协议、controller、ACK、HA | L | 控制 | E2/E3 | promote/failover/drift |
| E5 API/CLI/UI | axum/OpenAPI、CLI、React | M | 平台 | E3/E4 | UI 可查/可调/可回滚 |
| E6 Quality | netns、混沌、规模、fuzz、bench | L | QA+全员 | 并行 | 1k 模拟；混沌通过 |
| E7 Ops | 打包、service、指标、诊断、文档 | M | 平台 | E5 | 一键安装/卸载 |

规模：S≈3～5 人日，M≈8～12，L≈15～25。

---

## 3. 第一 sprint（2 周，M0）

### 3.1 目标

- 工程骨架可编译、CI 可跑。
- iroh + tun-rs 两节点 IP 隧道跑通。
- 记录 MTU/吞吐/直连-relay 行为。
- 冻结 v1 范围与核心类型。

### 3.2 任务

| # | 任务 | Owner | 产出 |
|---|---|---|---|
| 0.1 | 初始化 workspace/crates/rust-toolchain | 平台 | `Cargo.toml`、空 crate、CI |
| 0.2 | `stellaris-types`：ID/RouteEntry/FibEntry/Config/Error | 路由 | 编译 + 单测 |
| 0.3 | `stellaris-proto`：Envelope/Hello/Snapshot 骨架 | 控制 | `build.rs` + prost |
| 0.4 | iroh endpoint + ALPN + connect/accept | 平台 | 两节点 echo |
| 0.5 | tun-rs TUN 创建 + 读写 | 数据面 | 本机 ping TUN |
| 0.6 | MeshHeader + IP 包封装/解封装 | 数据面 | 两节点 ping |
| 0.7 | 测量 `max_datagram_size`/MTU/吞吐 | 数据面 | 数据记录 |
| 0.8 | FIB LPM + 静态路由表 | 路由 | 单测 + `route list` |
| 0.9 | CLI `status`/`route list` | 平台 | 可读输出 |
| 0.10 | netns 集成测试骨架 | QA | `cargo nextest` 跑通 |
| 0.11 | README/ADR/开发文档 | 全员 | 可交接 |

### 3.3 验收

- [ ] `cargo fmt --check`、`clippy -D warnings`、`nextest`、`deny` 全绿。
- [ ] 两台 Linux 机器（或 netns）互 ping overlay IP。
- [ ] `stellaris route list` 显示静态路由。
- [ ] 记录 MTU、direct/relay、吞吐数据。
- [ ] 没有未处理的 `unwrap`（测试除外）；错误有上下文。
- [ ] README 能让新人跑起来。

### 3.4 两周节奏

| 天 | 内容 |
|---|---|
| D1-2 | 0.1/0.2/0.3；CI |
| D3-4 | 0.4/0.5；单机 TUN |
| D5 | 0.6；两节点 ping |
| D6-7 | 0.7/0.8；MTU/FIB |
| D8-9 | 0.9/0.10；CLI/netns |
| D10 | 0.11 + demo + retro |

---

## 4. M1～M5 任务分解

### M1（6 周）：数据面 + 静态路由 + 查询

- TUN 多队列/MTU/MSS clamp；IPv4/IPv6 解析。
- MeshHeader v1；anti-spoof 框架；ACL 框架。
- FIB v4/v6；ECMP 基础；FIB 原子替换。
- 静态路由 Intent；`route list/lookup/explain`（只读）。
- SQLite 持久化（intents/fib snapshot）。
- CLI `status/peer/route`。
- netns 3 节点测试；NAT 矩阵（基础）。

**验收**：3 节点互通；静态路由可查；重启恢复；`explain` 正确。

### M2（6 周）：路由调节

- Intent/RIB/FIB 四层完整；路由来源优先级。
- RoutePolicy；ECMP 权重；pin/drain/reset。
- `POST/PATCH/DELETE /v1/routes`；dry-run；if-match；idempotency。
- 事务/回滚/audit；generation。
- `explain` 候选/淘汰原因；diff。
- QoS Byte-DRR；基础限速。
- 单测/属性测试/集成测试。

**验收**：add/pin/drain/rollback 全部可回滚；dry-run 与实际一致；3 节点不中断。

### M3（8 周）：无控制面 + 多网络 + ACL/exit

- `none` 模式 link-state：LSA、SPF、ECMP、TTL/防环。
- 多网络：多 TUN、network_hash、隔离。
- ACL：规则编译/匹配/默认策略；anti-spoof 完整。
- exit node：forwarding + NAT（Linux/macOS）。
- 路由聚合/限额/dampening 基础。
- 10 节点 netns；故障注入（peer down/relay down）。

**验收**：10 节点无 controller 组网；ACL 拒绝/允许正确；exit 可访问公网。

### M4（8 周）：embedded + external 基础

- Manifest：成员/IPAM/ACL/epoch/generation/签名。
- 控制协议：Hello/Sync/Snapshot/Delta/RouteIntent/ACK/Heartbeat。
- Agent 状态机；controller task；角色 promote/demote。
- Controller 算路 + 下发；applied_status/drift。
- 单 controller + 冷备；epoch fencing；故障回退。
- `stellaris-controller` binary：external 单租户模式，复用同一 controller 库/协议。
- 测试：controller 宕机/迁移/脑裂/过期。

**验收**：任意节点 promote；external controller 可独立部署；controller 挂掉数据面继续；drift 可见；回滚可用。

### M5（8 周）：UI/打包/质量

- React UI：Overview/Topology/Routes/Explain/Peers/Diagnostics/Settings。
- OpenAPI client；SSE；RBAC。
- 打包：Linux systemd、macOS launchd；签名/公证（macOS）。
- 指标/日志/诊断包；`/healthz`/`/readyz`。
- 混沌：kill controller/relay、分区、时钟偏移、重复请求。
- 100 节点；1k 模拟；性能基准。
- 文档/安装/升级/回滚。

**验收**：内测 demo；安装/卸载干净；UI 可完成查询/调节/回滚；混沌通过。

---

## 5. 工程规范

### 5.1 仓库

```text
.github/workflows/ci.yml
Cargo.toml
rust-toolchain.toml
deny.toml
buf.yaml
justfile
README.md
ARCHITECTURE.md
PROTOCOL.md
PLAN.md
crates/...
apps/dashboard/...
```

### 5.2 分支/提交

- Trunk-based；短分支；PR 必须 1 review。
- Conventional Commits：`feat:`, `fix:`, `docs:`, `refactor:`, `test:`, `chore:`。
- 每个 PR 关联 issue；禁止直接 push main。

### 5.3 CI 门禁

```bash
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo nextest run
cargo deny check
cargo audit
buf lint
cargo run -p stellaris-api -- openapi >/dev/null  # schema 可生成
```

- 覆盖率报告（可选，目标 ≥70% 核心 crate）。
- 集成测试在 netns 中跑；CI 需要 `CAP_NET_ADMIN` 或 privileged runner。
- macOS/Windows 编译检查（M5 前只编译）。

### 5.4 Definition of Done

- 代码 + 单测/集成测试 + 文档。
- 错误处理/日志/指标。
- 无新增 clippy warning；无未追踪 TODO。
- 涉及外部输入（packet/proto/API）必须有边界检查/fuzz。
- 涉及内核路由/NAT 的变更必须有清理/回滚。
- PR 描述含“怎么测的”。

### 5.5 代码审查重点

- 热路径无锁/无分配；`Bytes` 复用。
- `unsafe` 仅限 TUN/FFI；必须有 `// SAFETY`。
- 错误不吞；网络错误有上下文。
- 路由变更必须事务/审计。
- 密钥/日志脱敏。

---

## 6. 测试矩阵

| 类型 | 工具 | 频率 |
|---|---|---|
| 单元 | `cargo nextest` | 每次 PR |
| 属性 | `proptest` | 每次 PR |
| 集成 | netns + veth + nftables | 每次 PR（核心） |
| 混沌 | 脚本/测试工具 | nightly |
| 规模 | 模拟 1k 节点 | weekly |
| 模糊 | `cargo fuzz` | nightly |
| 基准 | `criterion` | weekly |
| 跨平台 | macOS/Windows runners | PR 编译；发布冒烟 |

### 6.1 必测场景

- NAT：full cone / restricted / port-restricted / symmetric / CGNAT。
- relay：直连失败回退；relay 宕机重选。
- 路由：静态/pin/drain/rollback；ECMP 成员故障；policy deny。
- 控制面：controller 宕机/迁移/脑裂/过期；snapshot gap。
- 安全：spoof 源、未授权 route intent、重放、撤销节点。
- 平台：TUN 创建失败、权限不足、MTU 黑洞、DNS 冲突。

---

## 7. 风险与缓解

| 风险 | 概率 | 影响 | 缓解 |
|---|---|---|---|
| iroh API 变化/路径选择 unstable | 中 | 中 | 锁 1.5.x；封装；v1 只做偏好 |
| QUIC 性能不达标 | 中 | 高 | M0 基准；MTU/MSS；后续 WireGuard 可选 |
| NAT 穿透失败率高 | 中 | 高 | 自建 relay；NAT 矩阵；TCP/WS fallback 评估 |
| 路由收敛/抖动 | 中 | 高 | 1k 先行；聚合/dampening；混沌 |
| controller HA 复杂 | 中 | 中 | v1 单活+冷备；v2 openraft |
| 跨平台签名/驱动 | 高 | 中 | Linux 先行；macOS 单独 milestone |
| 安全审计 | 中 | 高 | 威胁模型；外部审计；fuzz |
| 范围膨胀 | 高 | 高 | 非目标清单；MVP 冻结 |

---

## 8. 决策日志（持续更新）

| 日期 | 决策 | 备注 |
|---|---|---|
| 2026-11-22 | 不用 Tunnet 作为底座 | MPL/AGPL、v0.9.1、路由模型太薄 |
| 2026-11-22 | iroh 1.5 + tun-rs | 传输/TUN 复用 |
| 2026-11-22 | Intent/RIB/FIB/Path 四层 | 查询/调节/回滚 |
| 2026-11-22 | 三态控制面 | none/embedded/external |
| 2026-11-22 | 0-RTT 禁用 | FS/重放 |
| 2026-11-22 | v1 Linux/macOS | Windows 第二阶段 |

---

## 9. 参考

- `ARCHITECTURE.md`：实现架构
- `PROTOCOL.md`：协议/API
- `stellaris-linking-routing-design.md`：路由细节/低功耗
- `stellaris-linking-architecture.md`：早期架构
- `virtual-network-survey-2026-11.md`：方案调研
