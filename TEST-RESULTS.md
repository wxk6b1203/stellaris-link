# 真实环境测试记录（2026-11-23 ~ 11-24）

> 关联：[GAPS.md](GAPS.md)、[README.md](README.md)、[PLAN.md](PLAN.md)

本文记录实际执行过的测试、原始结果和结论边界。未执行的测试不写成通过。

---

## 1. 环境

| 批次 | 主机 | 用途 |
|---|---|---|
| 深圳批1 | 120.77.233.189 / 47.107.226.187 / 120.79.121.159 | controller HA、IPv4/IPv6 overlay |
| 深圳批2 | 47.119.37.129 / 47.119.37.217 / 47.119.37.223 | 双网卡 multipath/failover、公网 direct/relay |
| 上海 | 8.153.183.185 | 跨地域 overlay/controller |
| 成都 | 47.109.58.88 | netns PMTUD 路由实验 |
| 临时批（11-24 12:43–14:00） | 成都 47.108.95.243 / 深圳 47.107.226.187 / 上海 8.153.179.142 | TOML 三地滚动重启、WAN 丢包/时延、>4MiB snapshot |

---

## 2. 单元/集成

```text
cargo fmt --check                          ✅
cargo clippy --workspace --all-targets -- -D warnings  ✅
cargo test --workspace                     167 passed
```

---

## 3. Controller HA

### 3.1 同 VPC 三主机 + mTLS

```text
physical leader=1
physical snapshot ok
physical new leader=3
physical failover snapshot ok
OK: physical 3-host controller HA + mTLS + failover works.
```

### 3.2 跨地域公网 quorum

深圳 120.77.233.189 + 深圳 47.119.37.129 + 上海 8.153.183.185，公网 TCP 5701/5801。

```text
cross-region leader=1
cross-region snapshot ok
cross-region new leader=2
cross-region failover snapshot ok
OK: cross-region controller quorum + mTLS + failover works.
```

### 3.3 磁盘满

tmpfs 64 MiB 作为 Raft 目录，先正常写入，再填满：

```text
初始 LSA: 200
fill: 64 MiB / 100% 
写入 LSA: HTTP 503
raft write failed: when Write Logs: No space left on device (os error 28)
```

结论：磁盘满时写入失败，返回 503，不 ACK。

修复前观察：LSA API 返回 `generation: 3`，但 `/v1/status` 返回 `generation: 1`；Raft 模式 status 仍使用 legacy 字段。

修复后复测：

```text
LSA:     generation 3
status:  generation 3
磁盘满写入 503 后 status 仍为 generation 3
```

`/v1/status` 现在从 `ControllerModel` 读取 generation/acks/routes。

### 3.4 撕裂 log

删除填充后，把 `raft-log.json` 截断到 100 字节并重启：

```text
Error: not allowed to initialize due to current raft state:
last_log_id: Some(... index: 3)
```

结论：log 与 state 不一致时启动失败，fatal error，不静默继续。

### 3.5 Snapshot 跨重启续传

已实现并验证：

```text
snapshot_transfer_survives_http_restart
```

行为：

- transfer 元数据和 data.bin 持久化到 `raft_dir/snapshot-transfers/<id>/`
- controller HTTP server 重启后加载未完成 transfer
- 使用同一个 transfer ID 从已接收 offset 继续发送剩余 chunk
- sender 重启后再次 begin 也能拿到同一 id/received
- finish 成功

仍有限制：

- agent 客户端进程重启后不会自动复用旧 transfer ID
- 仅验证 controller HTTP server 重启，不是整个 Raft 集群滚动重启
- TTL 从进程重启后重新计时

### 3.6 三地 controller 滚动重启：通过

环境：

- Shenzhen 120.77.233.189
- Shanghai 8.153.183.185
- Chengdu 47.109.58.88

公网端口 5701/5801 + mTLS。

关键修正（当时用环境变量，现已产品化，见 §3.7）：

```text
STELLARIS_RAFT_ELECTION_TIMEOUT_MS=1000
```

默认 150ms 选举超时对跨地域 vote RPC 太短，日志里出现：

```text
timeout after 150ms when Vote 3->2
```

把 election timeout 提到 1000ms 后：

```text
initial leader=1
snapshot members ok

restart follower 2:
  leader after follower 1=1
  snapshot members ok

restart follower 3:
  leader after follower 1=1
  snapshot members ok

restart leader 1:
  new leader=3
  snapshot members ok

OK: cross-region 3-controller rolling restart works.
```

结果：

- follower 逐个重启通过
- leader 最后重启通过
- 新 leader 选出
- 旧 leader 重启后重新加入
- 成员/snapshot 可读

限制：

- 选举超时当时用环境变量覆盖；同日已暴露为 TOML 配置并在三地复跑（见 §3.8）
- 本轮滚动重启没有制造大 snapshot 传输；snapshot transfer 重启续传仍是单独单测验证（§3.10 补 WAN 大 snapshot）

### 3.7 选举超时 TOML 配置：本机通过（2026-11-24）

背景：§3.6 的三地滚动重启依赖环境变量。现已产品化为
`control.raft_election_timeout_ms`，省略时使用跨地域默认值 1000ms
（max 2000ms、heartbeat 250ms），越界（`50..=60000` 之外）在配置加载阶段报错。

本机（macOS）三进程 Raft 实测：

```bash
./scripts/test-controller-raft-3node.sh
# leader=1
# raft timing ok: min=300ms max=600ms heartbeat=75ms source=config
# invalid timing rejected: control.raft_election_timeout_ms must be between 50 and 60000 ms (got 10)
# snapshot ok
# new leader=3
# failover snapshot ok
# crash recovery ok
# OK: 3-controller raft join/LSA/snapshot/failover/crash-recovery works.
```

不配置该项时的生效值（单进程 + Raft，读 `/v1/status`）：

```text
raft election timing election_timeout_min_ms=1000 election_timeout_max_ms=2000 heartbeat_interval_ms=250 source="default-cross-region"
"raft": {"election_timeout_min_ms":1000,"election_timeout_max_ms":2000,"heartbeat_interval_ms":250,"source":"default-cross-region"}
```

优先级实测：

| 配置 | 生效 min/max/heartbeat | source |
|---|---|---|
| 都不设 | 1000 / 2000 / 250 | `default-cross-region` |
| 只设 env=1200 | 1200 / 2400 / 300 | `env`（带废弃 warn） |
| TOML=300 + env=1200 | 300 / 600 / 75 | `config`（env 被忽略并 warn） |
| env 非法值 | 1000 / 2000 / 250 | `default-cross-region` |

本机三进程集群在跨地域默认值下同样通过换主/崩溃恢复：

```bash
ELECTION_MS=1000 ./scripts/test-controller-raft-3node.sh
# raft timing ok: min=1000ms max=2000ms heartbeat=250ms source=config
# new leader=3
# crash recovery ok
```

未配置该项的 mTLS 三进程集群（默认 1000ms）同样通过：

```bash
./scripts/test-controller-raft-tls-3node.sh
# tls leader=1
# tls snapshot ok
# OK: 3-controller raft TLS join/LSA/snapshot works.
```

真实三地用 TOML 复跑滚动重启见 §3.8；WAN 丢包/时延下的选举见 §3.9。

### 3.8 三地 TOML 滚动重启：通过（2026-11-24）

新一批临时主机（成都 / 深圳 / 上海，公网，端口 5701 raft + 5801 HTTP，mTLS），
二进制在成都 `cargo build --release` 后 scp 到三台（同 md5），脚本直接写
`raft_election_timeout_ms = 1000`，不再注入环境变量：

```bash
H1=root@47.108.95.243 H2=root@47.107.226.187 H3=root@8.153.179.142 \
BIN=/opt/stellaris/stellaris-controller ./scripts/test-real-rolling-restart-ha.sh
```

```text
initial leader=1
raft timing ok: 1000ms source=config
snapshot members ok
--- restart follower 2 ---
leader after follower 1=1
snapshot members ok
--- restart follower 3 ---
leader after follower 1=1
snapshot members ok
--- restart leader 1 ---
new leader=3
snapshot members ok
OK: cross-region 3-controller rolling restart works.
```

说明：`status.raft.source=config` 证明生效值来自 TOML，而不是默认值或环境变量；
每台节点日志都有 `raft election timing ... source="config"`（脚本逐台断言）。

### 3.9 WAN 20% 丢包 + 50ms 单向时延下的选举：通过

用 `tc`（prio + u32 过滤）只对发往另外两台 controller 的流量注入
`delay 50ms loss 20%`，编排用的 SSH 不受影响。三地基线 RTT 36–38ms，
注入后 ping 采样 135.9ms（5 包样本偏大，只作量级参考）。

```bash
H1=... H2=... H3=... ./scripts/test-real-wan-loss-ha.sh
```

```text
[13:04:28] baseline ping: rtt avg 36.293ms / 38.233ms, 0% loss
[13:04:33] apply netem loss=20% delay=50ms (egress to peer controllers)
[13:04:49] initial leader=1 after 0.7s under loss
[13:04:50] raft timing: {'election_timeout_min_ms': 1000, 'election_timeout_max_ms': 2000, 'heartbeat_interval_ms': 250, 'source': 'config'}
[13:04:53] joined member and wrote lsa=1 on leader 1
[13:04:54] snapshot members ok on leader
[13:04:54] kill leader 1
[13:04:59] new leader=2 after 3.6s
[13:05:00] wrote lsa=2 on new leader
[13:05:02] failover snapshot ok
[13:05:02] OK: 3-region controller HA survives 20% loss + 50ms delay
```

同脚本复跑一次（验证入库版本）：`new leader=3 after 11.1s`。同样 20% 丢包下
换主耗时 3.6s vs 11.1s，说明会经历多轮选举，符合预期但没有稳定性统计。

边界：只验证了"单次 leader 故障 + 20% 丢包"；没有做长时间 soak，也没有在
丢包下测滚动重启和 >4MiB snapshot（见 §3.10）。

证据等级说明：本脚本最初只做日志输出、`OK` 无条件打印；2026-11-24 审计后已改为
`curl -fsS` + 逐项失败退出（`scripts/test-real-wan-loss-ha.sh`），但加固版没有在
主机释放前复跑。上面记录的是当时观察到的 leader 切换/LSA/snapshot 输出。

### 3.10 >4MiB snapshot 跨 WAN：通过（含中断续传）

做法：三 controller 正常起（TOML 1000ms），停掉 ctrl3，从 leader 本机并发写入
5100 条 LSA（每条 24 个 prefix，8 线程），写入耗时 331s（每条命令都重写整份
`raft-log.json`/`raft-state.json`，O(n²) 写放大）。leader 模型：

```text
leader raft-state.json bytes=5843090  (5.57 MiB)
leader generation=5102
```

然后把 leader→ctrl3 限速到 2mbit 再启动 ctrl3，观察分块传输（2MiB chunk）：

```text
[13:12:17] ctrl3 partial data.bin=2097152      # 正好一个 chunk
[13:12:18] kill ctrl3 mid-transfer (partial=2097152)
[13:12:20] partial on disk before restart=2097152
[13:12:24] partial after restart=2097152       # 重启后保留，没有从 0 开始
```

全速重跑后 ctrl3 追平：`ctrl3 generation=5102`，即 5.84MB 的 Raft snapshot 在
三地公网上通过分块路径完成传输和安装。

**中断后续传到完成：通过（复测）**。为拿到"续传完成"的证据，先写 300 条小
LSA 把状态推进到 generation 5402，再清空 ctrl3 并限速启动：

```text
[13:23:12] throttle leader->ctrl3, wipe ctrl3 raft dir, restart ctrl3
[13:23:27] partial=2097152
[13:23:28] killed mid-transfer, partial before restart=2097152
[13:23:30] partial after restart=2097152
[13:23:37] ctrl3 gen after resume=5102      # snapshot 安装完成（leader 5402）
后续日志复制：5182 -> 5245 -> 5296 -> 5350 -> 5402   # 追平 leader
```

收尾状态：`n3/raft/raft-state.json=5920027`、`raft-log.json=103038`（snapshot 后
已 purge）、`snapshot-transfers` 目录清空。

机制：`begin` 按 `total+checksum` 幂等，返回已收 `received`，sender 从该 offset
继续；上面的 2097152 字节（正好一个 2MiB chunk）在进程重启前后保持一致，随后
安装完成并继续追日志。

证据等级：本节是**手工编排**（5100 条 LSA 生成、netem 限速、中断/重启都是临时
命令），仓库里没有对应脚本，换环境不能一键复现；要固化成
`scripts/test-real-wan-snapshot-ha.sh` 才算回归证据。

仍未验证：

- 这次续传是在重启后**恢复链路**的情况下完成的；持续 2mbit 慢链路上 60s
  transfer TTL 是否够用，没有单独验证（对应 [FOLLOWUP.md](FOLLOWUP.md) 里
  "transfer TTL 与滚动重启窗口协调"）。
- 丢包/抖动叠加慢链路时的大 snapshot 没有测。

### 3.11 2026-11-24 晚审计修复验证（8 台临时主机）

成都 8.137.217.116/.51、深圳 47.112.117.96/.100.19、乌兰察布 8.161.224.235/.111、
上海 8.153.184.35/.228；公网互通，地域间 RTT 28–41 ms；`.116` 编译 release 后
md5 `9306484038210dce706ec406a41a71eb` 分发到其余 7 台。

| 验证 | 脚本 | 结果 |
|---|---|---|
| Raft 路由复制（三副本同 RouteId） | `scripts/test-controller-state-ha.sh` | ✅ |
| admin secret 分离（member secret 写路由 401） | 同上 | ✅ |
| 未签名 join 403 / agent 签名 join 复制到三副本 | 同上 | ✅ |
| 复制 LSA TTL（2s）到期后三副本同时移除 | 同上 | ✅ |
| 换主后 epoch 单调 | 同上 | ✅ |
| iroh 入口走 Raft（follower 不落本地、leader 复制三副本） | `scripts/test-real-iroh-raft.sh` | ✅ |
| OS 路由安全（默认路由 opt-in、外部路由不覆盖、proto 240、显式替换） | `scripts/test-netns-route-safety.sh` | ✅ |
| netns 3-node controller（含 transit 授权，ping/status 有断言） | `scripts/test-linux-netns-3node-controller.sh` | ✅ |
| netns IPv6（含 transit 授权） | `scripts/test-linux-netns-ipv6.sh` | ✅ |
| netns TUN / 3-node 分布式 LSA | `test-linux-netns-tun.sh` / `test-linux-netns-3node.sh` | ✅ |
| 分布式 LSA 签名链路 | `demo-distributed-linkstate.sh` | ✅ |
| TLS 集成 / 三进程 mTLS Raft | `test-tls.sh` / `test-controller-raft-tls-3node.sh` | ✅ |
| 本机三进程 Raft（含默认 1000ms 检查） | `test-controller-raft-3node.sh` | ✅ |
| 三地 TOML 滚动重启（新二进制） | `test-real-rolling-restart-ha.sh` | ✅ |
| 三地 20% 丢包 + 50ms（新二进制） | `test-real-wan-loss-ha.sh` | ✅ 换主 4.1s |
| 三地 >4MiB snapshot（重跑） | 临时编排 | ✅ 5.2 MiB 模型、2MiB 分块、中断后续传追平（generation 5103） |
| 动态 membership 3→4 voter + learner 转正 | `scripts/test-real-raft-membership.sh` | ✅；1 follower 宕机仍可写 |
| iroh 入口同步 >4MiB 模型 | `scripts/test-real-iroh-large-snapshot.sh` | ✅ 8 MiB 模型，member ACK |
| relay 故障重连（禁用 discovery 强制 relay） | `transport` 单测 | ✅ shutdown 承载流量的 relay 后数据改走第二个 relay（约 60s） |

state-ha 关键输出：

```text
leader=1
route present on all replicas (via=0202...0202)
member secret rejected for admin write
signed join replicated (74816bbd...)
LSA present: ['74816bbd...'] -> LSA expired on all replicas
epoch monotonic (1795518007 -> 1795518007), new leader=2
OK: controller state replication, signed join, LSA TTL and epoch verified
```

iroh-raft 关键输出：

```text
leader=1 follower=2
follower did not apply the iroh LSA
iroh LSA applied on the leader and replicated to all replicas
OK: iroh control path goes through Raft
```

补充（19:5x 重跑，新二进制 `02e412f6…`）：

```text
>4MiB snapshot: ctrl3 partial=2097152 -> kill -> restart(partial=2097152)
-> link restored -> ctrl3 caught up: generation=5103
OK: >4MiB snapshot transferred across regions with an interrupted resume

membership: initial leader=1 (3 voters) -> learner 4 added -> 4-voter cluster
-> route replicated to ctrl4 -> write accepted with one follower down (200)
OK: dynamic membership (3 -> 4 voters, learner promotion) verified

iroh large: controller raft-state.json bytes=9378264
iroh member ACKed a 8 MiB snapshot (acks=1)
OK: iroh control syncs models above the old 4 MiB frame cap

WAN loss rerun: initial leader=1 under loss; new leader=3 after 4.6s;
failover snapshot ok; OK
```

relay 故障重连（本轮修复）：用 `clear_address_lookup` 强制 relay-only，先确认数据经
某个 relay，再 `shutdown()` 该 relay；重连地址现已包含全部 `transport.relay_urls`，
连接关闭后会经第二个 relay 重建，数据恢复（实测约 60s，受 QUIC idle timeout 限制）。
多 relay 同时承载/秒级切换仍未实现。

### 3.12 2026-11-24 晚 P2 验证

| 项 | 环境/脚本 | 结果 |
|---|---|---|
| 应用层分片重组（v4） | `scripts/test-netns-reassembly.sh`，a MTU 600 / b MTU 1500，ping 1000B | ✅ 请求在 b 重组 3 次、回复在 a 重组 3 次，ping 3/3，0% 丢包 |
| ACL reject/drop | `scripts/test-netns-acl-reject.sh` | ✅ reject: ping "Packet filtered"，acl_rejected=52；drop: 100% 超时 |
| 入网审批 | controller 集成测试（Raft，3 副本） | ✅ 未签名 403；签名后 202 待审；member secret 审批 401；admin 批准后 200 且三副本可见 |
| metrics/audit | `api::metrics_endpoint_exposes_counters` | ✅ 新增 acl_rejected/spoof/frag/reassembly 指标；审计事件带 rule/src/dst/proto/peer |
| 真实互联网 PMTU | 成都 8.137.217.116 → 深圳 47.112.117.96 | 本机/路径 MTU 1500；payload 1472（1500B）可达，1473 被本机 "message too long" 拒绝；tracepath 报告 pmtu 1500；**未观测到路由器 PTB**（云网络无更小 MTU 链路） |
| systemd / CI 矩阵 | `packaging/*.service`、`.github/workflows/ci.yml` | 文件已加并与本地 `cargo`/`bash -n` 校验；GitHub 上未实际跑过 |
| 单元测试总数 | `cargo test --workspace` | **167 passed** |

> 真实互联网 PTB 的边界：需要 MTU <1500 的链路或可控路由器才能验证；当前 8 台云主机跨地域路径均为 1500，且 1473B 探测先被本机 MTU 拦截，因此"真实路由器生成 PTB"仍属未验证。

### 3.13 2026-11-25 单一成员凭据（本地验证，无云主机）

本轮把入网收敛为 controller 签名的 `MembershipCredential`，删除 PSK / join token /
`admission.mode`。8 台临时主机已在 2026-11-25 00:25 释放，因此全部验证在本机完成：

| 项 | 方式 | 结果 |
|---|---|---|
| 凭据密码学 | `credential::tests`（5 个） | ✅ 往返、篡改 grants 被拒、过期、跨网络、错误 node/issuer、revision 回滚、2/3 续签时机 |
| controller 签发 | `controller::tests` 预注册/审批 | ✅ 预注册直接返回凭据；未知节点 202；非 admin 审批 401；批准后 200；deny 后 403（tombstone） |
| 凭据必须由节点私钥签名 | `enrollment_rejects_a_signature_from_another_key` | ✅ 403 |
| HTTP enroll 端到端 | `control_client::tests::http_enrollment_installs_a_credential` | ✅ 真 HTTP server + 真 agent 请求，`credential.json` 落盘且 issuer/prefix 正确 |
| 撤销丢 grant | `control_client::tests::revoked_members_lose_their_grants_and_revisions_advance` | ✅ 快照移除成员后 grant 删除、revision 前进 |
| iroh 凭据握手 | `transport::tests::controller_credentials_gate_connections_and_install_grants` | ✅ 两个带凭据端点互相连上并安装 grant；无凭据的第三个节点被拒绝 |
| 全量测试 | `cargo test --workspace` | **190 passed**（agent 143 + types 22 + 其余 25） |
| Raft 预注册成员 | `scripts/test-controller-raft-3node.sh`（本机） | ✅ LSA/snapshot/failover/crash-recovery；修复了 Raft 状态机未从 config 播种成员的问题 |
| Raft TLS 预注册成员 | `scripts/test-controller-raft-tls-3node.sh`（本机） | ✅ TLS 三节点 LSA/snapshot |
| 审批入网全链路 | `scripts/test-controller-state-ha.sh`（本机） | ✅ agent 签名 enroll → 待审 → admin approve → 三副本可见；LSA TTL/epoch 通过 |
| 凭据 demo | `scripts/demo-credential-enroll.sh`（本机） | ✅ 预注册节点直接取证、未知节点审批后取证、双方 iroh 握手 |
| 跨网络凭据拒绝 | `scripts/demo-multi-network-isolation.sh`（本机） | ✅ 不同 network 的凭据在握手时报 `credential network mismatch` |
| 静态检查 | `cargo fmt --check`、`cargo clippy --workspace --all-targets -- -D warnings` | ✅ |

### 3.14 2026-11-25 static 模式（4 台真实主机）

`network.auth.mode = "static"`（WireGuard 式 peers 白名单）的跨地域实测：

| 项 | 环境/方式 | 结果 |
|---|---|---|
| 4 节点全互联 | 深圳 47.112.180.223 / 47.112.175.202 + 乌兰察布 8.161.224.235 / 8.161.224.111；TUN `10.77.0.1-4`，每个节点 `[[peers]]` 列其余 3 台 | ✅ 12 个方向的 peer 全部 connected；12 个方向 `ping` 2/2 通过 |
| 未知 key 拒绝 | 停掉 n1 后，用它的 UDP 端口（47101，云安全组唯一放行的端口）启动一个全新 identity 的 rogue，peers 指向 n2 | ✅ n2 日志出现 `peer key is not in the static allowlist`；`/v1/peers` 中没有 rogue；rogue 无法加入 |
| 动态 peer 拒绝 | `transport::tests::static_mode_only_accepts_allowlisted_keys` | ✅ 未列出的 key 在 QUIC 后立即被 close；`add_peer`（discovery/LSA 路径）也拒绝 |
| 单元/配置 | `config::tests::static_mode_requires_peers_and_allows_discovery` | ✅ static 必须至少一个 peer；discovery 在该模式下允许 |

> 云环境注意：第一次用随机 UDP 端口（47190）启动 rogue 时 QUIC 握手无法完成——安全组只放行各节点的固定端口；改用 n1 的 47101 后测试通过。脚本 `scripts/test-real-static-mesh.sh` 已按此实现。

### 3.15 2026-11-25 IPAM（4 台真实主机）

controller 在深圳 `.223`，3 个 member 分布在深圳 `.202`、乌兰察布 `.235/.111`；
member 配置 `node.ipam = "auto"`，controller 池 `10.66.0.0/24`：

| 项 | 结果 |
|---|---|
| 自动分配 | ✅ enroll → 待审 → admin approve → 凭据携带 `10.66.0.1/2/3`；三个 TUN 均配置对应地址 |
| 租约 | ✅ `/v1/ipam/leases` 3 条；最低空闲顺序分配 |
| 数据面 | ✅ 等待 peer mesh 后 3×2 方向 ping 全部通过 |
| 重启复用 | ✅ 重启 n1 后仍是 `10.66.0.1`（缓存 `credential.json`） |
| 撤销 | ✅ 撤销 n3 后租约降到 2、`10.66.0.3` 进入 quarantine；剩余成员继续互通 |
| 脚本 | ✅ `scripts/test-real-ipam.sh` |

> 环境说明：这批主机的安全组只放行 5689–6000；controller HTTP 用 5801，
> member 的 iroh 端口用 5901–5903，因此测试直接使用公网地址，无需隧道。

### 3.16 2026-11-25 controller 持久化重构

原实现每次 append/apply 重写整份 JSON。现改为：

- 日志：`raft-log/seg-*.wal` 追加（8 MiB 分段）+ `raft-log/meta.json`（vote/committed/purged）；
- 状态：`raft-state.json` 每 512 条应用写一次快照，`raft-state.wal` 追加每次 applied entry；
- 启动时先载入快照，再重放 WAL 尾部；旧 `raft-log.json`/`raft-state.json` 自动迁移。

| 项 | 结果 |
|---|---|
| 5,100 LSA×24 prefixes 导入（单节点 Raft，8 线程） | **16.41 s**（重构前 331 s，约 20×） |
| 重启恢复 | **0.14 s**，generation/lsas 完整（5102/5100） |
| 磁盘 | 7.2 MB（log 1.31 MB + snapshot 5.28 MB + WAL 0.59 MB） |
| 三节点故障/重启 | `test-controller-raft-3node.sh` ✅ |
| 三副本状态复制/恢复 | `test-controller-state-ha.sh` ✅ |
| 单测 | 追加日志不重写、purge/truncate、512 条快照+WAL 恢复、旧格式迁移、持久化失败不 apply |
| 脚本 | `scripts/test-raft-persistence.sh` |

> 升级注意：新布局与旧二进制不兼容；启动时会迁移并重命名旧 `raft-log.json`，
> 回滚需要恢复升级前备份。

### 3.17 2026-11-25 NAT 后面的主机（真实家庭宽带）

拓扑：本机 `10.0.10.42`（Ubuntu，8C/15G，`enp1s0` MTU 1500，无公网入向、无端口映射）
作为 member；controller 在深圳 `.223`（公网 5801），另一个 member 在深圳 `.202`
（公网 5901）。NATed agent 只主动出站，未配置 relay（`disable_relay=true`）。

| 项 | 结果 |
|---|---|
| enroll / approve / IPAM | ✅ 自动拿到 `10.66.0.1`；云端 peer 为 `10.66.0.2` |
| NAT 穿透 | ✅ `path=direct`；云端看到 NAT 公网映射 `120.85.169.79:9637`，无需端口映射/relay |
| overlay ping | ✅ 双向 0% loss，RTT 约 10–18 ms |
| 吞吐（20 MiB TCP） | 9.36 Mbps（NAT+overlay）vs 10.31 Mbps（同机直连公网 TCP），约 9% 开销；受家宽上行限制 |
| 空闲 3 分钟 | ✅ 连接保持，0% loss，RTT 9.6 ms；QUIC keepalive 保住 NAT 映射 |
| NAT 侧 agent 重启 | ✅ 重启后自动重连（秒级恢复 ping） |
| 云端 peer 重启 | ✅ 约 31 s 恢复（QUIC 默认 idle timeout 30 s + 2 s 重连间隔） |
| PMTU | ✅ TUN 1280；1252 字节 payload 双向通过，1253 字节按 MTU 正确失败 |

测试中发现并修复：

- **TUN MTU 抖动**：iroh 建连初期 datagram size 为保守的 1200，MTU monitor 会在
  1280/1114 之间反复切换；瞬时下调还会在 Linux 路由缓存留下 `mtu 1146`，导致
  >1146 的 ping 全部 EMSGSIZE。修复：下调需连续 30 个采样（约 60 s），上调时
  `ip route flush cache`。两端都升级后 TUN 稳定在 1280，1252 字节双向通过，
  1253 字节按 MTU 正确失败。只升级一端仍可能被对端 PTB 打回 1146。
- **重启检测慢（未修）**：QUIC 默认 idle timeout 30 s，云端 peer 重启后 NAT 侧要等
  旧连接超时才会重连（约 31 s）。试过把 idle timeout 调到 15 s，能把恢复降到 17.4 s，
  但会破坏 `endpoint_fails_over_to_the_second_relay...` 测试（relay 切换不再发生），
  因此保留默认值，记为已知限制。

仍**未测**：NAT↔NAT（两侧都无公网映射/对称 NAT）、relay-only 回退、家庭路由器
UDP 映射超时 <3 分钟、IPv6-only 路径、弱网/丢包下的 NAT 重绑定。

### 3.18 仍未验证

- 持续慢链路（2mbit 级）下 60s transfer TTL 是否足够
- 丢包/抖动下的滚动重启与 >4MiB snapshot
- 长时间 soak / 性能
- 磁盘慢 IO / fsync 失败注入
- 动态 Raft membership

---

## 4. 双网卡 multipath

A：47.119.37.129，eth0 `.162`，eth1 `.164`。
B：47.119.37.217。

结果：

```text
B -> A selected path_addr: 192.168.0.164:5911 path_count=1
B -> A after blocking .164: 192.168.0.162:5911
OK: dual-NIC direct path failover works.
```

进一步：

```text
对 .164 加 100ms 延迟：selected 仍为 .164，path_count=1
对 .164 加 20% 丢包：selected 仍为 .164，path_count=1
阻断 .164：切换 .162
```

结论：

- **双 direct 地址 failover 已通过**
- iroh 当前只打开 **1 条 path**（`path_count=1`）
- 没有验证到“双 direct 同时承载”
- **RTT/丢包不会触发路径切换；只有硬阻断才会**
- 双 relay 同时承载未验证：配置 `usw1` + `aps1` 两个 relay URL 后仍为 `path=relay, path_count=1`，只使用一个 relay

---

## 5. 真实 PTB 黑洞（agent 业务流量）

Chengdu netns：

```text
a --1500-- r1 --1400-- r2 --1300-- b
```

初始：

```text
peer path MTU: 1224
agent TUN MTU: 1176
```

测试：

1. 建立 overlay 长连接 TCP，持续发送大块数据。
2. 将 r2/b 链路 MTU 从 1300 降到 1100。
3. 在 r2 OUTPUT 丢弃 ICMP fragmentation-needed。
4. 15 秒后恢复 MTU 1300 和 PTB。

客户端观测：

```text
T 8.4  BYTES 13959168
T 32.4 BYTES 13959168
T 34.4 BYTES 18418802
...
TOTAL 74057804 GAPS [(6.4, 32.7)]
```

复跑（当前部署二进制）：

```text
TOTAL 73410940 GAPS [(6.2, 32.7)]
```

结论：

- 黑洞期间 overlay 完全停住
- 恢复 PTB/MTU 后，**长连接 TCP 自动恢复**，但延迟约 10–12 秒
- 恢复后新 HTTP flow 正常：`new_http_ok=1`
- overlay ping 恢复
- agent 的 `/v1/peers` 始终显示：
  - `connected=true`
  - `path=direct`
  - `mtu=1224`
  - `path_changes=1`
- 没有触发 iroh reconnect / 新 underlay 路径 / path_changes 变化
- 结论：**iroh QUIC 在黑洞期间未主动重建连接；TCP 长连接靠重传恢复，短时黑洞后可恢复**

脚本：

- `scripts/test-netns-pmtud-blackhole.sh`

---

## 6. PMTUD（IPv4）

成都 netns：

```text
tracepath: pmtu 1400 -> 1300
1450-byte DF -> R1 PTB 1400
1378-byte DF -> R2 PTB 1300
R2 丢 PTB：100% loss，无 1300 PTB
恢复：1300 PTB，1272-byte ping 通过
agent: peer 1224 / TUN 1176
2000-byte overlay ping: 0% loss
2 MiB TCP: 2,097,152 bytes
```

脚本：

- `scripts/test-netns-pmtud-lab.sh`

---

## 7. PMTUD（IPv6）

同一 netns，IPv6：

```text
tracepath -6: pmtu 1400 -> 1300
1450-byte -> R1 Packet too big mtu=1400
1300-byte -> R2 Packet too big mtu=1300
1252-byte ping: 0% loss
R2 丢 ICMPv6 PTB：100% loss
恢复：Packet too big mtu=1300，1252-byte 通过
```

---

## 8. 跨地域

深圳 120.77.233.189 ↔ 上海 8.153.183.185，公网 25 ms：

```text
基本 ping: 0% loss
2000-byte ping: 0% loss
TUN MTU: 1366
peer path MTU: 1414
```

---

## 9. Docker

- Docker 29.10.0
- `alpine:latest`、`debian:bookworm-slim` pull 成功
- 容器内 agent：
  - `--network host`
  - `--cap-add=NET_ADMIN`
  - `--device /dev/net/tun`
  - 宿主二进制挂载
  - host-network TUN + 2000-byte ping 通过
- 标准 `docker/runtime.Dockerfile` 的 apt 安装在云主机上极慢/卡住，未完成
- Docker 双容器 bridge 网络、macvlan、mDNS 未逐项复跑

---

## 10. 当前结论

已验证：

- controller 3 节点/mTLS/failover/跨地域公网
- IPv4/IPv6 overlay
- 双网卡 direct failover
- IPv4/IPv6 PMTUD、逐跳 MTU、PTB 黑洞/恢复
- agent 真实流量穿越 PTB 黑洞后的长连接恢复
- 磁盘满 503、撕裂 log fail-closed
- Docker host-network TUN
- 应用层分片重组、ACL reject/drop、入网审批（2026-11-24）
- 单一成员凭据：签发/审批/撤销/握手/续签（2026-11-25，本地）
- IPAM：自动分配、租约、TUN 地址、重启复用、撤销隔离（2026-11-25，4 主机）
- controller 持久化：分段日志 + 快照/WAL（2026-11-25，导入 16.4s、重启 0.14s）

仍未验证/未实现：

- 真正 multipath（双 direct 同时承载、RTT/丢包调度、双 relay）
- 真实互联网路由器 PTB（云网络路径均为 1500）
- GitHub Actions 实跑、systemd unit 的 `systemd-analyze verify`
- Docker 双容器网络/CI
- macOS/Windows NAT
- 大规模/长时间 soak、磁盘慢 IO 注入
- 多 controller 用各自 key 签发凭据的跨地域实测（本地只验证单 controller）
- static 模式的大规模（>10 节点）与动态增删（当前每个变更都要改配置）
