# 项目审计：未实现 / 未验证 / 文档不一致（2026-11-24）

> 关联：[GAPS.md](GAPS.md)、[TEST-RESULTS.md](TEST-RESULTS.md)、[FOLLOWUP.md](FOLLOWUP.md)、[README.md](README.md)、[OPENRAFT-HA.md](OPENRAFT-HA.md)
> 方法：静态通读 + 全仓 grep + 对照文档断言；**没有**重新跑真实主机测试（临时主机已于 11-24 14:00 释放）。
> 证据等级：`代码`（file:line 可核对）> `单测` > `本机脚本` > `真实主机脚本` > `手工记录`。凡是只有手工记录的结论，本文按"证据弱"处理。

---

## 0. 摘要

- 仓库规模：6 crates、约 15.7k 行 Rust、39 个脚本、118 个测试（agent 88 / types 10 / routing 8 / linkstate 6 / fib 6 / **cli 0**）、1 个 CI job。
- **没有** `todo!` / `unimplemented!` / `FIXME`；缺口不在标记，而在：
  1. **安全语义没落地**（LSA 无签名、transit capability 不执行、Raft RPC 可无鉴权、共享 secret 无分权）；
  2. **Raft 不是唯一写路径**（iroh 控制面完全绕过 Raft；`POST /v1/routes` 也不进 Raft）；
  3. **证据链有假绿**（至少 2 个脚本无条件成功，其中 1 个是本轮新增的 WAN 丢包脚本，已加固）；
  4. **文档把设计/计划写成了已实现**（README/ARCHITECTURE/PROTOCOL/OPENRAFT-HA 均有）。
- 审计时 `origin/main` 落后 8 个提交（本轮审计提交后为 10 个），因此 CI 从未对这批改动运行过。

| 级别 | 数量 | 代表项 |
|---|---:|---|
| P0 | 6 | LSA 可伪造、transit 放行任意成员源、OS 路由无 owner、iroh 绕过 Raft、Raft RPC fail-open、脚本假绿 |
| P1 | 17 | `/v1/routes` 不进 Raft、LSA TTL 不执行、epoch 语义、join 无签名、snapshot/manifest fail-open、动态 membership、relay failover 空断言、TTL/path hint 缺失、配置 no-op、空 secret、零测试模块…… |
| P2 | 15+ | metrics/audit、IPv6 MTU、network_hash、discovery 默认开放、relay 回退、CI/打包/许可、文档漂移…… |

---

## 1. P0：会直接推翻"可用/安全"结论的项

### P0-1 LSA 无签名，且 origin 不与连接绑定

- 证据：`crates/stellaris-linkstate/src/lib.rs:31-47`（`Lsa` 只有 origin/seq/zone/links/prefixes/overlay_ip/addrs，**无 signature、无 ttl**）；`crates/stellaris-agent/src/link_state.rs:231-233`（收到帧直接 `service.publish(lsa)`）；`crates/stellaris-agent/src/link_state.rs:124-129` + `crates/stellaris-agent/src/membership.rs:75-111`（只按 `lsa.origin` 对应的 grant/peer 前缀做授权，**不校验发送连接是否就是 origin 节点**）。
- 影响：任一已入网成员可发送 `origin=受害者` 的 LSA（seq 更大），覆盖其拓扑并把全网 SPF 指向攻击者；`overlay_ip/addrs` 还会触发自动 `add_peer`。
- 文档相反：`ARCHITECTURE.md:519` 称 LSA 带 signature、`ARCHITECTURE.md:521` 称带 ttl；`MEMBERSHIP-AUTH.md:186-188` 称连接时交换 manifest/grant 并验证签名。
- 验证：本机三进程即可复现（伪造 origin 后看第三节点 RIB）；修复需加 LSA 签名 + origin↔连接绑定。

### P0-2 anti-spoof 的 transit 分支放行任意成员源，capability 从不执行

- 证据：`crates/stellaris-agent/src/membership.rs:66-73`：源不属于该 peer 时，只要源属于**任一** grant 就放行；注释自认 `transit` 留给后续策略，但全仓无 `capabilities` 执行点。
- 影响：普通成员可冒用其他成员/网关前缀的源地址；`control.members[].capabilities` 与 `join_tokens[].capabilities` 是纯装饰。
- 文档相反：`README.md:21` 称"数据面 source grant 强制（transit capability）"；`ARCHITECTURE.md:440-445` 称按 peer 校验。

### P0-3 OS 路由 reconcile 无 owner/冲突/默认路由防护

- 证据：`crates/stellaris-agent/src/dataplane.rs:217-234` 只过滤 overlay CIDR；`dataplane.rs:248-278` 用 `ip route replace <prefix> dev <tun>` 安装、按前缀删除；无 owner/protocol 标记、无冲突检查、退出不清理。
- 影响：一条 `0.0.0.0/0`（exit node 常见写法，`scripts/test-linux-netns-exit-nat.sh:65` 就广告 0/0）或宽前缀会把宿主流量整体导入 TUN，并覆盖/删除 Tailscale、管理员同前缀路由；多网络/重启残留。
- 文档相反：`ARCHITECTURE.md:186/468/476` 称"只删自己 owner 标记的规则、启动检查冲突"；`ADVANCED-ROUTING.md:74-76` 自己把 owner/冲突检测列为待做。

### P0-4 iroh 控制入口完全绕过 Raft，形成第二套状态机

- 证据：`crates/stellaris-agent/src/controller.rs:1668-1710` `dispatch_control`：`Snapshot => state.snapshot(local)`、`Lsa => state.apply_lsa(lsa)`、`Ack => state.record_ack(...)`，全是 legacy 内存/JSON 路径；`ensure_leader`（`controller.rs:616-622`）只看静态 `control.leader_id`，未配置时恒 Ok；`controller.rs:1570-1578` 只要配了 `iroh_port` 就会启动它，即使 Raft 已启用。
- 影响：follower/少数派通过 iroh 提交的 LSA 被本地接受、不复制、不 fence；iroh 快照不保证线性化读；同一集群 HTTP 与 iroh 看到不同 model/generation/ACK。
- 文档相反：`README.md:8` 称"member 通过单个 controller URL 或 iroh control 接入，Raft 内部负责复制"；`OPENRAFT-HA.md:236-239` 称 member snapshot 读默认线性化。
- 验证：本机 3 controller 同时开 `raft_dir` + `iroh_port`，对 follower 发 LSA，对比 `/v1/model`。

### P0-5 Raft RPC 认证默认 fail-open，且无 RPC 超时

- 证据：`crates/stellaris-agent/src/controller_raft.rs:754-762` `authorized()` 在 `secret == None` 时 `return true`；`crates/stellaris-types/src/config.rs` 的 validate 没有"`raft_bind` 非 loopback 必须配 `raft_secret` 或 mTLS"的规则（只校验 `control.bind`）；`controller_raft.rs:1117/1145/1176` `_option: RPCOption` 未使用，`http_client`（`:64-80`）未设 timeout。
- 影响：`raft_bind = "0.0.0.0:5701"` 且未配 secret/TLS（配置合法，README/示例都这么写）时，同网段任何人可 `POST /raft/append|vote` 接管集群；黑洞 peer 可让 RPC 无限挂起。
- 文档相反：`OPENRAFT-HA.md:209-213` 称已实现 RPC timeout/backoff 与 target 校验。

### P0-6 证据链假绿（会影响本仓库所有"已验证"结论）

- `scripts/test-real-wan-loss-ha.sh`（本轮新增）：原版仅 `set -u`；`post()` 的 curl 结果丢到 `/dev/null`；snapshot 校验 `... | grep -q ... && log` 失败也继续；最后 `log "OK"` 无条件执行。**已在本轮加固**（`curl -fsS` + 逐项 `fail` + 删除硬编码 IP），但主机已释放，加固版**没有在真实主机复跑**。
- `scripts/test-linux-netns-3node-controller.sh:103-111`：4 条 ping 全部 `|| true`，无 OK/FAIL、无最终断言，脚本恒 0 退出；`README.md:349` 却称其验证"双向 0% loss 和 1000B 包"。
- 影响：阅读者会把"脚本退出 0"当成"断言通过"。修复前，TEST-RESULTS 中依赖这些脚本的结论要靠人工看日志，不能当作回归保护。

---

## 2. P1：高价值缺口

| # | 项 | 证据 | 影响 |
|---|---|---|---|
| 1 | `POST /v1/routes` 不在 Raft、不持久化、无 leader fence、RouteId 随机 | `controller.rs:1133-1140`、`:1451-1470`、`:1214-1228` | 任意 controller（含 follower）可写；重启/换主即丢；与 OPENRAFT-HA §1.1/§5.5 矛盾 |
| 2 | Raft 模式下 LSA TTL 从不执行 | `controller.rs:666-699` 只被 legacy `manifest()/snapshot()` 调用；`snapshot_from_model/manifest_from_model` 不调用；全仓无 Raft 侧 `ExpireLsa` 生产者 | 下线成员/前缀永久保留、快照无界增长、SPF 仍给死下一跳 |
| 3 | epoch 不复制、不单调、revoke 不 +1、`SetEpoch` 死命令 | `controller.rs:255,280`（各副本 `now_epoch()`）；`controller_model.rs:29`（无生产者）；`:149-153`（revoke 不 bump） | "epoch 单调/旧 leader fence"不成立；换主 epoch 可能回退；跨副本 ACK 409 |
| 4 | `/v1/join` 不证明 NodeId 私钥所有权，overlay_ip 不校验网段 | `controller.rs:1347-1382`（无签名/nonce）、`:943-971`、`:1031-1036` | 任何持共享 secret 者可冒名加入、抢 overlay IP、写网段外 grant |
| 5 | 控制 API 无特权分离 | `controller.rs:1087-1100` 同一 secret 通过所有 handler（snapshot/LSA/join/revoke/routes） | 任一成员可撤销他人、注入路由、读全网状态 |
| 6 | 快照/manifest 校验 fail-open，非 strict 模式"洗白"任意前缀 | `control_client.rs:399-451`（controller_keys 空且 secret 空 → true）；`controller.rs:862-863`（`!strict_membership` 直接 Ok）；`:475-495`（无 grant 时 allowed_prefixes 回填 LSA 自报前缀） | 默认可接受任意 origin 的 LSA 并把自报前缀下发给全网；`0.0.0.0/0` 可被集群接受 |
| 7 | 任意 controller（含 follower）可签发 manifest | `controller.rs:1318-1323` 无 leader/quorum 检查 | 成员可能被落后副本的旧成员表覆盖；与 MEMBERSHIP-AUTH C1 矛盾 |
| 8 | 动态 Raft membership 完全未实现 | 全仓无 `add_learner`/`change_membership`/`remove`；`controller_raft.rs:1543-1552` 只在 bootstrap 一次性 initialize | 扩缩容只能清空集群重建；OPENRAFT-HA §5.4/§11 的流程无入口 |
| 9 | relay failover 测试空转 | `transport.rs:607-625`：`drop(relay1)` 后连接本来就 true，循环立即 break，断言恒真 | "relay failover 已验证"无有效证据；真正 multipath 未实现（`path_count=1`） |
| 10 | Route TTL / pin expiry 永不生效 | `stellaris-routing/src/lib.rs:509-525` `expire()` 无调用方（全仓 grep 只命中 LSA/controller） | `expires_at`/`ttl_secs` 语义缺失；临时路由永久生效 |
| 11 | Path 层不存在，`set_path_hint` 空实现 | `stellaris-fib/src/lib.rs:139` 恒 `PathHint::Auto`；`stellaris-routing/src/lib.rs:701` `Action::SetPathHint { .. } => {}` | README "Intent/RIB/FIB 四层"、ARCHITECTURE "v1 只做偏好/观测" 均不成立 |
| 12 | 配置接受但无效 | `transport.listen` 0 读取（`config.rs:400`）；`routing.rib_mode` 仅 status 回显（`api.rs:198`）；`Match` 无 `zone` 字段（`route.rs:169-176`）但 README 称 zone 匹配；无 `deny_unknown_fields` | 用户以为关了监听/按 zone 过滤，实际不生效；写错字段会"匹配全部" |
| 13 | 空字符串 secret/token 绕过非 loopback 校验 | `config.rs:683-696` 只查 `is_none()`；`api.rs:74/97`、`controller.rs:1096-1099` 把空串当合法凭据 | `token = ""` 的 `0.0.0.0` API 通过校验且无鉴权 |
| 14 | Raft TLS cert/key 未成对校验，单边配置静默降级 | `config.rs:217-231`、`:706-715`；`controller.rs:1504-1519` `.zip()` | 配了 `raft_tls_cert` 却没配 key 时静默回到 HTTP Raft |
| 15 | QoS 两条校验路径不对称 | `config.rs:784-820` 查 queue_depth 但漏 rate_bps；`agent/src/policy.rs:35-61` 查 rate_bps 但漏 queue_depth | TOML `rate_bps=0` 永久限速；`PUT /v1/policy` 的 `queue_depth=0` 让整类包被 drop（`dataplane.rs:419-430`） |
| 16 | 大模型在 iroh 控制模式必然同步失败 | `control_wire.rs:11,59-61` 4 MiB 硬上限；Raft HTTP 路径支持 512 MiB 分块 | TEST-RESULTS §3.10 的 5.57 MiB 模型只有 HTTP 路径证据；iroh 部署会卡死在 "control frame too large" |
| 17 | 核心模块零测试 | `control_client.rs`（609 行）、`discovery.rs`（280）、`control_wire.rs`、CLI（274）均 0 测试；无 `tests/`、benches、fuzz | 控制面轮询/验签/发现/CLI 回归无保护；API 的 lookup/explain/pin/unpin/drain/reset/delete 无测试 |

补充（同属 P1，但影响面稍小）：Raft 单发 snapshot 空 checksum 跳过校验（`controller_raft.rs:1031`）；`LogStore`/`StateMachineStore` 反序列化失败 `unwrap_or_default()` 静默重置（`controller_raft.rs:128-133,307-315`），与"撕裂写 fail-closed"的叙述不一致；`join` token 单次消费存在 TOCTOU（`controller.rs:956-967`）；`/metrics` 只有 9 个指标、入站丢包只 debug 不计数（`dataplane.rs:639-642`）。

---

## 3. P2：中低优先级（摘要）

- **可观测性**：`stats.rs:5-12` 仅 5 个计数器；`ARCHITECTURE.md:890-905` 列的 14 个指标大多不存在；ACL deny 的 `stellaris_audit` 默认 EnvFilter 不启用（`bin/stellaris-agent.rs:24-25`）。
- **IPv6**：TUN MTU 自适应可到 576（`dataplane.rs:331-340`），可低于 IPv6 最小 1280；带扩展头的 IPv6 TCP 不 clamp MSS（`wire.rs:284-289`）；一个网络只能单栈。
- **MeshHeader**：`network_hash` 取 UUIDv7 前 4 字节（`wire.rs:60-63`），不是文档写的 xxhash64；同一 ~65s 窗口创建的网络 hash 相同，无碰撞检测。
- **发现/入网**：默认 `network.auth.mode=none`；UDP 广播/mDNS 无签名，发现即 `add_peer` 且每 peer 永久重试（`transport.rs:190-223`）；`relay_urls=[]` 不是禁用 relay 而是回退 N0 公共 relay（`transport.rs:73-84`）。
- **数据面细节**：ACL deny 不回 ICMP；非首片分片可能拿到不同 QoS 分类；`too_big_action` 早于 local/ACL 判定。
- **工程/发布**：无 `LICENSE` 文件（`Cargo.toml` 写 MIT OR Apache-2.0，`repository` 是 `example.invalid`）；无 systemd/打包/升级；无 bench/soak/规模测试；无真实互联网路由器抓包。
- **CI**：只 1 个 job、只跑 2 个脚本；Docker step 的 `BIN=target/debug/...` 是相对路径，`docker run -v` 需要绝对路径；未 pin action SHA；无 macOS job；`test-controller-raft-3node.sh` 等 37 个脚本不在 CI。

---

## 4. 已验证 / 未验证矩阵（按证据等级）

| 能力 | 最强证据 | 缺什么 |
|---|---|---|
| openraft 3 节点、mTLS、滚动重启 | 真实三主机脚本（TEST-RESULTS §3.6/§3.8） | 丢包下滚动重启、5 节点、动态成员 |
| WAN 20% 丢包 + 50ms 选举 | 真实三主机脚本（§3.9） | soak、丢包下的 snapshot/滚动 |
| >4MiB snapshot 跨 WAN + 中断续传 | 手工记录（§3.10，无脚本） | 固化成脚本；持续慢链路 TTL；agent 客户端重启续传 |
| 控制面 iroh 入口 | 仅 demo（`demo-iroh-controller.sh`） | 无 Raft 语义证据（见 P0-4）；>4MiB 失败 |
| LSA 洪泛/SPF/ECMP | 单测 + demo 脚本 | 无签名/防伪证据；heartbeat 超时路径无测试 |
| ACL 首片/后续分片 | 单测 | 无 netns/真实流量 |
| QoS token bucket/队列 | 单测（队列上限无测试） | 无吞吐/公平性/丢包计数证据 |
| NAT44/NAT66 public exit | Linux netns 脚本 | 云上/真实公网、macOS、清理与幂等 |
| PMTUD/PTB | netns 脚本 + 单测 | 真实互联网路由器、IPv6 逐跳/扩展头 |
| 多网络隔离 | demo + PSK 网络串 | MeshHeader hash 隔离、snapshot network_id 校验 |
| OS 路由 reconcile | netns/docker 正常前缀 | 默认路由/owner/冲突/退出清理 |
| relay 建连 | 单测（本地 relay） | relay1→relay2 failover（现测试空转）、多路径 |
| CLI | 无测试 | 6 个子命令无任何脚本/测试覆盖 |

---

## 5. 文档与代码不一致（抽样，均需修正）

| 文档位置 | 说法 | 实际 |
|---|---|---|
| `README.md:5,8` | relay failover 落地；iroh 控制由 Raft 复制 | failover 测试空转；iroh 绕过 Raft |
| `README.md:10` | Intent/RIB/FIB 四层 | 只有三层，无 Path |
| `README.md:21` | transit capability 强制 | `membership.rs:66-73` 放行任意成员源 |
| `README.md:22` | AZ 用 `region`/`zone` 匹配 | `Match` 只有 `region` |
| `README.md:32` | 多网络尚未实现 | 已实现（`demo-multi-network-isolation.sh`、多 `--config`） |
| `README.md:255` | withdrawn after **b** failure | 脚本实际输出 **c**（`demo-distributed-linkstate.sh:122`） |
| `README.md:349` | netns 3node-controller 验证 0% loss/1000B | 脚本全部 `ping || true`，恒成功 |
| `README.md:568` | `apps/` 预留 dashboard | 无 `apps/`；实际 UI 是 `crates/stellaris-agent/static/index.html` |
| `README.md:601` | `scope=network` 已支持 | agent API 直接 400（`api.rs:365-369`），CLI 固定 local |
| `README.md:604` | 公共 relay 已验证 failover | 无有效证据 |
| `ARCHITECTURE.md:73-74` | `apps/dashboard/` React | 无该目录 |
| `ARCHITECTURE.md:406,484` | IPv4 重组/分片、超 MTU 指标 | 均未实现 |
| `ARCHITECTURE.md:459-462` | Byte-DRR、per-peer 三队列 | 单全局严格优先级堆 |
| `ARCHITECTURE.md:519-521` | LSA 带 signature/ttl | `Lsa` 无这些字段 |
| `PROTOCOL.md:31-48` | 8 MiB 帧、zstd、protobuf | 4 MiB、JSON、无 zstd |
| `PROTOCOL.md:544-545` | controller `GET/PUT /v1/policy` | controller 无该端点 |
| `PROTOCOL.md:578` | LSA 30s 过期由 controller 清理 | Raft 模式不清理 |
| `OPENRAFT-HA.md:43,157` | epoch 单调、leader 周期提交 ExpireLsa | epoch 各副本墙钟；无生产者 |
| `OPENRAFT-HA.md:231,735` | `/v1/controller/status`、controller `/metrics` | 不存在 |
| `OPENRAFT-HA.md:332` | 非 leader 返回 307 + Location | 实际 503 + header；`/v1/routes` 无检查 |
| `GAPS.md:37` | `cargo test 112 passed` | 118 |
| `GAPS.md:228-229` | WAN 丢包/large snapshot 未验证 | 已于 11-24 验证（§3.9/§3.10） |
| `TEST-RESULTS.md:223` | 真实三地 TOML 未复跑 | §3.8 已复跑通过 |

---

## 6. 建议的下一步（按投入产出排序）

1. **先修证据链（1-2 天）**：把 WAN 脚本加固版在下一批主机复跑；修 `test-linux-netns-3node-controller.sh` 让 ping 失败即退出；CI 的 Docker step 改绝对路径；至少把 `test-controller-raft-3node.sh`、一个 netns 脚本、`test-tls.sh` 纳入 CI；push 让 CI 真正跑一次。
2. **控制面安全闭环（1-2 周）**：LSA 签名 + origin↔连接绑定；transit capability 真正执行；join 带 NodeId 签名/nonce；拆 controller 读写 secret（或 per-member key）；空 secret/token 校验；`raft_bind` 非 loopback 强制 `raft_secret` 或 mTLS；Raft RPC 加 timeout/backoff。
3. **让 Raft 成为唯一写路径（1-2 周）**：iroh 控制帧改走 Raft（或组合明确拒绝启动）；`POST /v1/routes` 入 Raft 并持久化；`ExpireLsa` 周期生产者；epoch 入 Raft 且 revoke +1；加 controller status/metrics。
4. **数据面正确性（1-2 周）**：OS 路由 owner/冲突/默认路由防护与退出清理；分片/重组与 transit 跨 MTU；route TTL 定时器；path hint 实现或拒绝；IPv6 <1280 处理；分片 QoS 一致性。
5. **文档与 CI 对账（1-2 天）**：按本文 §5 全量修正；把 ARCHITECTURE/PROTOCOL 的"设计"与"已实现"分开标注；CI 增加 macOS `cargo check`、shellcheck、`cargo deny`（可选）。

**资源需求**：第 1、3 步大部分本机可做（3 进程 + loopback）；第 2 步的 LSA 伪造/transit 攻击本机三进程可复现；第 4 步需要 Linux root/netns；真实公网 NAT/互联网 PMTUD 与 5 节点/动态成员需要 3-5 台多地域主机。若再开机器，仍按 3 台一地域一台、root SSH、TCP/UDP 5689-6000 的规格即可。
