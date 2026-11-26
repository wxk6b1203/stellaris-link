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
- 审计时 `origin/main` 落后 8 个提交（本轮审计提交后仍未 push），因此 CI 从未对这批改动运行过。

| 级别 | 数量 | 代表项 |
|---|---:|---|
| P0 | 6 | LSA 可伪造、transit 放行任意成员源、OS 路由无 owner、iroh 绕过 Raft、Raft RPC fail-open、脚本假绿 |
| P1 | 17 | `/v1/routes` 不进 Raft、LSA TTL 不执行、epoch 语义、join 无签名、snapshot/manifest fail-open、动态 membership、relay failover 空断言、TTL/path hint 缺失、配置 no-op、空 secret、零测试模块…… |
| P2 | 已关闭 9 项（metrics/audit、IPv6 MTU、discovery 默认、relay_mode 语义、ACL ICMP、打包/CI、应用层重组、network_hash、文档漂移）；真实互联网 PTB、真 multipath、macOS NAT 仍开放 | 见 §7.2 / §7.3 |

---

## 0.1 2026-11-24 修复状态（当晚）

下面 §1–§3 保留当天上午的审计原文；本条与 §7 是修复后的状态。

| 级别 | 修复 | 仍有边界 |
|---|---|---|
| P0 | 6 / 6 已修复并在真实主机/本机验证 | 无已知 P0 残留 |
| P1 | 17 / 17 修复或关闭（relay failover 为“旧连接关闭后经配置 relay 列表重连”，恢复需数十秒） | 见 §7.3 的残余边界 |
| P2 | 已关闭 9 项；真实互联网 PTB、真 multipath、macOS NAT 仍开放 | 见 §7.2 / §7.3 |

P0 证据速查：

| 项 | 证据 |
|---|---|
| P0-1 LSA 签名 | `lsa_auth` 单测（签名/篡改/换钥/畸形）；`demo-distributed-linkstate.sh` 三进程通过（LSA 帧带签名） |
| P0-2 transit capability | `membership::tests::dataplane_grants_require_transit_for_other_sources`；netns 3-node controller/IPv6 脚本给转发成员 `capabilities=["transit"]` 后通过 |
| P0-3 OS 路由防护 | `scripts/test-netns-route-safety.sh` 在临时主机通过（默认路由拒绝、外部路由保留、proto 240 标记、显式替换） |
| P0-4 iroh 走 Raft | `scripts/test-real-iroh-raft.sh`：follower iroh 入口不落本地，leader 入口复制到三副本 |
| P0-5 Raft 鉴权/超时/checksum | `control.raft_dir` 强制非空 `raft_secret`、TLS 配对、RPC 超时、单发 snapshot 拒绝空 checksum；config 单测 + 全部 raft 脚本（TLS/三地/滚动）通过 |
| P0-6 脚本假绿 | netns 3-node-controller 改为断言并在主机通过；WAN 丢包脚本加 `-e`/逐项失败/重试后在成都-深圳-上海通过 |

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

> 说明：§5 中 README/GAPS/TEST-RESULTS 的条目已按实际修复情况修正；ARCHITECTURE.md、
> PROTOCOL.md、MEMBERSHIP-AUTH.md 已加"设计文档/实现状态"横幅，未实现条目仍保留为设计目标。

## 6. 建议的下一步（按投入产出排序）

1. **先修证据链（1-2 天）**：把 WAN 脚本加固版在下一批主机复跑；修 `test-linux-netns-3node-controller.sh` 让 ping 失败即退出；CI 的 Docker step 改绝对路径；至少把 `test-controller-raft-3node.sh`、一个 netns 脚本、`test-tls.sh` 纳入 CI；push 让 CI 真正跑一次。
2. **控制面安全闭环（1-2 周）**：LSA 签名 + origin↔连接绑定；transit capability 真正执行；join 带 NodeId 签名/nonce；拆 controller 读写 secret（或 per-member key）；空 secret/token 校验；`raft_bind` 非 loopback 强制 `raft_secret` 或 mTLS；Raft RPC 加 timeout/backoff。
3. **让 Raft 成为唯一写路径（1-2 周）**：iroh 控制帧改走 Raft（或组合明确拒绝启动）；`POST /v1/routes` 入 Raft 并持久化；`ExpireLsa` 周期生产者；epoch 入 Raft 且 revoke +1；加 controller status/metrics。
4. **数据面正确性（1-2 周）**：OS 路由 owner/冲突/默认路由防护与退出清理；分片/重组与 transit 跨 MTU；route TTL 定时器；path hint 实现或拒绝；IPv6 <1280 处理；分片 QoS 一致性。
5. **文档与 CI 对账（1-2 天）**：按本文 §5 全量修正；把 ARCHITECTURE/PROTOCOL 的"设计"与"已实现"分开标注；CI 增加 macOS `cargo check`、shellcheck、`cargo deny`（可选）。

**资源需求**：第 1、3 步大部分本机可做（3 进程 + loopback）；第 2 步的 LSA 伪造/transit 攻击本机三进程可复现；第 4 步需要 Linux root/netns；真实公网 NAT/互联网 PMTUD 与 5 节点/动态成员需要 3-5 台多地域主机。若再开机器，仍按 3 台一地域一台、root SSH、TCP/UDP 5689-6000 的规格即可。

---

## 7. 2026-11-24 修复记录与剩余项

### 7.1 已修复（代码 + 证据）

| 审计项 | 修复 | 证据 |
|---|---|---|
| P0-1 LSA 可伪造 | 控制流 LSA 帧携带 Ed25519 签名（origin 即公钥），接收端先验签；iem/controller 的 iroh 入口要求签名 | `lsa_auth` 4 个单测；`demo-distributed-linkstate.sh` 通过 |
| P0-2 transit 放行 | `inbound_source_allowed` 要求发送 peer 具备 `transit`/`gateway`/`exit` capability 才可携带他人源地址 | 单测 + netns 3node/Ipv6（授权后通过） |
| P0-3 OS 路由无主 | 默认路由需 `dataplane.allow_default_route`；外部路由默认跳过，需 `replace_existing_routes`；安装带 `proto 240`；`Drop` 清理 | `test-netns-route-safety.sh` 通过 |
| P0-4 iroh 绕过 Raft | iroh `Snapshot/Lsa/Ack` 改为 `linearize` + `snapshot_current` + `apply_lsa_current` + Raft Ack | `test-real-iroh-raft.sh` 通过 |
| P0-5 Raft 鉴权 | `raft_dir` 必须有非空 `raft_secret`；raft TLS cert/key 与 client cert/key 成对校验；append/vote RPC 超时；单发 snapshot 必须带 checksum | config 单测；三地/滚动/TLS 脚本通过 |
| P0-6 假绿 | netns 3node-controller 断言 ping+status；WAN 丢包脚本 `curl -fsS`、逐项 fail、snapshot 重试 | 两者均在临时主机通过 |
| P1 routes 不在 Raft | 新增 `UpsertRoute` 命令与模型 routes；执行 `POST /v1/routes` 走 Raft；RouteId 由 (network,prefix,via) 确定性生成 | `test-controller-state-ha.sh`：三副本同 id |
| P1 LSA TTL 不执行 | leader housekeeping 周期提交 `ExpireLsa`；`control.lsa_ttl_secs` 可配 | 同上：LSA 在三副本全部过期 |
| P1 epoch 不复制 | raft 模式初始 epoch 为 0，leader 当选后写 `SetEpoch`（墙钟、单调）；revoke +1 | 同上：换主后 epoch 不回退；模型单测 |
| P1 join 无签名 | `require_join_signature` + nonce + Ed25519 签名；member agent 始终签名；未签名 curl 可显式关闭 | 同上：未签 403、agent 加入成功并复制 |
| P1 无特权分离 | `control.admin_secret`：revoke/routes 需要 admin；member secret 被拒 | 同上 + 单测 |
| P1 snapshot/manifest fail-open | 未签名快照默认拒绝（`allow_unsigned_snapshot` 显式开启）；校验 `network_id` 与 epoch 回退；LSA 不再自授权前缀；manifest 仅 leader 可签 | `control_client` 4 个单测；follower manifest 503 单测 |
| P1 动态 membership | `/v1/raft/learner`、`/v1/raft/membership`（admin） | 单测 + `test-real-raft-membership.sh`：3→4 voters、learner 转正、1 follower 宕机仍可写 |
| P1 relay failover | 重连地址加入全部 `transport.relay_urls`；新增 `disable_discovery` 以便强制 relay-only 测试 | 单测：shutdown 承载流量的 relay 后，数据改走第二个 relay（约 60s，等旧连接关闭） |
| P2 network_hash | 改为 SHA-256(network_id) 前 32 位，避免 UUIDv7 时间前缀碰撞 | wire 单测；文档同步 |
| P1 配置 no-op | `transport.listen=false`、`rib_mode!=full`、`set_path_hint` 直接报错；新增 `Match.zone` 并实现匹配 | config/routing 单测 |
| P1 空 secret / TLS 配对 / QoS 校验 | 全部为 validate 错误；QoS 两条路径都校验 0 值 | config/policy 单测 |
| P1 route TTL 不生效 | runtime 每秒调用 `RouteEngine::expire()` | routing 单测 |
| P1 iroh 4 MiB 上限 | 控制帧上限提高到 64 MiB | `test-real-iroh-large-snapshot.sh`：8 MiB 模型经 iroh-only member 同步并 ACK |
| P1 LSA 过期洪泛 | 新增批量 `ExpireLsas`，每轮一条 Raft 写 | 模型单测；修复了 5100 条 LSA 同时过期导致复制/追赶被拖慢的问题 |
| P1 零测试模块 | 新增 control_client/discovery/CLI/路由 API/成员接口测试 | 测试数 118 -> 167 |

### 7.2 2026-11-24 晚 P2 第二批（已完成）

| 项 | 修复 | 证据 |
|---|---|---|
| 应用层分片重组 | 有界 IPv4/IPv6 重组（256 流/128 片/30s），ACL 前完成；IPv6 重叠拒绝、超限丢弃 | 5 个单测 + netns 600/1500 MTU 阶梯（请求 3/回复 3 重组，0% 丢包） |
| ACL 不回 ICMP | `acl.deny_action = reject` 回 ICMP admin-prohibited；echo 可回、ICMP error 不回 | 单测 + `test-netns-acl-reject.sh`（ping "Packet filtered"，acl_rejected>0；drop 静默超时） |
| IPv6 <1280 | TUN MTU 不再低于 1280；路径更小时告警并依赖 PTB/MSS | `ipv6_mtu_never_drops_below_1280` 单测 |
| discovery 默认开放 | 开 discovery 必须 PSK，除非显式 `allow_unauthenticated_discovery` | config 单测 |
| relay_urls 语义 | 新增 `transport.relay_mode = auto/n0/custom/disabled`：`custom` 必须带 urls，`n0`/`disabled` 带 urls 报错，`disable_relay` 视为 disabled | config 单测 + README |
| metrics/audit 细化 | `/metrics` 新增 acl_rejected/spoof/fragment/reassembly；ACL 审计带 rule/src/dst/proto/peer | API 单测 |
| 打包/CI 矩阵 | systemd 两个 unit（capability 最小化）+ packaging 文档；CI ubuntu/macos + netns/TLS/docker + 脚本语法 | 文件已加；GitHub CI 未实际跑过 |
| 真实互联网 PMTUD | 实测成都→深圳路径 MTU 1500（payload 1472 通、1473 报错）；tracepath pmtu 1500 | `TEST-RESULTS.md` §3.12；云网络无更小 MTU 链路，路由器 PTB 生成未观测 |
| 入网 ACL（已被 2026-11-25 方案取代，见 §7.5） | `admission.mode = approve/allowlist`：签名申请入 Raft 待审队列，admin 审批时显式授予前缀/能力 | 模型单测 + controller 集成测试（未签名 403、待审 202、member secret 不能审批、批准后 200） |

### 7.3 仍开放的 P1/P2 边界

- **relay failover 的恢复时延**：2026-11-26 已改为双 endpoint/双 link 热备
  （active 故障立即 fallback，link-state 心跳 4s 清理死链）；不再是旧的 ~60s
  重连。真 multipath/带宽聚合仍未实现（依赖 iroh 上游）。
- **iroh >4MiB 端到端**：上限已提高，但没有用 >4MiB 模型跑 iroh 快照（WAN 大快照验证走 HTTP）。
- **relay 自动 failover**：见上，需要传输层改动。
- **持续慢链路 TTL**：60s transfer TTL 在持续 2mbit 链路下的行为仍未验证。
- **大状态写入/追赶性能（2026-11-25 已修复）**：原实现 `LogStore::append` 每次重写整份
  `raft-log.json`，`apply` 每条重写整份 `raft-state.json`；批量导入 n 条且模型增长时总
  I/O 为 Θ(n²)，5,100 LSA 实测 **5 分 50 秒**。现改为：日志按 **8 MiB 分段追加**（`raft-log/seg-*.wal`
  + 小 `meta.json`），状态机用 **`raft-state.json` 周期快照（每 512 条）+ 追加 WAL**；
  同样的 5,100 LSA×24 前缀实测 **16.4 秒**（约 21×），重启恢复 **0.14 秒**、目录 7.2 MB。
  旧 `raft-log.json`/`raft-state.json` 在启动时自动迁移；升级后不支持回滚到旧二进制。
  仍未做：日志/快照的压缩与远端对象存储（见 §7.3 其他项）。
- **iroh 大帧**：8 MiB 已验证；>64 MiB 仍会失败（无分块）。
- **P2 未动**：真 multipath、真实互联网 PTB（无小 MTU 链路可测）、macOS NAT/Windows、磁盘满/慢 IO 注入、CI 仓库推送与实跑。

### 7.4 本轮新增的配置/行为变化（升级注意）

- 新增：`control.admin_secret`、`control.require_join_signature`、`control.lsa_ttl_secs`、`dataplane.allow_default_route`、`dataplane.replace_existing_routes`。
- Raft 模式现在**强制** `raft_secret`；只配 `raft_tls_cert` 不配 key 会报错（之前静默退化为 HTTP）。
- `transport.listen=false`、`routing.rib_mode!=full`、`set_path_hint` 从“静默忽略”改为配置报错。
- 子网网关/exit 转发必须给成员 grant `capabilities=["transit"]`，否则数据面按 spoof 丢弃。
- 未配置 `controller_keys`/`control.secret` 且未开 `allow_unsigned_snapshot` 的 member 会拒绝控制器快照。
- iroh LSA/Ack 现在要求签名；旧版本 agent 与新版 controller 的 iroh 入口不兼容。
- `network_hash` 从 UUIDv7 前 4 字节改为 SHA-256 前 32 位：混合版本节点的数据面会互不匹配，需同时升级。
- 新增 `control.admission.mode`（legacy/approve/allowlist）与成员侧 `control.request_admission`；`approve` 必须配合 raft。
- 新增 `acl.deny_action = "drop" | "reject"`；`reject` 仅对非 ICMP-error 包回 ICMP admin-prohibited。
- 开启 `discovery_port`/`mdns` 且 `auth.mode = "none"` 现在会配置报错；隔离实验需显式 `transport.allow_unauthenticated_discovery = true`。
- `disable_relay` 与 `relay_urls` 同时配置会报错（此前静默忽略 relay_urls）。
- 分片重组在 ACL 前执行；超限/重叠（IPv6）分片会被丢弃并计入 `frag_dropped`。

### 7.5 2026-11-25 入网模型二次收敛：单一成员凭据

审计结论中“PSK + join token + admission.mode 三套入口”属于**重叠而非纵深**，本轮把它们收敛为
一套 controller 签名的 `MembershipCredential`：

- **删除**：`network.auth.secret`、`network.auth.allowed_nodes`、`control.join_token(s)`、
  `control.require_join_signature`、`control.admission`、`control.request_admission`、
  `POST /v1/join`、`AuthMode::Psk`、`AdmissionMode`/`JoinTokenConfig`。
- **新增**：`MembershipCredential { network, node, overlay_ip, prefixes, capabilities,
  revision, not_after }` + controller 签名；`POST /v1/enroll`（HTTP 签名请求）与
  iroh `Request::Enroll`；`POST /v1/members/{node}/grants`；`control.credential_ttl_secs`。
- **握手**：数据面 bi-stream 交换凭据，验证 `network`、`node == remote_id`、
  `issuer ∈ controller_keys`、签名、`not_after`、`revision`；失败即关闭连接。
- **撤销**：`RevokeMember`/`DenyAdmission` 递增 revision 并写 tombstone；member 在
  下一个快照（≤10s）主动断连并丢弃 grant/LSA；旧凭据因 revision 回滚被拒绝。
- **授权解耦**：grant 可单独更新（`/v1/members/{node}/grants`），不再需要 revoke + 重新审批。
- **认证边界变化**：`controller` 模式不再接受任何 PSK 连接（fail-closed）；`none`
  仅保留给隔离实验，且 discovery 需 `allow_unauthenticated_discovery`。

验证（全部本地，无云主机）：`cargo test --workspace` 覆盖凭据签名/篡改/过期/跨网络/
revision 回滚、controller 预注册与审批签发、HTTP enroll 落盘、撤销丢 grant、
以及真实 iroh 双端点凭据握手（无凭据节点被拒绝）。脚本层同步改为预注册或
enroll+approve 流程。

