# P1/P2 审计清单与处置决定（2026-11-27，第二轮）

> 来源：5 个子代理的只读审计（安全 `S`、Raft/控制面 `R`、传输 `T`、数据面 `D`、
> 测试证据 `E`）+ 本轮主 agent 复核与真实环境验证。
> 证据等级：`真实主机` > `本机进程/netns` > `单测` > `代码路径`（静态）。
> 本轮范围决定：**单 controller（非 Raft）继续受支持，但标记 deprecated + 启动告警**；
> 其 generation/seed 持久化按 P2 处理，不再作为本轮 P1 门槛。
>
> 状态：`已修` = 本轮或上一轮已改代码并有测试/真实环境证据；`部分` = 关键路径已修但
> 仍有明确边界；`开放` = 未修；`弃用` = 随非 Raft deprecated 一起关闭；`误报` = 复核后
> 不成立。

---

## 0. 分级标准（本轮统一口径）

- **P1**：已认证成员可破坏他人/全网安全控制；或受支持的主路径在常见部署下不可用；
  或数据面正确性在真实异构网络中会静默丢包。
- **P2**：边缘条件、可观测性、性能、文档/测试证据、legacy 模式，或修复成本远高于收益。
- **P0**：未认证远程接管/全集群沦陷。本轮未发现仍开放的 P0。

---

## 1. P1 清单

| ID | 问题 | 来源 | 状态 | 处置/证据 |
|---|---|---|---|---|
| P1-01 | HTTP `/v1/lsa` 完全不验签，持共享 secret 的成员可伪造他人 origin/前缀 | S-6 | **已修** | 默认要求 `{lsa,signature}` 的 Ed25519；`control.allow_unsigned_lsa` 仅显式开启；agent HTTP 客户端自动签名；单测 `http_lsa_requires_a_valid_signature` |
| P1-02 | 撤销 tombstone 不进快照/清单，revision floor 只在内存 | S-1/T-7 | **已修** | Snapshot/Manifest 增加签名 `revoked[{node,revision}]`；成员持久化 `control-state.json`；`apply_members` 对 revoked 设 floor+close；单测 `revoked_snapshot_fences_a_node_never_seen_before`、`revoked_member_can_be_reinstated_explicitly` |
| P1-03 | manifest 无 generation/epoch 单调校验，可重放旧成员表 | S-3 | **已修** | 成员持久化 manifest floor；`manifest_floor_allows` 拒绝旧 `(epoch,generation)`；单测 `revisions_and_control_floors_survive_restart` |
| P1-04 | 认证前按 64MiB 长度预分配控制帧 | T-6 | **已修** | `read_frame_limited` + `MAX_REQUEST_FRAME=8MiB`；服务端请求路径使用 |
| P1-05 | 最后一条 link 关闭与新建 link 竞态，旧清理会清掉新 link 的 grant/connected | T-1 | **已修** | 清理移入 `remove_conn` 的连接锁临界区；新增逻辑注释 |
| P1-06 | 多跳 LSA 授权依赖直连 credential grant，非全网状拓扑丢 LSA | T-4 | **已修** | `apply_members` 用签名成员表安装 `install_snapshot_grant`，A 可授权 B 洪泛来的 C LSA |
| P1-07 | LSA `links` 无反向校验，成员可广告虚假 0 成本链路做黑洞 | T-5 | **已修** | SPF 只使用双向 link（`link_is_bidirectional`）；单测 `one_way_link_claim_is_not_used_by_spf` |
| P1-08 | 已建立连接不再校验 credential `not_after`，controller 不可达时永不过期 | S-1 | **已修** | Grant 记录 `expires_at`；30s 周期 `expire_grants` 并触发重认证；单测 `expired_handshake_grant_is_dropped` |
| P1-09 | revoke 未知 NodeId 也写 tombstone，且被撤销节点无法重新准入 | R-3 | **已修** | revoke 未知返回 404；新增 admin `POST /v1/members/{node}/reinstate`；单测 `revoked_member_can_be_reinstated_explicitly` |
| P1-10 | 审批制 Raft controller 启动时 `strict_membership=false`，LSA 授权终生失效 | R-0/S-5 | **已修**（上一轮） | 有 members/revoked/pending 时强制 model 授权；`test-controller-approval-auth.sh` |
| P1-11 | HTTP ACK 比较 `ControllerState.epoch`（恒 0），epoch 发布后全部 409 | R-1 | **已修**（上一轮） | HTTP `/v1/ack` 统一 `record_ack_current`；`test-controller-ack.sh` |
| P1-12 | ACK 命令递增 generation，形成每 2s 全量快照 + Raft 写死循环 | R-2 | **已修**（上一轮） | ACK 不参与 generation；单测 + `test-controller-ack.sh`（idle gen 3→3） |
| P1-13 | IPAM 改址不迁移租约，旧租约到期删除在线成员 | D-3 | **已修**（上一轮） | UpsertMember 迁移/释放旧租约；ExpireLeases 守卫；2 个模型单测 |
| P1-14 | 双 relay 任一不可达 `online().await` 永久挂起启动 | T-0 | **已修**（上一轮） | 10s 超时后继续启动；不可达 relay 探针 11s 就绪 |
| P1-15 | revision bump 复用 `close_peer` 把合法成员加入 blocked | T-2 | **已修**（上一轮） | 拆出 `reconnect_peer`；单测 + IPAM reassign 真实测试 |
| P1-16 | 配置 relay 后丢弃 `peer.addrs`，direct 永不尝试 | T-8 | **已修**（上一轮） | 仅 dual-endpoint 模式强制 pinned relay；roaming 初始 direct |
| P1-17 | `/v1/peers` path/rtt/mtu 建连后不再刷新 | T-7 | **已修**（上一轮） | 2s path watcher；真实 roaming `direct→relay` 可观测 |
| P1-18 | 中转不按下一跳 MTU 检查/回 PTB，异构 MTU 静默丢包 | D-2 | **已修** | transit 超限时向上一跳回 ICMP PTB；单测 `transit_too_big_returns_ptb_to_previous_hop` |
| P1-19 | IPv6 underlay <1296B 时 PTB 不可达、MSS 被 clamp 进黑洞 | D-1 | **部分** | `path_mtu` 不再锁 1280，MSS/PTB 使用真实容量；单测 `ipv6_path_mtu_is_not_pinned_to_1280`；TUN 设备 MTU/端到端仍待测（P2 边界） |
| P1-20 | FIB 选中失联下一跳，ECMP 槽黑洞 | D-18 | **已修**（P2 顺带） | `FibEntry::select_where` + dataplane 只选 connected peer |
| P1-21 | `commit_command` 丢弃状态机 apply 结果，多个写端点失败仍 200 | R-4 | **已修** | `CommandResult.changed` + `commit_command` 对 no-op 返回 409；create/update/delete pool、lease、reserve、reassign、approve/deny 等统一生效 |
| P1-22 | IPAM 校验只在 handler，状态机可绕过（duplicate overlay/越界/exclude） | R-5 | **已修（入口层）** | `validate_overlay` 增加 CIDR/range/exclude/quarantine；enroll、approve、reinstate、grants、reserve 均复用；状态机 `overlay_taken` 仍是最后一道防线 |
| P1-23 | member 只配 follower URL 时 snapshot/LSA/enroll 永久 503 | R-6 | **已修** | 新增 `control.failover_urls`；客户端在 503/连接失败时轮换 endpoint；`scripts/test-controller-failover.sh` 真实 3-controller 单机测试 follower→leader 通过 |
| P1-24 | Raft 日志 rotate/reset/legacy 迁移崩溃窗口 | R-7 | **开放** | 需目录 fsync/原子切换 + kill -9 注入；本轮未改 |
| P1-25 | LSA 授权在 client_write 前，revoke 与在途 LSA 竞争 | R-8 | **部分** | `ControllerModel::apply(ApplyLsa)` 拒绝已 revoked origin；授权与提交仍非同一原子步骤 |
| P1-26 | Raft 初始状态来自各副本本地 config/legacy 文件，副本可分歧 | R-9 | **开放** | 架构级：bootstrap 种子应走 leader 提交的复制命令 |
| P1-27 | control endpoint 与 data endpoint 同 NodeId/同 relay，relay 可能把一路置 inactive | T-3 | **已修（设计）** | 数据 endpoint 同时注册 DATA/CONTROL ALPN；`control.endpoint_id` 在有 transport 时直接复用该 endpoint，不再创建同 NodeId 的第二 endpoint；accept 侧按 ALPN 过滤；`test-real-iroh-raft.sh` 通过。relay-only 真实链路仍建议补一条专项测试 |
| P1-28 | 只有 NodeId 较小一侧拨号，单边配置/出站故障时不连接 | T-17 | **开放** | 静态 mesh rogue 测试约 50% 失败；需要连接代际/双向协商 |
| P1-29 | 非 Raft controller 重启 generation 归零、config seed 复活 revoked | S-2/S-4 | **弃用** | 单 controller 标记 deprecated，启动告警；generation/seed 持久化列为 P2 |
| P1-30 | `admin_secret` 未配置时回落 member secret | S-9 | **部分** | 启动时打 warn；完全分权仍要求部署配置 `admin_secret`（列为 P2） |

---

## 2. P2 清单

### 2.1 安全 / 成员 / 配置

| ID | 问题 | 来源 | 状态 |
|---|---|---|---|
| P2-01 | 启动加载 `credential.json` 不验签/不查过期，bootstrap 检查被它满足 | S-1 | 开放 |
| P2-02 | `controller_keys` 大小写敏感字符串比较，大写 hex 导致快照全拒 | S-2 | 开放 |
| P2-03 | 静态 overlay 不校验 CIDR/冲突（enroll/grants 两条路径） | S-3 | 部分（CIDR/update_grants 已加） |
| P2-04 | `admin_secret` 缺省回落 member secret | S-4 | 开放（P1-30） |
| P2-05 | 非 Raft 快照 epoch 用启动副本，revoke bump 不反映 | S-5 | 弃用 |
| P2-06 | 撤销后本地 LSA DB 不清理，旧路由最多残留 30s | S-6 | 开放 |
| P2-07 | 被撤销节点无法重新审批（reinstate 已补） | S-7 | 已修（P1-09） |
| P2-08 | HMAC 快照共享 secret 即签发权 + 非恒时比较 | S-8 | 开放（legacy 模式） |
| P2-09 | enroll 签名不覆盖 auto/pool/addrs，无 nonce/时间戳 | S-9 | 开放 |
| P2-10 | CLI 离线签发临时文件非 O_EXCL/O_NOFOLLOW | S-10 | 开放 |
| P2-11 | LSA 签名载荷未绑定 network_id | S 附注 | 开放 |
| P2-12 | discovery UDP/mDNS 无认证/无上限/无淘汰 | T-12 | 开放 |
| P2-13 | 共享 secret 下 admin/member 权限未真正分离 | S-4/R | 开放 |

### 2.2 控制面 / Raft / 持久化

| ID | 问题 | 来源 | 状态 |
|---|---|---|---|
| P2-14 | `Ack` 可回退；DenyAdmission 对已有成员无效且 generation 不变 | R-1 | 开放 |
| P2-15 | 非 Raft LSA TTL 忽略配置、legacy members 自授权前缀、无 leader fence | R-2 | 弃用 |
| P2-16 | release/reserve/delete_pool 破坏 member↔lease 不变量 | R-3 | 部分（lease 校验已加） |
| P2-17 | `AllocStrategy` 是死配置；IPv6 探测可能 4096 次失败 | R-4/D-24 | 开放 |
| P2-18 | snapshot transfer 只按 total+checksum 去重、先删后验、512MB 预分配、阻塞 IO | R-5 | 开放 |
| P2-19 | `install_snapshot` 先改内存后写盘，失败不回滚 | R-6 | 开放 |
| P2-20 | 动态 membership 吞 add_learner 错误、无 CAS、无 leader hint | R-7 | 开放 |
| P2-21 | `/v1/status.routes` 不含 controller 路由；读端点不 linearize；member 可见 admin 元数据 | R-8 | 开放 |
| P2-22 | 非 Raft command log 半行粘连、members/lsas/acks 无 fsync | R-9 | 弃用 |
| P2-23 | 只配 raft client cert 时静默退回 HTTP Raft；raft_bind 临时端口；pending admission 无上限 | R-10 | 开放 |
| P2-24 | `/readyz` 对失去 quorum 的旧 leader 仍返回 ready | R-11 | 开放 |
| P2-25 | 非 Raft controller 无 quorum/durable generation | S-2 | 弃用（启动告警） |

### 2.3 传输 / 链路状态

| ID | 问题 | 来源 | 状态 |
|---|---|---|---|
| P2-26 | LSA 签名缓存按 origin 无条件覆盖，旧 seq 签名可污染 | T-1 | 开放 |
| P2-27 | LSA 无时间戳/过期字段，30s 后可重放复活 | T-2 | 开放 |
| P2-28 | 全量 LSA snapshot 先写后 spawn reader，可能流控死锁 | T-3 | 开放 |
| P2-29 | link-state reader 出错静默，坏帧后单向失联 | T-4 | 开放 |
| P2-30 | 双 relay 快速清理依赖 `routing.link_state=true` | T-5 | 开放 |
| P2-31 | send 不尝试更大 MTU 的 standby link | T-6 | 开放 |
| P2-32 | accept loop 串行握手/认证，可被慢连接 HOL 阻塞 | T-9 | 开放 |
| P2-33 | blocked 检查 TOCTOU（认证后/insert 前不复检） | T-10 | 部分（连接锁清理已加） |
| P2-34 | `install_grant` 无 revision 单调，双 link 并发旧凭据可覆盖 | T-11 | 开放 |
| P2-35 | 动态 peer 无上限/无 TTL/无原子 add_peer | T-12 | 开放 |
| P2-36 | inbound peer 未写入 registry，LSA/API 不显示单向连接 | T-13 | 开放 |
| P2-37 | 快照过滤未连接下一跳后不再补装（已改为 FIB 过滤，保路由） | T-15 | 已修（P1-20 顺带） |
| P2-38 | 控制客户端无 HTTP/iroh 超时，controller 半死卡住续签 | T-16 | 开放 |
| P2-39 | LSA seq 用墙钟，时钟回拨被旧 LSA 挡住；peer.relay_url 未预解析；transport 无 shutdown | T-17 | 开放 |
| P2-40 | 流控/链路心跳参数文档写 2s/7s，代码 1s/4s | T-文档 | 开放（文档） |

### 2.4 数据面 / IPAM / 路由

| ID | 问题 | 来源 | 状态 |
|---|---|---|---|
| P2-41 | 重组表全局 256 条，无 per-peer/字节配额，单成员可占满 | D-1 | 开放 |
| P2-42 | 分片在 peer/anti-spoof 校验前进入重组表 | D-2 | 开放 |
| P2-43 | IPv4 重组校验和只算 20 字节，带 options 重组包被内核丢 | D-3 | 开放 |
| P2-44 | IPv4 重组 total_length 截断/越界载荷 | D-4 | 开放 |
| P2-45 | IPv6 只拒绝同 offset，不拒绝部分重叠/非 8 字节对齐 | D-5 | 开放 |
| P2-46 | IPv6 扩展头在 Fragment 前时绕过应用层重组 | D-6 | 开放 |
| P2-47 | ACL reject 引用最后一个分片而非重组报文，ICMP 无法关联 | D-7 | 开放 |
| P2-48 | fragment_cache 无 TTL，满 4096 整表清空 | D-8 | 开放 |
| P2-49 | MTU monitor 初值/60s 低通窗口/无 datagram_too_large 指标 | D-9/D-10 | 开放 |
| P2-50 | peer MTU 语义混用（max_datagram vs path MTU） | D-11 | 开放 |
| P2-51 | ICMP PTB 对全部 ICMP 不回，`is_icmp_error` 固定偏移 | D-12 | 开放 |
| P2-52 | `effective_mtu` 32B 余量与 `path_mtu` 不一致 | D-13 | 部分（path_mtu 已改） |
| P2-53 | 路由回收只在 Drop；macOS 安装失败无日志 | D-14 | 开放 |
| P2-54 | 逐前缀 fork `ip route`，30s 全量重算 | D-15 | 开放 |
| P2-55 | 替换外部路由后不恢复原路由 | D-16 | 开放 |
| P2-56 | 路由 owner 用字符串子串匹配 | D-17 | 开放 |
| P2-57 | peer 掉线不撤路由（FIB 已过滤，路由仍保留） | D-18 | 部分（P1-20） |
| P2-58 | 运行期 policy 更新后 per-class caps 仍用启动快照 | D-19 | 开放 |
| P2-59 | QoS 分类依赖端口，非首片 DSCP 不一致 | D-20 | 开放 |
| P2-60 | 出入/中转共用一个 token bucket | D-21 | 开放 |
| P2-61 | 计数器缺字节/route_miss/ttl/datagram_too_large/per-class | D-22 | 开放 |
| P2-62 | `burst_bytes < 包长` 时该类永久 100% 丢包 | D-23 | 开放 |
| P2-63 | `AllocStrategy` 死配置；IPv4 线性扫描 O(n²) | D-24/D-26 | 开放 |
| P2-64 | `UpdatePool` 可把 CIDR 改到不含现有租约 | D-25 | 开放 |
| P2-65 | `PathHint`/`set_path_hint` no-op | D-27 | 开放 |
| P2-66 | `routes(RouteView::Fib)` 恒空 | D-28 | 开放 |
| P2-67 | 每次路由变更全量克隆 intents + 重建 FIB | D-29 | 开放 |
| P2-68 | `Drain` 忽略 grace_secs | D-30 | 开放 |
| P2-69 | ARCHITECTURE/GAPS 与实际实现/测试相反 | D-31/D-32 | 开放（文档） |

### 2.5 测试证据 / 脚本

| ID | 问题 | 来源 | 状态 |
|---|---|---|---|
| P2-70 | `test-netns-pmtud-blackhole.sh` 零断言，硬编码已释放主机 | E-A1 | 开放 |
| P2-71 | `test-raft-persistence.sh` 只打印不断言 | E-A2 | 已修（上一轮） |
| P2-72 | `test-real-dualnic-multipath.sh` RTT/丢包不切换无断言，SKIP 仍 OK | E-A3 | 开放 |
| P2-73 | `test-real-wan-loss-ha.sh` 无 set -e/pipefail，未验证丢包注入 | E-A4 | 开放 |
| P2-74 | `test-linux-netns-ipv6.sh` 三处 `ping || true` | E-A5 | 开放 |
| P2-75 | CI debug 构建 vs release 路径、TLS/Docker 路径错配 | E-A6 | 已修（上一轮） |
| P2-76 | 3host HA 只从 leader 断言，无逐副本校验；mTLS 无负向 | E-B | 开放 |
| P2-77 | `test-real-iroh-raft.sh` member 进程不在 PIDS，失败泄漏 | E-B | 开放 |
| P2-78 | `test-real-static-mesh.sh` rogue 断言死代码/无第 3 项验证 | E-B | 开放（部分与 P1-28 相关） |
| P2-79 | `test-real-ipam.sh` 假定分配顺序 | E-B | 开放 |
| P2-80 | 多个脚本 `ping -c 2` 只看退出码，非 0% loss 断言 | E-B | 开放 |
| P2-81 | PMTUD 三个脚本拓扑不可复现/`-M dont` 语义误读 | E-A/E-C | 开放（`-M dont` 已复核为“不置 DF”，不是 bug） |
| P2-82 | 脚本端口/目录冲突（5801/5900/47001/opt 路径） | E-C | 开放 |
| P2-83 | 3host overlay/IPv6 不做 loss/path/connected 断言 | E-B | 开放 |

> 说明：`-M dont` 在 iputils 里是“不设置 DF”，因此原脚本的 2000B ping 确实会
> 本地分片，evidence-review 的“DF 假绿”判断是误报；本轮已实测 0% loss。

---

## 3. 本轮修复的横切设计

1. **签名/可信输入统一**：HTTP LSA 与 iroh LSA 都验 Ed25519；Snapshot/Manifest 的
   签名载荷包含 `revoked` 和成员 revision；成员端所有 controller 输入先验签再应用。
2. **单调 floor 持久化**：`control-state.json` 保存每节点 revision、snapshot floor、
   manifest floor；重启后旧快照/旧 manifest/旧凭据不能复活。
3. **撤销闭环**：controller tombstone → 签名快照/清单 → 成员 floor+close →
   旧凭据 revision/expiry 双重拒绝 → 管理员显式 reinstate。
4. **多跳拓扑**：成员用 controller 签名成员表安装 grant；SPF 只信双向 link。
5. **MTU/转发**：FIB 只选 connected 下一跳；transit 超下一跳 MTU 回 PTB；
   IPv6 可用 MTU 不再被 1280 下限掩盖。
6. **测试**：新增/修复单测覆盖签名、撤销、floor、SPF、transit PTB、MTU、grant expiry、
   reinstate；真实 3 机测试见 §4。

---

## 4. 真实环境测试矩阵（新 3 台）

主机：`47.112.160.125`（10.0.0.99）、`47.112.188.27`（10.0.0.97）、
`120.77.233.189`（10.0.0.95），同 VPC 10.0.0.0/24，公网 5689–6000 开放。

| 测试 | 结果 |
|---|---|
| `cargo test --workspace` | 220 passed / 0 failed / 2 ignored |
| 3 机 controller HA + mTLS + failover | **通过**（leader 1→2，snapshot/failover 正常；test-real-3host-ha.sh） |
| 3 机 IPv4 TUN overlay | **通过**（3/3、1000B/2000B 各 3/3，0% loss） |
| 3 机 IPv6 TUN overlay | **通过**（1200B 3/3，0% loss） |
| 3 机 IPAM + 热改址 + 撤销 | **通过**（.1→.9 热切换、旧地址 quarantine、撤销后剩余成员互通；test-real-ipam.sh） |
| HTTP LSA 签名 | **单测通过**（未签名 403、签名 200、篡改 403）；真实 IPAM 中 agent 走默认拒绝未签名配置并通过 |
| 审批制 LSA 授权 | **通过**（rogue/越权 403，自身 overlay 200；test-controller-approval-auth.sh） |
| ACK epoch / idle generation | **通过**（正确 epoch 200、陈旧 409、idle gen 3→3；test-controller-ack.sh） |
| manifest/snapshot 重放 | **单测通过**（floor 持久化、旧 epoch/generation 拒绝） |
| follower URL failover | **通过**（member 初始指向 follower，轮换到 leader；test-controller-failover.sh） |
| iroh control 与 data 共用 endpoint | **通过**（test-real-iroh-raft.sh；不再创建同 NodeId 的第二 endpoint） |
| 撤销后旧凭据/新成员 | **单测通过**（revoked tombstone 对未见节点设 floor+close；reinstate 后恢复） |
| netns 套件 | **16/16 通过**（route-safety、acl-reject、reassembly、tun、3node、3node-controller、ipv6、nat44、nat66、mdns、discovery、raft-tls、raft-membership、iroh-large、persistence；3node-controller/ipv6 需 12–14s 收敛等待） |

---

## 5. 结论与下一轮

- 本轮把安全边界上最危险的 P1 闭环：HTTP LSA 签名、撤销持久化、manifest 重放、
  预认证帧上限、link 竞态、多跳授权、LSA 双向校验、凭据过期重检、reinstate、
  中转 PTB、FIB 过滤、非 Raft deprecated 告警；并把 `commit_command` 的 no-op
  统一改为 409、IPAM range/exclude/quarantine 校验放到所有入口。
- 真实 3 机与 netns 回归均通过；本轮新增 9 个单测/回归断言（HTTP LSA 签名、
  撤销 tombstone、control floor 持久化、reinstate、transit PTB、IPv6 path MTU、
  单边 link SPF、grant expiry、no-op 409、IPAM range/exclude）。
- 仍开放且建议优先：Raft 日志 rotate/reset 崩溃一致性、Raft 初始状态副本分歧、
  单边拨号规则、IPv6 <1296 端到端。
  （`commit_command` changed/409、IPAM 入口校验、follower URL failover 已补齐。）
- 非 Raft 按用户决定标记 deprecated，不再投入 P1 级修复；启动日志会明确告警。
