# Relay 故障切换规划（2026-11-26）

> 状态：**规划/TODO，未实施**。当前仍是“旧连接关闭后按 relay 列表重连”，
> 实测约 60s；`endpoint_fails_over_to_the_second_relay...` 测试目前会失败。
> 本文先把方案、依赖和验收标准固定下来；是否投入 multipath 取决于 §5 的 spike。

关联：[AUDIT.md](AUDIT.md) §7.3、[FOLLOWUP.md](FOLLOWUP.md)、[TEST-RESULTS.md](TEST-RESULTS.md)、[PROTOCOL.md](PROTOCOL.md)。

---

## 1. 目标与非目标

### 目标

- relay 单点故障后，**数据面恢复 p95 < 5s**（第一阶段）；条件成熟后 **< 1s**。
- 支持每个 peer 配置/发现多个 relay；不再固定从死 relay 开始重连。
- relay 故障检测不依赖 QUIC 默认 30s idle timeout。
- 失败可观测：当前 relay、路径 RTT/丢包、切换次数、切换耗时。
- 不改变现有安全模型：凭据、LSA 签名、anti-spoof、node key 绑定都不变。

### 非目标（本轮）

- 不做 relay 服务端自研；直接部署 `iroh-relay`。
- 不承诺“切换零丢包”；UDP 数据面在切换瞬间允许个位数丢包，TCP 靠重传恢复。
- 不改变 overlay IP / 凭据语义。

---

## 2. 当前实现与根因

- `transport.rs` 每个 peer 只有一条 `Connection`（`conns: NodeId → Connection`）。
- relay 候选 = `peer.relay_url` + `transport.relay_urls`；重连时按顺序尝试。
- 没有 relay 健康探测；relay 挂掉只能等 QUIC idle timeout（默认 30s）。
- 重连循环每次 2s，成功后重新握手；旧连接关闭前数据面持续丢包。
- iroh 1.5 已有多路径原语（`max_concurrent_multipath_paths`、`PathEvent`、
  `Connection::paths`），但当前代码没有显式建立多条 relay 路径；iroh 也没有
  公开“手动添加任意 relay path”的 API，需 spike 验证。

**为什么是 ~60s**：检测（≈30s idle）+ 重连间隔（2s）+ 从死 relay 开始的
connect 超时/重试 + 重新握手。

---

## 3. 方案选项

| 方案 | 机制 | 预期恢复 | 工期 | 风险 |
|---|---|---|---|---|
| A. 快速检测 | relay 健康探测 + 更短 path idle/keepalive | 30s → 1–3s | 1–2 天 | 误判 |
| B. 并行竞速 | 同时连所有健康 relay + direct，首个成功即用；候选轮换 | 60s → 3–5s | 2–4 天 | 仅对新连接有效 |
| C. 热备双连接 | 每 peer 主/备两条连接，不同 relay，备用只探活 | < 1s | 1–1.5 周 | 双份状态/探测流量 |
| D. QUIC multipath | 同一连接保持多条路径，路径死亡自动迁移 | 亚秒级 | 2–4 周 | 依赖 iroh/noq 成熟度 |
| E. Relay 舰队 | 多地域 relay + 就近/健康排序 + controller 下发 | 降低故障域 | 1–2 周（运维） | 容量/成本 |

> A+B 不依赖 multipath，可先做；C/D 需要先做 §5 的 spike。
> “多 relay”不等于“同时承载”：B 是建连竞速，C 是一条闲置，D 才是真多路径。

---

## 4. 推荐路线

### Phase 0：基线与可观测性（1–2 天）

- 修复/重写 `endpoint_fails_over_to_the_second_relay...`，让它稳定复现。
- 记录时间线：relay 死亡 → 检测 → 选路 → 握手 → 首个数据包。
- 增加指标：`relay_active{peer}`、`relay_switch_total`、`relay_switch_seconds`、
  `relay_path_rtt_ms`、`relay_path_lost_packets`。
- 验收：脚本能在本地 3 个 `iroh-relay` 上量化 60s 基线。

### Phase 1：快速检测 + 并行竞速（3–5 天）

- relay 健康探测 1s/次，连续 3 次失败标记 down；恢复后重新入池。
- 连接时对所有健康 relay + direct 并行竞速（250ms stagger），首个成功即取消其他。
- 重连候选轮换，不再固定从死 relay 开始。
- relay 优雅关闭时 close/drain，立即切换。
- 验收：kill 当前 relay，**新连接 p95 < 5s**；TCP 吞吐恢复 < 10s；控制流不丢凭据。

### Phase 2：热备或 multipath（1–2 周，取决于 spike）

1. 若 iroh 能稳定建立两条 relay 路径并自动迁移 → 走 D 轻量版。
2. 否则做 C：主/备双连接，主失败切 `conns` 指针；备用只跑心跳。
3. 处理不同 relay 的 PMTU 差异（见 NAT 测试的 MTU 抖动）、发送缓冲/乱序、
   anti-spoof 单份 grant。
- 验收：切换 **p95 < 1s**，连续 ping 丢包 ≤ 个位数，24h soak 无泄漏。

### Phase 3：Relay 舰队（可与 1/2 并行）

- 部署 3+ `iroh-relay`（不同地域/运营商），TLS + 健康接口。
- controller 在 manifest/LSA 下发 relay 列表；agent 按 RTT/健康排序。
- 容量按“所有 NAT 节点都走 relay”的最坏情况预留；监控带宽/连接数/错误率。

---

## 5. iroh multipath spike（先做，1–2 天，时间盒）

在投入 C/D 前必须回答：

1. 同一 QUIC 连接能否同时建立 **两条 relay 路径**？还是只把多个 relay 当地址候选？
2. 应用层有没有 API 主动添加/切换 relay path？目前只看到只读的
   `Connection::paths()` 和 `PathEvent`，没有 `add_path/set_path`。
3. `PathEvent::Closed` 后 noq 是否会自动选另一条健康路径？切换耗时多少？
4. 两个 relay 的路径 MTU 不同时，`max_datagram_size`/TUN MTU 如何变化？
5. relay 服务端（`iroh-relay`）是否支持 multipath 的连接 ID/路由？
6. 是否存在“多条路径同时发送”的调度器，还是只有故障切换？

**退出标准**：

- 能写一个本地测试：两个 `iroh-relay`，一条连接，kill 一条，观察是否
  < 1s 继续传输且 `PathEvent` 有记录。
- 若答案是否/不稳定：不做 D，Phase 2 改做 C（双连接热备），并在文档记录原因。
- 若 iroh 版本升级后 API 变化，重新评估。

### 5.1 2026-11-26 spike 结果（本机 10.0.10.42，两个本地 iroh-relay）

测试：`cargo test -p stellaris-agent --lib multipath_spike_two_relays -- --ignored --nocapture`
（测试代码保留在 `transport.rs`，手动运行；同一台主机，先阻断 IPv4/IPv6 direct，仅留 relay）。

| 场景 | 观察 |
|---|---|
| 两个 relay 地址参与 `EndpointAddr` | 建立 **1 条 relay 路径**，没有第二条 relay 路径 |
| 允许 direct | `paths=2`：一条 relay + 一条 direct，direct 被选中 |
| 阻断 direct（IPv4+IPv6） | `paths=1`，只有一条 relay 路径 |
| kill 当前 relay | 测试里 `Server::shutdown()` 后路径仍在（测试装置未能真正断流）；不能作为产品 failover 证据 |
| API | `Connection::paths()` / `PathEvent` 只读；没有 `add_path`/`set_path`；多 relay 只是建连候选 |

**结论**：

- iroh 1.5 的 multipath 面向 **direct/NAT 地址**，不是“多条 relay 同时承载”。
- 应用层无法把第二个 relay 加成同一连接的路径；relay 故障仍需要重新建连。
- **D（真 relay multipath）暂不可行**，除非上游提供 API/实现；Phase 2 采用 **C（主/备双连接）**。
- 现有 relay failover 测试失败的另一原因是 `iroh_relay::Server::shutdown()` 不能可靠切断
  已建立的 relay 会话；Phase 0 改用 iptables/进程 kill 模拟真实故障。
- TODO 更新：spike 完成；决策 C；Phase 2 按 C 设计。

---

## 6. 测试矩阵

| 场景 | 方法 | 指标 |
|---|---|---|
| 单 relay 进程被杀 | 本地 2 relay，kill active | 中断时长、丢包数 |
| relay 优雅 drain | 发送 close/GOAWAY | 是否 0 丢包切换 |
| relay 半死（能连不转发） | iptables/代理丢包 | 检测时间、误判率 |
| 弱网 | 100ms RTT + 5% 丢包 | 切换稳定性 |
| 全部 relay 挂 | 关闭所有 relay | 明确报错/恢复 |
| 真实 NAT | NAT 主机 + 2 relay，阻断 direct | ping/TCP 恢复时间 |
| 长时间 | 24h relay 反复重启 | 内存/连接泄漏 |

验收基线：Phase 1 p95 < 5s；Phase 2 p95 < 1s；切换丢包 ≤ 个位数；
控制面凭据/LSA 不重复入网。

---

## 7. 风险与未决

- **iroh multipath 成熟度未知**：这是最大不确定性；先 spike，不预设 D。
- 多 relay 同时承载可能增加带宽成本；热备只增加心跳流量。
- 不同 relay 的 MTU/拥塞控制差异，可能造成切换后短时吞吐下降。
- 双连接会带来双份 `Connection` 状态，需要谨慎处理 grant/anti-spoof 的唯一性。
- relay 仍能观察流量元数据（看不到载荷）；舰队需自建/可信运营。
- 现有 relay failover 测试失败本身是 Phase 0 的 blocker。

---

## 8. TODO

- [ ] Phase 0：稳定复现 relay failover 测试（用 iptables/进程 kill，不用 Server::shutdown），记录 60s 时间线
- [ ] Phase 0：relay/路径指标（active、switch_total、switch_seconds、rtt、lost）
- [ ] Phase 1：relay 健康探测（1s/3 次失败）与恢复
- [ ] Phase 1：并行竞速 + 候选轮换 + 优雅 drain
- [x] Phase 1：2 relay 故障测试，active link 关闭/relay kill 可切换（200ms 采样 0 丢包）
- [x] Spike：iroh multipath 双 relay 路径/自动迁移/MTU（2026-11-26 完成，结论见 §5.1）
- [x] 决策：C（双连接热备）；D 需要上游 multipath API（记录于 §5.1）
- [x] Phase 2（初版）：双 endpoint + 双 link 热备；本地/真实主机 failover 验证（2026-11-26）
- [ ] Phase 2（增强）：heartbeat 降到亚秒级、relay 舰队与容量监控
- [ ] Phase 3：3+ relay 舰队、controller 下发、监控/容量
- [ ] 真实 NAT 主机 + relay 故障回归，更新 TEST-RESULTS

---

## 9. 实现状态（2026-11-26，双连接热备初版）

已实现：

- `transport.relay_urls` 至少 2 个时，创建**两个 iroh endpoint**（同一 NodeId/secret，
  分别只绑定一个 relay），从而强制每条 QUIC 连接走不同 relay；只用一个 endpoint 时
  iroh 可能让两条连接选到同一个 relay。
- 每个 peer 两条 link（Primary/Standby）：数值较小的 NodeId 负责主动拨号，另一侧只
  接受，避免双方互拨产生重复连接后被角色去重逻辑互相关闭。
- 数据只走 active link；发送失败时立即尝试另一条并切换 active。
- 每条 link 独立 `link_state` 控制流/心跳；心跳 1s、超时 4s，超时通过
  `Transport::close_link` 关闭不健康 link，连接管理器立即提升另一条。
- grant 只在最后一条 link 关闭时 drop；revoke 关闭全部 link。
- `PeerState.path_addr` 现在会显示 relay URL（例如 `http://host:5891/`），便于观测。

验收/已知限制：

- 本地确定性测试 `dual_relay_links_fail_over_when_the_active_connection_closes`：
  两条 relay link 建立，关闭 active 后 standby 接管；通过。
- 真实三机（深圳 relay 主机 + 两台 agent，阻断 direct IPv4/IPv6）：
  两个 link 分别走 5890/5891；kill 当前 relay 后 active 切到另一 relay，
  200ms 采样下 ping 无丢失（send fallback 立即切换），heartbeat 随后清理死链。
- **检测不是亚秒级**：控制面 heartbeat 4s 超时；数据面发送失败可立即切换。
- 仍是 active/standby，不做带宽聚合；真 multipath 仍需上游支持。
- 需要为 standby endpoint 预留 `listen_port + 1`；端口范围要规划。
