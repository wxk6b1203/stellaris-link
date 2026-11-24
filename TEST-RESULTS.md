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
cargo clippy -p stellaris-types -p stellaris-agent --all-targets -- -D warnings  ✅
cargo test --workspace                     118 passed
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

未验证：真实三地用 TOML 复跑滚动重启（当前无测试主机）；WAN 丢包/抖动下的选举稳定性。

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

### 3.10 >4MiB snapshot 跨 WAN：传输/安装通过，中断续传部分通过

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

未完成/未验证：

- 限速 + 中断之后"续传到完成"没有在 90s 窗口内看到；随后一次复测被编排脚本
  自身 `pkill` 误杀和 ctrl3 未进入 snapshot 路径打断，因此不能写成通过。
- 60s transfer TTL 与 2mbit 级慢链路是否冲突，需要单独实验（这正是
  [FOLLOWUP.md](FOLLOWUP.md) 里"transfer TTL 与滚动重启窗口协调"那条）。

### 3.11 仍未验证

- snapshot 传输中断后 **续传到完成**（§3.10 只验证了部分数据和全速安装）
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

仍未验证/未实现：

- 真正 multipath（双 direct 同时承载、RTT/丢包调度、双 relay）
- 应用层 fragment reassembly
- agent 客户端/整集群滚动重启后的 snapshot 续传
- 动态 Raft membership
- Docker 双容器网络/CI
- macOS/Windows NAT
- 大规模/长时间 soak
