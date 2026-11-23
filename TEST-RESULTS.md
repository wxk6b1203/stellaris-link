# 真实环境测试记录（2026-11-23）

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

---

## 2. 单元/集成

```text
cargo fmt --check                          ✅
cargo clippy --all-targets -- -D warnings  ✅
cargo test                                 112 passed
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

### 3.6 仍未验证

- snapshot 传输中断后 agent/controller **重启续传**
- 磁盘慢 IO / fsync 失败注入
- 跨地域大 snapshot
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
