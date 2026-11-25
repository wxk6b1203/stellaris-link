# 能力与测试审计（2026-11-23，2026-11-24 更新）

> 关联：[AUDIT.md](AUDIT.md)（2026-11-24 静态审计，未实现/未验证/文档不一致的完整清单）、[README.md](README.md)、[PLAN.md](PLAN.md)、[PRIORITIES.md](PRIORITIES.md)、[OPENRAFT-HA.md](OPENRAFT-HA.md)、[TEST-RESULTS.md](TEST-RESULTS.md)

本文只记录**已验证**、**未验证**和**代码未实现**的内容，避免把设计/演示当成生产结论。

---

## 1. 本轮代码清理

### 已移除：旧 active-active fanout

- 删除 `control.urls` 多 controller 写 fanout 路径
- 删除 `control.controller_threshold` 阈值逻辑
- 删除 `scripts/demo-controller-ha.sh`
- 删除 `scripts/demo-controller-threshold.sh`
- member 只使用单个 `control.url`（可指向 LB/任一 controller）
- 旧配置出现非空 `control.urls` 或 `controller_threshold != 1` 会直接报错
- 单 controller + 3 members 的 `scripts/demo-controller-3node.sh` 已重新跑通

仍保留：

- 非 Raft 模式的 legacy controller 代码/JSON ACK，用于兼容路径
- 旧配置字段 `control.urls`、`control.controller_threshold` 仅作为拒绝入口，不再执行 fanout

---

## 2. 已验证

### 2.1 单元/集成测试

最近一次：

```text
cargo fmt --check                                          ✅
cargo clippy --all-targets -- -D warnings                  ✅
cargo test                                                 152 passed
```

覆盖：

- FIB/RIB/路由/持久化
- MeshHeader/IPv4/IPv6 fragment 解析
- ACL 首片判定、QoS/queue
- controller 签名/model/Raft storage
- Raft 3 节点/快照/磁盘只读
- relay 建连/failover
- per-class queue

### 2.2 真实物理三主机

三台同 VPC 云主机（私网 172.21.163.47/48/49）：

| 测试 | 结果 |
|---|---|
| 3 controller + mTLS + leader failover | ✅ |
| 真实物理 3 agent IPv4 overlay | ✅ |
| 1000-byte ping | 0% loss |
| 2000-byte ping through 1366-MTU TUN | 0% loss（分片转发 + 目的端内核重组） |
| 真实物理 3 agent IPv6 overlay | ✅ |
| 1200-byte IPv6 ping | 0% loss |
| direct → relay roaming（阻断 direct UDP） | ✅（至少一条路径切到 relay） |

脚本：

- `scripts/test-real-3host-ha.sh`
- `scripts/test-real-3host-overlay.sh`
- `scripts/test-real-3host-ipv6.sh`
- `scripts/test-real-3host-roaming.sh`

### 2.3 新一批主机（2026-11-23）

网络：

- 批1：私网 10.0.0.88/89/90，同 /24
- 批2：私网 192.168.0.161/162/163/164，同 /24；47.119.37.129 有 eth0/eth1 双网卡
- 批1↔批2 私网不通
- 公网 TCP 5689–6000 全部开放；用户打开 UDP 后，UDP 5689/5901/6000 也通
- Docker 可用，`docker pull alpine:latest` 成功
- 三台批1：2 vCPU/1.7 GiB/40 GB

新增通过：

| 测试 | 结果 |
|---|---|
| 批1 私网 3 controller + mTLS + failover | ✅ |
| 批1 私网 IPv4 overlay + 1000/2000 ping | ✅ 0% loss |
| 批1 私网 IPv6 overlay + 1200 ping | ✅ 0% loss |
| 批1 direct→relay roaming | ✅（一个 peer relay，一个仍 direct） |
| 批2 双网卡 direct path failover | ✅ `.162:5911` → `.164:5911` |
| 批1↔批2 公网 direct UDP | ✅ |
| 批1↔批2 公网 relay | ✅ |
| 深圳↔上海 公网 TUN overlay（25ms RTT） | ✅ 0% loss |
| 深圳↔上海 2000-byte 分片 ping | ✅ 0% loss |
| 深圳/上海 3 controller 公网 quorum + mTLS + failover | ✅ |
| Docker host-network + TUN（容器内 agent） | ✅ 手测 |

双网卡注意事项：

- `.162`/`.164` 同 /24，默认路由都走 eth0
- 需要 `arp_ignore=1`/`arp_announce=2` 和 source policy route（`from .164 table 164`）才能在 `.164` 上稳定工作
- 测试脚本已包含该设置和清理

脚本：

- `scripts/test-real-dualnic-multipath.sh`
- `scripts/test-real-crossbatch-direct.sh`
- `scripts/test-real-crossbatch-relay.sh`

### 2.4 成都 netns PMTUD + 黑洞实验

主机：47.109.58.88，4C/8G，Ubuntu 6.8。

拓扑：

```text
a --1500-- r1 --1400-- r2 --1300-- b
```

实测：

| 测试 | 结果 |
|---|---|
| agent underlay path MTU / TUN | 1224 / 1176 |
| 2000-byte overlay ping | 0% loss |
| 2 MiB TCP over overlay | 2,097,152 bytes |
| tracepath 逐跳 | pmtu 1400 → 1300 |
| 1450-byte DF | R1 回 PTB 1400 |
| 1378-byte DF | R2 回 PTB 1300 |
| R2 丢 PTB 黑洞 | 100% loss，无 1300 PTB |
| 恢复 PTB | 1300 PTB，1272-byte ping 通过 |

脚本：

- `scripts/test-netns-pmtud-lab.sh`

### 2.4.1 真实 agent 流量 PTB 黑洞

在 Chengdu netns 中把 r2→b 从 1300 降到 1100 并丢 PTB 15 秒：

```text
长连接 TCP: T8.4 13,959,168 bytes
黑洞期间: 不再增长
T32.4 恢复增长
GAPS [(6.4, 32.7)]
恢复后新 HTTP flow: new_http_ok=1
peer: connected=true path=direct mtu=1224 path_changes=1
```

结论：长 TCP 可恢复，但约 10–12 秒；iroh 不重连，只保持连接；未主动重建 underlay 路径。

脚本：`scripts/test-netns-pmtud-blackhole.sh`

### 2.5 Docker 与 PMTUD 现状

Docker：

- 7 台主机 Docker 29.10.0 可用
- `docker pull alpine:latest`、`debian:bookworm-slim` 成功
- 容器化 agent（`--network host --cap-add=NET_ADMIN --device /dev/net/tun` + 宿主二进制 + Debian slim）实测 TUN + 2000-byte ping 通过
- 标准 `docker/runtime.Dockerfile` 的 `apt-get` 在云主机上极慢/卡住，未完成镜像构建；Docker TUN 双容器脚本未复跑

PMTUD：

- 已修：peer MTU 未知时不再回退到 1100，使用配置 MTU
- 已加：源端 oversized DF 包的 PTB 合成（ICMP 类原包除外）+ TCP MSS clamp
- 已验证：peer path MTU 1162–1414、TUN MTU 自适应、手工抬高 TUN MTU 后 2 MiB TCP 传输成功
- 仍未验证：
  - agent 真实流量在 underlay PTB 黑洞下的重连/回退
  - IPv6 PTB/逐跳 MTU
  - 真实互联网路由器抓包（当前是 Linux netns 路由器）
- 缺口：源端 PTB 是本地合成；未做真实互联网黑洞探测

### 2.5 之前已验证（本轮未重复跑）

- macvlan 真实 LAN 3 controller + mTLS + partition recovery
- Raft 本机 3 节点 + TLS/mTLS
- Linux netns IPv6 TUN 双向
- NAT44 public exit + UDP mapping
- NAT66 public exit + UDP mapping
- Docker mDNS/bridge/macvlan
- Docker two-node TUN / subnet gateway

---

## 3. 未跑通/未验证

| 项目 | 状态 | 说明 |
|---|---|---|
| 强制 multipath | ⚠️ | 双网卡 failover 通过；`path_count=1`；100ms/20% loss 都不切换，只有硬阻断切换；两个 relay URL 仍只用一个 relay |
| 3/3 全路径 roaming | ⚠️ | 批1 最后一次一个 peer relay、一个 direct；脚本仍只断言一个 peer |
| 完整 PMTUD | ✅ | netns 1500/1400/1300 + tracepath + PTB 黑洞/恢复已跑通 |
| 应用层 fragment reassembly | ❌ | 2000-byte ping 依赖目的端 Linux 内核重组；agent 没有重组缓存 |
| 公网 NAT/安全组 | ⚠️ | 批1↔批2、深圳↔上海公网 direct/relay 已测；public exit NAT 云上未测 |
| 磁盘满/撕裂写 | ⚠️ | ENOSPC→503、撕裂 log 启动失败已验证；慢 IO/fsync 未注入 |
| snapshot 跨进程续传 | ✅ | 真实三地 5.57 MiB 分块传输；限速中断（保留 2097152 字节）→ 重启 → 续传安装完成 → 日志追平（gen 5402）；持续慢链路下 TTL 未验证 |
| 真实物理跨地域 | ✅ | 深圳↔上海 25 ms TUN overlay 已测 |
| Docker 测试复跑 | ⚠️ | Docker pull/容器内 agent 手测通过；标准 Dockerfile apt 构建未完成 |
| macOS NAT/pf、Windows | ❌ | 只有 Linux NAT |
| tracing/dashboard/打包 | ❌ | 未实现 |

---

## 4. 能力缺口

### 4.1 数据面

- **PMTUD**：IPv4/IPv6 netns 逐跳、PTB 黑洞/恢复、agent 真实流量黑洞均已测；真实互联网路由器抓包未做。
- **fragment reassembly**：只有解析、转发、首片 ACL；没有应用层重组。
- **multipath**：双网卡 failover 通过，但 `path_count=1`；RTT/loss 不切换，双 direct/双 relay 同时承载未实现。
- **NAT**：NAT44/66 公网 exit 已在 Linux netns 验证；NAT66 仅 Linux `ip6tables`，macOS 未实现。
- **队列/整形**：有 token bucket + 全局/per-priority/per-class queue depth/bytes；没有 DRR/公平调度/更细粒度 SLA。

### 4.2 已实现/已修复

- Raft 模式下 `/v1/status.generation` 改为从 `ControllerModel` 读取；复测 LSA/status 都为 generation 3。
- snapshot transfer 元数据/data.bin 落盘；controller HTTP 重启后按 offset 续传，单测 `snapshot_transfer_survives_http_restart` 通过。
- 磁盘满返回 503；撕裂 log 启动 fail-closed。

### 4.3 Controller HA

- **三地滚动重启已通过**：openraft 默认 150ms election timeout 对跨地域 vote RPC 太短；已把选举超时产品化为 `control.raft_election_timeout_ms`，跨地域默认 1000ms（2000ms/250ms）。2026-11-24 在成都/深圳/上海新主机上用 TOML（`source=config`）复跑滚动重启通过。
- **WAN 丢包/时延**：只对 controller 间流量注入 20% 丢包 + 50ms 单向时延（RTT ~136ms），leader 故障后 3.6s 选出新 leader，写和 snapshot 正常；未做 soak。
- **大 snapshot 跨 WAN**：5.57 MiB 模型走 2MiB 分块传输；限速中断后部分数据（2097152 字节）在重启后保留，重启并恢复链路后续传安装完成，日志追平 leader（generation 5402）。持续 2mbit 慢链路下 60s TTL 是否够用未验证。

- 单 member 入口 URL；没有 client 侧多 controller endpoint 自动 failover（依赖 LB/DNS）。
- IPAM 已实现并通过 4 主机验证（地址池/租约/自动分配/撤销隔离）；DHCP 明确不做。见 [IPAM.md](IPAM.md)。
- IPAM 地址热变更需重启 agent 才能切换 TUN 地址。
- 非 Raft legacy controller 仍保留。
- agent 客户端重启后的 snapshot 续传未验证（controller 侧 + 整集群滚动后的续传已在 TEST-RESULTS §3.10 验证）。
- 动态 Raft membership 已实现（`/v1/raft/learner|membership`）；WAN 丢包/大 snapshot 已测单次，未做 soak。
- 2026-11-24 审计发现：iroh 控制入口绕过 Raft、`POST /v1/routes` 不进 Raft、Raft 模式 LSA TTL 不执行、epoch 不复制、Raft RPC 可无鉴权等，详见 [AUDIT.md](AUDIT.md)。

### 4.3.1 2026-11-24 审计修复（详见 AUDIT.md §7）

已修复并验证：LSA Ed25519 签名、transit capability 强制、OS 路由 owner/默认路由防护、
iroh 入口走 Raft、Raft RPC 鉴权/超时/checksum、routes/LSA TTL/epoch 入 Raft、
签名 join、admin secret 分权、snapshot/manifest 默认 fail-closed、动态 membership 接口、
配置 no-op 报错、route TTL、QoS 校验对称。

仍开放：relay 秒级切换/多 relay 同时承载（现为旧连接关闭后重连，约 60s）、持续慢链路 60s TTL、
大状态写入/追赶的全量 JSON 持久化（批量导入 Θ(n²)；snapshot 后尾部为 Θ(m×状态大小)）、真 multipath、真实互联网 PTB（云网络路径 MTU 均为 1500）、macOS NAT。
已完成：应用层分片重组、ACL ICMP reject、IPv6 最小 MTU、discovery 默认认证、relay_urls 校验、
metrics/audit、systemd/CI 矩阵、签名审批入网。
2026-11-25：入网进一步收敛为单一 controller 签名凭据（`MembershipCredential` + `/v1/enroll`），
删除 PSK/join token/`admission.mode`；撤销后 ≤10s 断连并丢弃 grant，grant 可单独更新。
仍未验证：多 controller 各自 key 签发的跨地域实测、真实路由器 PTB、CI 实跑。
（动态 membership 3→4 与 iroh 8 MiB 快照已在 2026-11-24 晚验证通过。）

### 4.4 平台/运维

- 没有 CI 真实主机流水线；本轮为手工 SSH 执行。
- 没有 systemd/打包/升级。
- 没有 tracing/dashboard。
- UI 只覆盖基础查询。

---

## 5. 文档状态

已更新：

- README：openraft HA、IPv4/IPv6、fanout 移除、已知限制、真实三主机
- OPENRAFT-HA：标题/状态、fanout 迁移、阶段记录
- PLAN：fanout/threshold 清理、真实物理测试
- PRIORITIES：能力表、后续计划
- PROTOCOL：member 单 URL
- ARCHITECTURE：openraft v2 状态

仍需注意：

- `OPENRAFT-HA.md` 的 §8–§10 保留设计/迁移记录，部分“尚未”是阶段描述，以顶部状态为准。
- README 章节编号历史上有重复，不影响内容，但可后续整理。

---

## 6. 建议优先级

1. **真正 multipath**：双 direct/双 relay 同时承载、RTT/丢包调度、带宽聚合；当前 only failover。
2. **snapshot 客户端/集群滚动重启续传**：controller HTTP server 续传已实现。
3. **应用层 fragment reassembly**：当前依赖目的端内核。
4. **Docker 双容器网络/mDNS/TUN 回归**；标准 Dockerfile apt 构建仍受网络阻塞。
5. **动态 Raft membership、WAN 丢包/抖动、large snapshot 跨 WAN**。
6. **public exit NAT 云上、macOS/Windows、CI/tracing/打包**。
