# 能力与测试审计（2026-11-23）

> 关联：[README.md](README.md)、[PLAN.md](PLAN.md)、[PRIORITIES.md](PRIORITIES.md)、[OPENRAFT-HA.md](OPENRAFT-HA.md)

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
cargo test                                                 110 passed
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

双网卡注意事项：

- `.162`/`.164` 同 /24，默认路由都走 eth0
- 需要 `arp_ignore=1`/`arp_announce=2` 和 source policy route（`from .164 table 164`）才能在 `.164` 上稳定工作
- 测试脚本已包含该设置和清理

脚本：

- `scripts/test-real-dualnic-multipath.sh`
- `scripts/test-real-crossbatch-direct.sh`
- `scripts/test-real-crossbatch-relay.sh`

### 2.4 之前已验证（本轮未重复跑）

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
| 强制 multipath | ❌ | 只验证 direct→relay；没有双 direct/双 relay 同时可用与路径选择测试 |
| 3/3 全路径 roaming | ⚠️ | 批1 最后一次一个 peer relay、一个 direct；脚本仍只断言一个 peer |
| 完整 PMTUD | ❌ | 没有逐跳 MTU 递减、PTB 黑洞、TCP MSS 抓包验证 |
| 应用层 fragment reassembly | ❌ | 2000-byte ping 依赖目的端 Linux 内核重组；agent 没有重组缓存 |
| 公网 NAT/安全组 | ❌ | 三台同 VPC，只走私网；没有公网入站/跨 NAT 测试 |
| 磁盘满/撕裂写 | ❌ | 只读目录测试已做；没有 ENOSPC/partially written log |
| snapshot 跨进程完整续传 | ⚠️ | begin/chunk 重试、TTL/abort 已做；没有 agent/controller 重启后续传 |
| 真实物理跨地域 | ❌ | 同 VPC 低 RTT；没有跨 region/高延迟 |
| Docker 测试复跑 | ⚠️ | 新主机 Docker 可用且 pull 成功；Docker 功能测试未逐项复跑 |
| macOS NAT/pf、Windows | ❌ | 只有 Linux NAT |
| tracing/dashboard/打包 | ❌ | 未实现 |

---

## 4. 能力缺口

### 4.1 数据面

- **PMTUD**：有 peer path MTU、MSS clamp、ICMP PTB，但没有完整 PMTUD 状态机/缓存/黑洞检测。
- **fragment reassembly**：只有解析、转发、首片 ACL；没有应用层重组。
- **multipath**：iroh 默认能力，没有策略/强制测试。
- **NAT**：NAT44/66 公网 exit 已在 Linux netns 验证；NAT66 仅 Linux `ip6tables`，macOS 未实现。
- **队列/整形**：有 token bucket + 全局/per-priority/per-class queue depth/bytes；没有 DRR/公平调度/更细粒度 SLA。

### 4.2 Controller HA

- 单 member 入口 URL；没有 client 侧多 controller endpoint 自动 failover（依赖 LB/DNS）。
- 非 Raft legacy controller 仍保留。
- snapshot 跨重启续传未验证。
- 磁盘满/撕裂写未注入。
- 真实物理三主机已验证；跨地域/公网未验证。

### 4.3 平台/运维

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

1. **multipath/roaming**：双网卡/双 VPC，强制 3/3 路径切换。
2. **PMTUD + reassembly**：`tc` 改 MTU、抓 ICMP PTB、TCP MSS；决定是否需要应用层重组。
3. **公网 NAT 矩阵**：安全组 + 公网 IP + relay。
4. **磁盘满/撕裂写**：ENOSPC、fsync 失败、重启恢复。
5. **跨地域/高延迟**。
6. Docker/CI 回归、macOS/Windows NAT、打包/tracing。
