# 优先级评估与下一步路线

> 版本：2026-11-23
> 关联：[OPENRAFT-HA.md](OPENRAFT-HA.md)、[PLAN.md](PLAN.md)、[README.md](README.md)
> 目的：在继续加功能前，先判断什么最该做、什么可以等。

---

## 0. 结论

**Controller HA 与 P1 数据面生产化基线已完成。**

- controller 已迁移到 openraft：3 节点、HTTP Raft、mTLS、snapshot、leader failover、partition recovery、crash recovery、join config 一致性。
- 真实 LAN 使用 macvlan 3 controller + mTLS 验证。
- 数据面已覆盖 IPv4/IPv6、NAT44/66、public exit、MSS/MTU、ICMP PTB、fragment ACL、relay failover、per-class queue。
- 真实物理三主机 controller/overlay/IPv6/roaming 已完成；剩余为完整 PMTUD 状态机、分片重组、强制 multipath、磁盘满故障。

---

## 1. 评估维度

| 维度 | 含义 |
|---|---|
| 用户价值 | 对可用产品/演示/交付的直接帮助 |
| 风险 | 不做会造成的安全/正确性/运维风险 |
| 工作量 | S/M/L/XL |
| 依赖 | 是否被其他工作阻塞 |
| 建议 | 现在做 / 下一步 / 暂缓 |

---

## 2. 当前能力与缺口

| 能力 | 状态 | 主要缺口 |
|---|---|---|
| L3 overlay / TUN | 可用 | IPv4/IPv6；应用层重组/完整 PMTUD 未做；macOS NAT 未做 |
| iroh 传输 | 可用 | direct/relay、relay failover、controller 凭据成员认证；multipath 强制测试待做 |
| link-state/SPF | 可用 | UDP/mDNS discovery、static seed、controller；跨区拓扑优化待做 |
| controller | 可用 | openraft 3 节点 + HTTP/mTLS + snapshot + failover |
| ACL | 可用 | counters/审计/每规则命中已做；UI 待扩展 |
| QoS | 可用 | DSCP + token bucket + 全局/per-priority/per-class queue depth/bytes |
| AZ | 可用 | 同 zone pref + cross-zone penalty；无 policy engine/故障域 |
| 安全 | 可用 | PSK/Ed25519/TLS/mTLS/RBAC/轮换/持久化/openraft quorum；审计待做 |
| 多网络 | 可用 | 进程级隔离 + 单进程多 runtime；共享 endpoint 待做 |
| 真实主机测试 | 可用 | 真实物理三主机 HA/overlay/IPv6/roaming；公共 NAT/大规模待做 |
| 可观测性 | 可用 | metrics/audit/每规则命中；tracing/dashboard 待做 |

---

## 3. 优先级矩阵

| 优先级 | 项目 | 用户价值 | 不做的风险 | 工作量 | 依赖 | 建议 |
|---|---|---|---|---|---|---|
| **P0** | 身份/成员认证 + Hello | 高 | 任意 iroh peer 可注入 LSA/控制帧；共享 secret 泄露即全泄 | M | 无 | **完成：controller 签名凭据（2026-11-25 取代 PSK）** |
| **P0** | 控制面授权/前缀 ownership | 高 | 恶意 member 广告任意前缀，劫持流量 | M | Hello | **完成：grant + LSA/dataplane 强制** |
| **P0** | 真实 3 节点 TUN/LSA/controller 测试 | 高 | 单机 demo 通过≠真实网络通过；MTU/NAT/防火墙问题 | M | Linux x86 build | **TUN/LSA + controller 3 节点已通过** |
| **P1** | bootstrap/discovery | 高 | 部署必须手填 controller URL/peer addrs | M | 无 | **完成：UDP broadcast + PSK** |
| **P1** | 多网络/多租户隔离 | 高 | 无法一个 agent 接入多个 overlay；产品能力缺失 | L | NetworkId/FIB/TUN | **完成：进程级隔离 + 单进程多 runtime + 凭证隔离测试** |
| **P1** | ACL/QoS 生产化 | 中高 | 无法定位丢包；队列满静默丢；无 SLA | M | 现有 policy | **完成：queue_depth/counters/byte shaping/审计/每规则命中** |
| **P1** | RoutePolicy/AZ 高级策略 | 中 | `RoutePolicy` 已执行；无故障域自动 failover | M | 状态机/策略引擎 | **完成：policy engine + AZ region + failover 测试** |
| **P2** | openraft HA | 高（长期） | 单 controller 无 split-brain 保护 | XL | P0 安全 + 确定性状态机 | **完成：3 节点/mTLS/failover/partition/crash** |
| **P2** | mDNS | 中 | 部署便利性 | M | P1 | **完成：Docker bridge + macvlan 物理 LAN 验证** |
| **P2** | 共享 endpoint 多网络 / tracing | 中 | 可观测性和部署增强 | L | P1 | 后续增强 |
| **P2** | metrics/audit/tracing | 中高 | 线上不可观测、不可审计 | M | 无 | **metrics + ACL audit 已做；tracing 待做** |
| **P2** | 打包/service/upgrade | 中 | 部署体验差 | M | — | 后期 |
| **P2** | Windows / macOS NAT / IPv6 | 中 | 平台覆盖不足 | L | 数据面 | 后期 |
| **P3** | UI 扩展 | 中 | 当前 UI 只覆盖基础查询 | S/M | API | 随时 |

---

## 4. 为什么安全排在 HA 前面

当前实现的实际边界：

- iroh 数据/控制连接接受任意 endpoint；数据面靠 anti-spoof 丢包，但**控制面 LSA 帧没有成员签名**。
- 历史：member 与 controller 曾用 shared HMAC secret；2026-11-25 起改为 controller 签名的 per-member 凭据。
- member 没有 `Hello` 证明“我是这个 network 的合法节点”。
- 路由写入没有前缀 ownership/角色校验；任何能调 API/控制面的主体可广告前缀。
- HTTP API token 是可选的，默认没有 TLS。

在这种前提下加 Raft：

```text
恶意 member -> 提交伪造 LSA/前缀 -> Raft 复制到多数派 -> 全网路由被劫持
```

Raft 保证“副本一致”，不保证“写入合法”。所以先做：

1. member/controller Ed25519 身份 + `Hello` challenge/nonce。
2. 控制帧签名/绑定 network+epoch。
3. 前缀 ownership / `can_route` capability。
4. controller snapshot 从 shared HMAC 迁移到 controller key 签名（成员侧已完成 membership credential）。
5. API TLS/token/本地 socket 权限。

---

## 5. 为什么真实 3 节点测试优先

现在已经有：

- bee（x86_64）真实 TUN 双 netns ping 通过；
- Docker 双节点/网关通过；
- 分布式 LSA 单机 3 进程通过。

还缺：

- 3 台真实主机/3 个 netns 的 **controller + LSA + TUN** 联调；
- 真实 MTU、防火墙、relay/直连、NAT、丢包；
- controller 挂掉、member 挂掉、LSA 过期、ACK 对账；
- ACL/QoS 在真实流量下的 counters。

这是 P0，因为它验证的是**系统可用性**，不是“功能存在”。

---

## 6. 后续硬化计划

已完成：

- controller openraft HA + mTLS + 真实物理三主机
- IPv4/IPv6 overlay、NAT44/66、public exit
- MSS/peer MTU/ICMP PTB、fragment ACL
- relay failover、per-class queue

2026-11-24 审计修复后剩余：

1. 真 multipath（双 direct/双 relay 同时承载、按 RTT/丢包调度、去重）
2. 应用层 fragment reassembly / 完整 PMTUD 状态机
3. relay 切换时延（现为重连，约 60s；未做多 relay 同时承载）
4. 持续慢链路 TTL、大状态写入/追赶的全量 JSON 持久化（批量导入 Θ(n²)）
5. 磁盘慢 IO/撕裂写注入、公网 NAT 矩阵、Windows/macOS NAT；打包/CI 已补（未在 GitHub 实跑）

修复记录见 [AUDIT.md](AUDIT.md) §7。

---

## 7. 当前重点

**先把真实网络矩阵补齐，再扩平台。**

- 真实物理三主机已验证同 VPC 私网；下一步是跨 NAT/公网。
- 数据面不要在没有 PMTUD/重组结论前宣称“生产完成”。

---

## 8. 一句话

**controller HA 已完成；剩余工作主要是数据面边界和跨平台验证。**
