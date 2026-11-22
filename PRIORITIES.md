# 优先级评估与下一步路线

> 版本：2026-11-22
> 关联：[OPENRAFT-HA.md](OPENRAFT-HA.md)、[PLAN.md](PLAN.md)、[README.md](README.md)
> 目的：在继续加功能前，先判断什么最该做、什么可以等。

---

## 0. 结论

**不建议现在直接开始 openraft HA。**

当前更优先的是：

1. **P0：身份/成员认证与控制面授权**——否则 Raft 只会“高可用地复制未授权写入”。
2. **P0：真实 3 节点/多主机验证**——bee x86_64 已经能跑；先把数据面、LSA、controller 在真实主机上打穿。
3. **P1：bootstrap/discovery**——去掉 controller URL/静态 seed 的硬依赖。
4. **P1：多网络隔离**——这是产品能力，不只是实现细节。
5. **P1：ACL/QoS 生产化 + 指标**——当前队列深度硬编码、缺少 counters。
6. **P2：openraft HA**——设计已写，但在安全与真实集群验证之后。

如果业务把“controller 多副本”作为硬性上云门槛，可以提前 openraft，但必须先做 P0 安全，否则没有意义。

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
| L3 overlay / TUN | 可用 | IPv4 only；macOS 未回归；无 IPv6 分片 |
| iroh 传输 | 可用 | 默认公共 relay；无应用层成员认证 |
| link-state/SPF | 可用 | seed 静态；无 mDNS；无 controller 跨区拓扑优化 |
| controller | 可用 | HTTP/iroh/fanout；无 Raft quorum |
| ACL | 可用 | 配置/API/UI；无 counters/日志审计 |
| QoS | 可用 | DSCP + token bucket + 优先级队列；无整形/队列配置 |
| AZ | 可用 | 同 zone pref + cross-zone penalty；无 policy engine/故障域 |
| 安全 | **不足** | 无 Hello、无成员签名、shared HMAC、API token 可选 |
| 多网络 | **缺失** | 单 NetworkConfig / 单 TUN / 单 FIB |
| 真实主机测试 | 部分 | bee x86_64 TUN 已通过；未做 3 节点/多主机 chaos |
| 可观测性 | 缺失 | 无 `/metrics`、无审计日志、无 controller drift |

---

## 3. 优先级矩阵

| 优先级 | 项目 | 用户价值 | 不做的风险 | 工作量 | 依赖 | 建议 |
|---|---|---|---|---|---|---|
| **P0** | 身份/成员认证 + Hello | 高 | 任意 iroh peer 可注入 LSA/控制帧；共享 secret 泄露即全泄 | M | 无 | **现在做** |
| **P0** | 控制面授权/前缀 ownership | 高 | 恶意 member 广告任意前缀，劫持流量 | M | Hello | **现在做** |
| **P0** | 真实 3 节点 TUN/LSA/controller 测试 | 高 | 单机 demo 通过≠真实网络通过；MTU/NAT/防火墙问题 | M | Linux x86 build | **TUN/LSA + controller 3 节点已通过** |
| **P1** | bootstrap/discovery | 高 | 部署必须手填 controller URL/peer addrs | M | 无 | **完成：UDP broadcast + PSK** |
| **P1** | 多网络/多租户隔离 | 高 | 无法一个 agent 接入多个 overlay；产品能力缺失 | L | NetworkId/FIB/TUN | **完成：进程级隔离 + 凭证隔离测试；单进程多网络为 P2** |
| **P1** | ACL/QoS 生产化 | 中高 | 无法定位丢包；队列满静默丢；无 SLA | M | 现有 policy | **完成：queue_depth/counters/byte shaping/审计/每规则命中** |
| **P1** | RoutePolicy/AZ 高级策略 | 中 | `RoutePolicy` 已执行；无故障域自动 failover | M | 状态机/策略引擎 | **完成：policy engine + AZ region + failover 测试** |
| **P2** | openraft HA | 高（长期） | 单 controller/ fanout 无 split-brain 保护 | XL | P0 安全 + 确定性状态机 | 设计完成，未实现 |
| **P2** | mDNS | 中 | 部署便利性 | M | P1 | **完成：`_stellaris._udp.local.`** |
| **P2** | 单进程多网络 / tracing | 中 | 可观测性和部署增强 | L | P1 | 后续增强 |
| **P2** | metrics/audit/tracing | 中高 | 线上不可观测、不可审计 | M | 无 | **metrics + ACL audit 已做；tracing 待做** |
| **P2** | 打包/service/upgrade | 中 | 部署体验差 | M | — | 后期 |
| **P2** | Windows / macOS NAT / IPv6 | 中 | 平台覆盖不足 | L | 数据面 | 后期 |
| **P3** | UI 扩展 | 中 | 当前 UI 只覆盖基础查询 | S/M | API | 随时 |

---

## 4. 为什么安全排在 HA 前面

当前实现的实际边界：

- iroh 数据/控制连接接受任意 endpoint；数据面靠 anti-spoof 丢包，但**控制面 LSA 帧没有成员签名**。
- member 与 controller 用 shared HMAC secret，不是 per-member key。
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
4. controller snapshot 从 shared HMAC 迁移到 controller key 签名。
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

## 6. 建议的两周计划

### Sprint A（P0）

- Day 1-3：成员认证/Hello + 控制帧签名
- Day 3-5：前缀授权 + controller key 签名（替代 shared HMAC 过渡）
- Day 5-8：3 netns/3 主机真实集群测试
- Day 8-10：失败注入 + 文档 + CI

### Sprint B（P1）

- bootstrap/discovery（先 UDP broadcast/mDNS 选一个）
- ACL/QoS counters + queue depth 配置
- 多网络设计/原型（每网络独立 FIB/TUN/ACL）

### 之后

- openraft HA（按 [OPENRAFT-HA.md](OPENRAFT-HA.md) Phase 0→3）
- 可观测性/打包/Windows

---

## 7. 如果一定要先做 openraft

可以，但请接受两个前置条件：

1. 先做 `ControllerModel`/`Command` 确定性重构（1～2 周）；
2. 至少做 controller 间身份认证（不能只靠 shared HMAC）。

否则建议把 HA 目标拆成：

- H0：确定性状态机（无 Raft）
- H1：单节点 openraft shadow
- H2：3 节点 Raft
- H3：cutover + chaos

每一步都可验收，不会出现“写了很多 Raft 代码但没人敢上线”。

---

## 8. 一句话

**先让系统“可信、可观测、可在真实网络工作”，再让它“高可用”。**
