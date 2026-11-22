# 静态路由、AZ 分段与 Subnet Gateway

> 版本：v0.1（2026-11-22）
> 配套：[ARCHITECTURE.md](ARCHITECTURE.md)、[PROTOCOL.md](PROTOCOL.md)、[README.md](README.md)
> 结论：**a → b → c（c 无 agent）是本项目的核心目标之一**，属于 L3 subnet gateway / subnet router，不是 L4 代理。当前 MVP 已实现并实测通过。

---

## 0. 当前实现边界

| 能力 | 状态 |
|---|---|
| 本地静态路由（`scope=local`） | ✅ 已实现 |
| `admin_distance` / `metric` / ECMP / pin / drain / reset | ✅ 已实现 |
| 非 overlay 前缀的 OS 路由 reconcile（`prefix -> TUN`） | ✅ 已实现（5s 轮询） |
| subnet gateway（b 广告前缀，a 路由到 b，b 转发到 c） | ✅ 已实现并在 Docker 实测 |
| `zone` 标签 + 同 AZ local_pref | ✅ 已参与选路（静态/controller 路由） |
| `scope=network` 全网静态路由 | ✅ MVP HTTP controller（HMAC 签名/ACK；iroh/HA 待做） |
| NAT / MASQUERADE | ✅ Linux 已实现（`NAT=1` 测试通过）；macOS/规则清理待做 |
| 多网关 HA / ECMP | ⏳ 设计已留，未实现 |
| BGP/OSPF 互操作 | ❌ 非目标（可做静态/汇总导入） |

---

## 1. 手动静态路由怎么做合适

### 1.1 两种 scope

```text
scope = local | network
```

| scope | 谁执行 | 适用 | 当前 |
|---|---|---|---|
| `local` | 本节点 RouteEngine | 单节点临时路由、实验、pin | ✅ |
| `network` | controller 签名 → 所有节点 | 生产静态路由、网关前缀 | ⏳ |

**建议：**

- 本地实验用 `local`；生产入口只允许 `network`，由 controller 做权限/校验/审计。
- `network` 路由进入 `RouteIntent`，带 generation/expires/reason；agent ACK；UI 显示 desired vs applied。
- 不要允许普通 agent 直接广播 `network` 路由；否则一个坏节点可以劫持流量。

### 1.2 路由属性

```text
prefix, via, admin_distance, local_pref, metric, weight,
pin, expires_at, zone/region, tags, reason
```

建议语义：

- `admin_distance`：来源优先级（connected 0 / static 1 / controller 20 / link-state 100）；
- `local_pref`：同来源内的策略偏好（越大越优先）；
- `metric`：路径代价；
- `weight`：ECMP 权重；
- `pin`：固定同前缀下一跳（不绕过 LPM）；
- `expires_at`：临时路由自动撤销；
- `zone/region`：给 AZ 选路/解释用，不直接改 FIB；
- `tags`：给 policy/审计/UI 分组。

### 1.3 OS 路由 reconcile

overlay 路由不改内核表（只改 FIB）；**非 overlay 前缀**（如 `192.168.50.0/24`）需要安装 `prefix -> TUN`：

- 当前实现：5 秒轮询 RIB，`ip route replace <prefix> dev <tun>`（Linux）/`route -n add`（macOS）；
- 只安装 RIB 中存在的非 overlay 前缀；路由删除后移除；
- 缺点：5 秒延迟、用 `ip` 命令、可能覆盖别人同前缀路由。

**生产建议：**

1. 用 `rtnetlink`（Linux）/ `route` socket（macOS）替代命令；
2. 路由变更事件驱动，不轮询；
3. 给路由打 owner/protocol 标记，只删自己的；
4. 安装前检查冲突：同前缀是否已被其他 VPN/接口占用，冲突则拒绝并告警；
5. 路由表独立（Linux `ip rule` + table）避免污染主表。

### 1.4 安全与校验

- 只有授权 gateway 能广告前缀；controller 校验 prefix ownership；
- 防环：path vector/TTL；
- 前缀限额/聚合：不要把每个 /32 都灌进全网；
- `dry_run` + `If-Match: generation` + `Idempotency-Key`；
- 所有变更 audit；回滚是新增 generation，不改历史；
- 网关前缀必须显式配置/签名，不能由数据面“自动学习”。

---

## 2. AZ 分段怎么做合适

### 2.1 先定义 AZ 是什么

AZ（Availability Zone）是**故障域 + 延迟域**，不是 IP 段：

- 同一 AZ：低延迟、可免费/高带宽；
- 跨 AZ：有延迟/带宽成本，可能单独计费；
- AZ 故障：该 AZ 内节点同时不可用。

因此 AZ 应该是一个 **label**（`zone=az-a`），不是网段；一个 AZ 可以有多个子网，一个子网也可以跨 AZ（云上通常不建议）。

### 2.2 控制面放置

| 组件 | 建议 |
|---|---|
| controller | 3 节点跨 3 AZ；openraft quorum；leader 在任一 AZ；当前 MVP 是单 HTTP controller |
| manifest/DB | 跨 AZ 复制；备份 |
| relay | 每 AZ 至少一个；节点优先本 AZ relay |
| gateway/exit | 每 AZ 至少一个；跨 AZ 只作备份 |
| UI/API | 任 AZ，前置 LB/overlay |

**不要**把 3 个 controller 放同一 AZ；否则 AZ 故障 = 控制面不可用。MVP 单 controller 可以接受，但生产必须跨 AZ。

### 2.3 路由策略

建议按优先级：

1. **同 AZ 优先**：同前缀多候选时，本 AZ 的 `local_pref += 100`；
2. **跨 AZ 代价**：link cost 加跨 AZ penalty（可配置，如 +20ms 或 +100）；
3. **避免 tromboning**：a(az-a) → b(az-b) → c(az-a) 这种绕行，应在 SPF/controller 里加 zone path 惩罚；
4. **AZ 内 gateway 优先**：访问 AZ 内子网，优先本 AZ gateway；跨 AZ gateway 只作备份；
5. **exit node 按 AZ**：默认出口在本 AZ；跨 AZ 出口需要显式策略；
6. **故障回退**：本 AZ 不可用时允许跨 AZ，但要有容量/策略上限。

实现上：

- `NodeConfig.zone` / `PeerConfig.zone` 已有字段；
- `RoutePolicy` 可加 `match.zone`、`action.set_local_pref`；
- link attributes 加 `zone`/`cross_zone`，SPF/controller 算路时加 penalty；
- `explain` 返回 zone path，UI 按 AZ 分组。

### 2.4 故障与容量

- AZ 故障：controller quorum 仍可用（3 AZ 中 2 个）；relay 切换；gateway 切换；
- 跨 AZ 带宽/成本：限制跨 AZ 中转（`avoid_transit_zones`）；
- 容量：每 AZ gateway 按峰值预留；ECMP 多网关；
- 不要做“硬隔离”：AZ 只是 preference，硬隔离会在故障时造成不可用；
- 监控：每 AZ 的 peer/route/gateway/relay 健康；跨 AZ 流量比例。

### 2.5 分阶段落地

| 阶段 | 内容 |
|---|---|
| P1 | `zone` 字段 + status/peer/explain 展示；UI 分组 |
| P2 | `RoutePolicy match zone` + `local_pref` + cross-zone penalty；静态路由带 zone |
| P3 | controller 跨 AZ 部署 + openraft；AZ-aware gateway/relay 选择 |
| P4 | 跨 AZ 容量/成本控制、故障演练、AZ 自动 drain |

**建议先做 P1/P2**：不需要 controller 也能验证“同 AZ 优先”的选路；P3 再上 HA。

---

## 3. a → b → c（c 无 agent）是不是目标？

### 3.1 是，而且是核心目标

这正是 **subnet gateway / subnet router**：

```text
a (agent) ──overlay──► b (agent, gateway) ──underlay──► c (no agent)
```

- b 广告 `c_prefix`（如 `192.168.50.0/24`）；
- a 加 `c_prefix via b`；
- a 的包走 overlay 到 b；
- b 把包交给内核，内核转发到 c；
- c 的回包通过 b 的 LAN 路由/或 NAT 回到 overlay。

它不是“代理到 c”的 L4 端口转发；它是**L3 路由**。如果 c 不是 IP 可达（只支持串口/BLE/私有协议），那才是 L4 代理/网关适配，另做。

### 3.2 当前已验证

`scripts/docker-subnet-gateway.sh`：

- a/b 是 agent，c 是普通容器（**无 agent**）；
- b `advertise = ["192.168.50.0/24"]`；
- a `[[peers]] advertised = [...]` + `[[routes]] prefix via b`；
- a 的 OS 路由由 reconciler 自动安装 `192.168.50.0/24 -> TUN`；
- a ping c：**3/3，0% 丢包**；1000B 包也通过。

### 3.3 成立的四个条件

1. **b 有到 c 的 underlay 路由**（同 LAN/专线/VPN 均可）；
2. **c 有回程路由**到 overlay（`10.77.0.0/16 via b`），或者 b 做 NAT；
3. **b 开启 IP forwarding**（当前 agent 自动写 `ip_forward=1`）；
4. **a 信任 b 的前缀**：b 的 `advertised` 同时用于 anti-spoof 和路由授权。

缺一不可。当前 Linux 已支持 `dataplane.nat = true`（iptables MASQUERADE），c 不需要回程路由；macOS 的 pf 版本待做。

### 3.4 安全与 HA

- 只有 `can_route` 的 gateway 能广告前缀；
- b 的前缀必须显式配置/controller 签名，不能自动学习；
- a 只接受 b 广告的前缀；anti-spoof 检查源 IP 属于 b 的 `advertised`；
- 多 gateway：同一前缀多个 b，ECMP/HA；`drain` 一个 gateway 逐步迁移；
- 聚合：广告 `192.168.0.0/16` 而不是每个 /32；
- MTU：gateway 两侧 MTU 不同，需要 MSS clamp/分片（当前依赖 TUN MTU + IPv4 分片）。

---

## 4. 建议的实现顺序

1. **静态路由/网关产品化**（当前 MVP 已有基础）：
   - 事件驱动 OS route reconcile；
   - NAT/MASQUERADE 产品化（Linux 已通，改 nftables/owner 标记；macOS pf）；
   - route ownership/冲突检测；
   - 多 gateway ECMP/HA。
2. **AZ P1/P2**：
   - zone 展示 + explain；
   - policy match zone + 同 AZ local_pref + cross-zone penalty；
   - 静态路由 zone 属性。
3. **controller**：
   - `scope=network` 静态路由；
   - 前缀授权/汇总；
   - 跨 AZ controller HA。
4. **运维**：
   - 每 AZ 的 gateway/relay 容量；
   - 故障演练（AZ down、gateway down）；
   - UI 按 AZ 分组/跨 AZ 流量视图。

---

## 5. 一句话

- **a → b → c（c 无 agent）就是本项目的目标场景**，属于 subnet gateway；当前已用 Docker 实测通过。
- **手动静态路由**已支持本地 scope；生产应走 controller 的 network scope + 授权/审计。
- **AZ** 应该做“标签 + 偏好 + 故障域”，不要做“硬网段隔离”；先做展示/同 AZ 优先，再做跨 AZ controller HA。
