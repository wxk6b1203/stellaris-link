# 多网络隔离设计

> 状态：当前实现 **每网络一个 agent 进程**；单进程多网络 runtime 仍是后续工作。
> 关联：[MEMBERSHIP-AUTH.md](MEMBERSHIP-AUTH.md)、[ARCHITECTURE.md](ARCHITECTURE.md)、[PRIORITIES.md](PRIORITIES.md)

## 0. 目标

一个节点可以加入多个 overlay 网络，并且：

- 网络之间路由/FIB 隔离；
- TUN 地址可以重叠；
- 成员凭证不能跨网络重放；
- 一个网络的 controller/路由故障不影响另一个网络；
- API/UI 能明确区分网络。

## 1. 当前可用：每网络一个进程

这是目前支持的部署方式：

```text
stellaris-agent --config net-a.toml
stellaris-agent --config net-b.toml
```

要求：

- 不同 `node.state_dir`
- 不同 `network.id`（或者至少不同 `network.name` + 独立配置）
- 不同 `dataplane.tun_name`
- 不同 overlay CIDR（或相同 CIDR，但不同 TUN）
- 不同 `api.bind`
- 每网络独立 controller URL / PSK / manifest

每个进程有独立的：

- `AgentState`
- `PeerRegistry`
- `RouteEngine` / FIB
- `LinkStateDb`
- `Policy` / ACL / QoS
- TUN
- 控制连接

因此网络之间没有共享路由或数据面状态。

### 1.1 显式 network id

```toml
[network]
name = "prod"
id = "11111111-1111-4111-8111-111111111111"
cidr = "10.7.0.0/16"
```

`id` 必须跨网络唯一；没有配置时由 `name` 派生 UUIDv5。

### 1.2 地址校验

`node.overlay_ip` 必须在 `network.cidr` 内，否则配置加载失败。

## 2. 安全隔离

### 2.1 PSK 模式

每个网络的 PSK 不同。PSK handshake transcript 包含 `network_id`，所以：

- 网络 A 的 PSK 不能连接网络 B；
- 重放 A 的 handshake 到 B 会因 network 不同失败。

### 2.2 Controller 模式

- controller manifest 包含 `network_id`；
- member 校验 manifest network id；
- 每个网络独立 controller key set；
- 不允许跨网络使用 manifest/snapshot。

### 2.3 数据面

- mesh header 有 network hash；
- 错误网络的数据报被丢弃；
- LSA 控制连接建立于已认证的 per-network transport 上。

## 3. 单进程多网络（未来）

单进程多网络需要：

```text
Agent
 ├── NetworkRuntime A
 │    ├── NetworkId
 │    ├── TUN
 │    ├── FIB
 │    ├── PeerRegistry
 │    ├── LinkStateDb
 │    └── Policy
 └── NetworkRuntime B
      └── ...
```

关键约束：

1. **连接绑定 network**
   - 每个网络独立 iroh endpoint/ALPN，或连接 handshake 带 network id。
2. **路由查找带 network scope**
   - `RouteEngine`/`Fib` 不能只有全局一个。
3. **TUN/OS 路由隔离**
   - Linux 用独立 routing table/namespace；
   - macOS 多 utun + 路由表。
4. **凭证隔离**
   - 每网络独立 manifest/PSK；
   - nonce 缓存按 `(network,node)` 分区。
5. **API**
   - `/v1/networks/{id}/...` 或每网络独立 API。
6. **资源限制**
   - 每网络 max routes/peers/queues，防止一个网络打满全局。

## 4. Controller 与多网络

两种部署：

### 4.1 每网络独立 controller（推荐）

- 故障域、密钥、成员集合完全隔离；
- 简单；
- 多网络节点需要多个 controller URL。

### 4.2 共享 controller + network scope

- controller 有 `NetworkId` 参数；
- 每网络独立 manifest/epoch/grant；
- 需要 RBAC：admin 只能管理授权网络；
- 复杂度更高，暂不做。

## 5. 当前限制

- 单进程多网络未实现；
- 多网络共享 iroh endpoint 未实现；
- controller 多网络 scope 未实现；
- 相同 overlay CIDR 的多进程部署需要独立 TUN，且 OS 路由可能冲突，推荐不同 CIDR。

## 6. 测试矩阵

| 测试 | 期望 |
|---|---|
| overlay 不在 CIDR | 配置拒绝 |
| 显式 network id | 使用配置 id |
| 两网络不同 PSK | 不能互连 |
| 两网络同名不同 id | 网络隔离 |
| manifest network 不匹配 | 拒绝 |
| 错误 network hash 数据报 | 丢弃 |
| 多进程同 overlay IP | 独立 TUN/进程，可运行 |
| 单进程多网络 | 未实现 |

## 7. 结论

**当前生产可用形态是每网络一个 agent 进程。**
这已经提供进程级隔离、独立 FIB/TUN/凭证，是多网络 MVP 的可用边界。
单进程多网络是性能/运维优化，不应在没有隔离测试前贸然合并。
