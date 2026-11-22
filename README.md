# Stellaris Linking

**A fully controllable, Rust-native L3 overlay network with optional control plane, per-node route query, and route adjustment.**

> 状态：**MVP+ 已实现**（2026-11-22）。当前是 static-peer + signed controller（HTTP/iroh）+ 分布式 LSA/SPF；**下一步优先级见 [PRIORITIES.md](PRIORITIES.md)**，openraft HA 设计见 [OPENRAFT-HA.md](OPENRAFT-HA.md)。
> 设计基线：[ARCHITECTURE.md](ARCHITECTURE.md)、[PROTOCOL.md](PROTOCOL.md)、[PLAN.md](PLAN.md)。

## MVP 已实现

- **路由引擎**：Intent / RIB / FIB 四层；LPM、admin distance、local_pref、metric、ECMP、pin、drain、reset、dry-run、generation、持久化。
- **HTTP API**：`/v1/status`、`/v1/peers`、`/v1/routes`、`/v1/routes/lookup`、`/v1/routes/explain`、`/v1/routes/pin`、`/v1/routes/drain`、`/v1/routes/reset`、`/v1/routes/{id}`。
- **controller**：`stellaris-controller` 下发 network-scope 静态路由与 link-state 计算路由；snapshot 带 epoch、member manifest（含 underlay addrs）、HMAC-SHA256 签名；member 校验后应用、自动发现/连接成员、回 ACK（ACK 持久化）；支持 **HTTP**、**iroh control protocol**，以及多 controller **active-active fanout（pre-Raft）**。
- **Link-state 自动路由**：两种模式：① member 通过 iroh control stream 直接洪泛 LSA，节点本地 SPF；② controller 汇聚 LSA 并按节点计算。LSA 带 underlay `addrs`，节点会自动发现并连接新 peer；link metric 使用当前 RTT（每 5s 刷新 LSA）+ 跨 AZ penalty；LSA 30s 过期；等代价路径生成 ECMP；Ping/Pong heartbeat（2s/7s）自动撤回故障链路。
- **ACL/QoS**：ACL allow/deny（方向、五元组、peer、zone、优先级）；QoS 按类设置 DSCP + token-bucket rate/burst + egress 优先级队列（`qos.queue_depth` 可配，默认 4096）；`/v1/status` 暴露 ACL/QoS/转发 counters；`/metrics` 提供 Prometheus counters/gauges；ACL 拒绝写 `stellaris_audit` 日志；可通过 `GET/PUT /v1/policy` 动态更新并持久化到 `state_dir/policy.json`；在 TUN 收发包路径执行。
- **AZ 选路**：`zone` 标签 + 同 AZ `local_pref` 加成 + 跨 AZ link penalty（`routing.cross_zone_penalty`），`explain` 可见 zone。
- **事件驱动 OS 路由**：RouteEngine 通过 `watch` 通知；非 overlay 前缀变更立即 reconcile，30s fallback。
- **CLI**：`stellaris status`、`peer list`、`route list/lookup/explain/add/delete/pin/unpin/drain/reset`。
- **传输**：iroh 1.5（QUIC）静态 peer；direct/relay 路径与 RTT 可见；固定 UDP 端口，便于 LAN/实验环境直连。
- **数据面**：TUN（Linux/macOS）+ 16 字节 MeshHeader；IPv4 overlay；TTL/转发/anti-spoof；subnet gateway（a→b→c）；初始 MTU 1100 + 自适应；需要 root/CAP_NET_ADMIN。
- **入网安全**：`network.auth.mode = "psk"` 双向 HMAC challenge/response + 可选 allowlist；controller snapshot 支持 Ed25519 签名；`control.members` 支持 allowlist/prefix grant；支持一次性 `control.join_token` → `POST /v1/join`；member 侧 LSA 前缀 grant 强制、controller threshold、独立 `GET /v1/manifest` Ed25519 signed membership manifest、manifest threshold、`POST /v1/revoke` 撤销已实现。
- **RoutePolicy**：配置化 policy engine（Accept/Deny/SetLocalPref/SetMetric/SetAdminDistance/SetWeight），在 RIB→FIB 前执行；AZ 用 `region`/`zone` 匹配。
- **测试**：FIB/路由/持久化/报文解析/数据面决策/ACL/QoS/API 鉴权/controller 签名/SPF 单元测试；`demo-two-node.sh` 双节点 iroh；`docker-two-node-tun.sh` 双容器 TUN；`docker-subnet-gateway.sh` a→b→c 1000B ping；`demo-linkstate.sh`/`demo-distributed-linkstate.sh` 自动路由与 `TEST_FAILOVER=1` 撤路；`demo-iroh-controller.sh` iroh control；`demo-controller-discovery.sh` controller 自动发现成员。

## 未实现（下一步）

- 完整 controller：openraft quorum/leader election（当前 HTTP/iroh + 多 controller fanout + HMAC + epoch/manifest + 持久化 ACK）。
- 初始 seed 仍来自静态 peer 配置；LSA 会自动发现/连接新 peer，但没有 mDNS/广播发现。
- ACL/QoS 的真实队列/整形（当前有 API + token-bucket rate limit + DSCP + 优先级队列，队列深度 4096）。
- 多网络、Windows、低功耗 gateway/leaf、macOS NAT。

## 快速开始

### 1. 构建

```bash
cargo build --release
# 二进制：
#   target/release/stellaris-agent
#   target/release/stellaris-controller
#   target/release/stellaris
```

### 2. API-only（不需要 root）

```bash
./target/release/stellaris-agent --config examples/agent.toml
# 另一个终端
./target/release/stellaris status
./target/release/stellaris route add 10.7.0.0/16 --via <node-id> --metric 10
./target/release/stellaris route explain 10.7.0.5
```

内置 Web UI：<http://127.0.0.1:7777/>（如果配置了 `api.token`，点右上角 "API token" 填入）。

ACL/QoS 动态更新：

```bash
curl -X PUT http://127.0.0.1:7777/v1/policy \
  -H 'content-type: application/json' \
  -d '{"acl":{"default_action":"allow","rules":[]},"qos":{"enabled":true,"classes":[{"name":"https","dscp":46,"rate_pps":1000,"burst":100}]}}'
```

### 3. 双节点 iroh 连通性演示（不需要 root）

```bash
./scripts/demo-two-node.sh
```

脚本会：

1. 生成两个临时 identity（`--print-id`）；
2. 写入 peer 配置，固定 iroh 端口；
3. 启动两个 agent，确认 `connected: true`、`path: direct`、RTT；
4. 在 A 上加一条 `10.7.0.2/32 via B` 的路由并展示 `explain`。

### 4. Docker 双节点 TUN 验证（推荐，不需要本机 root）

```bash
./scripts/docker-two-node-tun.sh
```

脚本自动：

1. 构建 Linux 二进制（首次会拉 Rust 镜像/编译，几分钟）；
2. 构建最小 runtime 镜像；
3. 创建两个 `--privileged` 容器，分别给 `172.28.0.2/.3`，各带独立 TUN；
4. 验证 `connected: true`、`path: direct`、RTT；
5. 双向 `ping`，包含 1000 字节包；
6. 退出时清理容器/网络。

> 实测结果：A/B 双向 100% 收包，1000B ICMP RTT 约 1～3ms；A 的 TUN MTU 会从 1100 自适应到 1114（iroh 报告 `max_datagram_size` 后）。

### 5. Docker a → b → c Subnet Gateway（c 无 agent）

```bash
./scripts/docker-subnet-gateway.sh
```

验证：

- a/b 是 agent，c 是普通容器（**没有安装 agent**）；
- b 广告 `192.168.50.0/24`，a 路由该前缀 via b；
- a ping c：3/3、0% 丢包；1000B 包也通过；
- a 的 OS 路由由 agent 自动安装（`192.168.50.0/24 -> TUN`）。

可选 NAT 模式（c 完全不需要回程路由）：

```bash
NAT=1 ./scripts/docker-subnet-gateway.sh
```

这就是“网关/子网路由”场景，不是 L4 端口代理。细节见 [ADVANCED-ROUTING.md](ADVANCED-ROUTING.md)。

### 6. 可选 MVP controller（HTTP + link-state 自动路由）

```bash
# 终端 1：controller
./target/debug/stellaris-controller --config examples/controller.toml

# 终端 2：member（dataplane 可开/可关）
./target/debug/stellaris-agent --config examples/member.toml

# member 会在 2s 内拉到 controller 的 192.168.50.0/24 -> node-b
./target/debug/stellaris --api http://127.0.0.1:7781 route list --view rib

# 动态加一条 network route
curl -X POST http://127.0.0.1:7800/v1/routes \
  -H 'content-type: application/json' \
  -H 'x-stellaris-secret: change-me' \
  -d '{"prefix":"10.99.0.0/16","via":"0202020202020202020202020202020202020202020202020202020202020202","metric":5}'
```

当前限制：HTTP/iroh 都已支持，shared secret/HMAC + epoch/manifest + 持久化 ACK；仍无 openraft HA；peer 仍靠静态配置。

### 7. controller 自动发现成员（无静态 peer）

```bash
./scripts/demo-controller-discovery.sh
```

两个 member 只配置 controller URL 和 `transport.advertise`，**不配置 `[[peers]]`**：

- member LSA 上报 overlay_ip/addrs
- controller 把它们放进 member manifest
- member 从 snapshot 自动 `add_peer` 并建立 iroh 连接
- 脚本检查 `peer list` 出现 `auto-*` 且 `connected: true`

### 8. 多 controller active-active fanout（pre-Raft）

```bash
./scripts/demo-controller-ha.sh
```

member 配置多个 HTTP controller：

```toml
[control]
urls = ["http://10.0.0.1:7800", "http://10.0.0.2:7800"]
secret = "change-me"
```

member 会把 LSA 发给所有 controller、从最新 snapshot 应用、并向所有 controller 回 ACK；单个 controller 挂掉不影响 member。当前是 **active-active fanout，不是 Raft consensus**；openraft HA 是下一步。

### 9. iroh controller demo（不需要 HTTP 轮询）

```bash
./scripts/demo-iroh-controller.sh
```

controller 配置：

```toml
[control]
bind = "127.0.0.1:7800"   # HTTP 仍保留
secret = "change-me"
iroh_port = 43100         # 开启 iroh control
```

member 配置：

```toml
[control]
endpoint_id = "<controller endpoint id>"
addrs = ["10.0.0.1:43100"]
secret = "change-me"
```

controller 可用 `stellaris-controller --config ... --print-id` 输出 endpoint id。demo 会检查 controller 收到 iroh ACK、member 应用 snapshot。

### 10. Link-state 自动路由 demo（不需要 root）

两种都可用：

```bash
# 分布式：a—b—c，节点间 iroh control stream 洪泛 LSA，本地 SPF
./scripts/demo-distributed-linkstate.sh

# controller-mediated：member 上报 LSA，controller 汇聚/SPF
./scripts/demo-linkstate.sh
```

分布式脚本会检查 a 自动发现 c、且 RIB 出现 `10.101.0.3/32`，输出 `OK`；controller 脚本检查 `192.168.70.0/24`。

失败收敛测试：

```bash
TEST_FAILOVER=1 ./scripts/demo-distributed-linkstate.sh
# OK: link-state route withdrawn after b failure.
```

### 11. Linux netns TUN 回归（单机、需要 root）

```bash
sudo BIN=./target/release/stellaris-agent ./scripts/test-linux-netns-tun.sh
```

在 Linux 上用两个 network namespace + veth 启动两个 agent 和各自的 TUN，做双向 ping 与 1000B 包测试。已在本机 x86_64 Linux 上实测通过。

### 12. Linux 3 节点 TUN/LSA transit 回归（单机、需要 root）

```bash
sudo BIN=./target/release/stellaris-agent ./scripts/test-linux-netns-3node.sh
```

三个 network namespace + 两个 veth，a—b—c；验证 LSA 自动路由、b 的 transit 转发、双向 ping 和 1000B 包。已在 bee x86_64 实测通过。

### 13. 真正的 TUN overlay（两台机器，需要 root）

两台 Linux 机器（或 macOS + Linux；macOS `utun42`）：

```toml
# node-a.toml
[node]
name = "node-a"
state_dir = "./state/node-a"
overlay_ip = "10.7.0.1"

[network]
name = "demo"
cidr = "10.7.0.0/16"

[transport]
listen_port = 41001

[dataplane]
enabled = true
tun_name = "stellaris0"   # macOS: utun42
mtu = 1280

[api]
bind = "0.0.0.0:7777"

[[peers]]
name = "node-b"
endpoint_id = "<node-b endpoint id>"
overlay_ip = "10.7.0.2"
addrs = ["<node-b-ip>:41002"]
```

```bash
# 先分别 --print-id 生成 identity，再填 peer endpoint_id
sudo ./target/release/stellaris-agent --config node-a.toml
# 两台都起来后
ping 10.7.0.2
```

> TUN 创建需要 root/CAP_NET_ADMIN；macOS 要求 `utunN`（本实现默认 `utun42`）。如果没有 TUN 权限，使用上面的 transport-only/API-only 模式。

## 目录

```text
crates/
  stellaris-types/      # ID、路由类型、配置、错误
  stellaris-fib/        # LPM、ECMP、FIB 编译
  stellaris-routing/    # Intent/RIB、route engine、持久化
  stellaris-agent/      # agent、API、iroh 传输、TUN 数据面
  stellaris-cli/        # stellaris CLI
apps/                   # 预留 dashboard/desktop
scripts/                # demo-two-node.sh
examples/               # 示例 TOML
```

## 文档

| 文档 | 内容 |
|---|---|
| [ARCHITECTURE.md](ARCHITECTURE.md) | 完整实现架构与后续模块 |
| [PROTOCOL.md](PROTOCOL.md) | 控制协议/API/MeshHeader |
| [PLAN.md](PLAN.md) | 里程碑、Epic、第一 sprint |
| [ADVANCED-ROUTING.md](ADVANCED-ROUTING.md) | 静态路由、AZ 分段、subnet gateway 设计 |
| [PRIORITIES.md](PRIORITIES.md) | 当前缺口、优先级与下一阶段路线 |
| [MEMBERSHIP-AUTH.md](MEMBERSHIP-AUTH.md) | 入网、成员授权、前缀授权设计 |
| [OPENRAFT-HA.md](OPENRAFT-HA.md) | openraft controller HA 详细设计（未实现） |
| [examples/policy.toml](examples/policy.toml) | ACL/QoS 配置示例 |
| [scripts/demo-linkstate.sh](scripts/demo-linkstate.sh) | controller-mediated link-state 演示 |
| [scripts/demo-distributed-linkstate.sh](scripts/demo-distributed-linkstate.sh) | 分布式 LSA/SPF 演示 |
| [stellaris-linking-routing-design.md](stellaris-linking-routing-design.md) | 路由/低功耗设计背景 |
| [stellaris-linking-architecture.md](stellaris-linking-architecture.md) | 早期架构与 Rust 选型 |
| [virtual-network-survey-2026-11.md](virtual-network-survey-2026-11.md) | 方案调研 |

## 已知限制

- controller 支持 HTTP/iroh + 多 controller fanout（HMAC + epoch/manifest + 持久化 ACK），但无 openraft quorum/leader election；peer 初始仍靠静态配置。
- 数据面 IPv4 overlay；IPv6 路由类型已支持但 TUN 数据面未启用。
- 初始 bootstrap 仍需要 controller URL 或静态 peer；之后可由 controller manifest/LSA `overlay_ip/addrs` 自动发现/连接；没有 mDNS 发现/HA。
- `scope=network` 已支持（MVP HTTP controller）；本地 `scope=local` 仍用于实验/紧急路由。
- ACL/QoS 支持 API 动态更新 + token-bucket rate limit + DSCP；没有 UI、队列/整形。anti-spoof 允许 peer 自身 overlay IP + 它广告的前缀；subnet gateway 的 NAT 目前仅 Linux（macOS 待做），且 NAT 规则退出清理/owner 管理待完善。
- **没有应用层成员认证/Hello 握手**：任何知道 endpoint id/ALPN 的 iroh 节点都能建立 QUIC 连接；数据包会被 anti-spoof 丢掉，但不要把这个 MVP 暴露在不可信网络。
- iroh 使用默认公共 relay；生产应改 `RelayMode::Custom` 自建 relay。
- 没有做安全审计；MVP 仅用于开发/实验。

## 贡献

- 每个 PR 关联 issue；Conventional Commits。
- `cargo fmt --check`、`cargo clippy --all-targets -- -D warnings`、`cargo test` 必须全绿。
- 外部输入（packet/API）必须有边界检查/测试。
