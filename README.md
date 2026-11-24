# Stellaris Linking

**A fully controllable, Rust-native L3 overlay network with optional control plane, per-node route query, and route adjustment.**

> 状态：**controller HA + P1 数据面生产化基线已完成**（2026-11-23）。3 节点 openraft/mTLS/快照/故障恢复、真实物理三主机 HA、IPv4/IPv6 overlay、NAT44/66、public exit、MSS/MTU/PTB、fragment ACL、direct→relay 切换、per-class queue 已验证。
> **2026-11-24 已按 [AUDIT.md](AUDIT.md) 修复 P0 与大部分 P1**：LSA Ed25519 签名、transit capability、OS 路由防护、iroh 走 Raft、Raft 鉴权/超时、routes/LSA TTL/epoch 入 Raft、签名 join、admin secret、动态 membership 等；剩余边界（真 multipath、应用层重组、relay 路径选择、真实互联网 PMTUD、macOS NAT）仍以 AUDIT.md 为准。设计记录见 [OPENRAFT-HA.md](OPENRAFT-HA.md)。
> 设计基线：[ARCHITECTURE.md](ARCHITECTURE.md)、[PROTOCOL.md](PROTOCOL.md)、[PLAN.md](PLAN.md)。

## MVP 已实现

- **路由引擎**：Intent / RIB / FIB 三层（Path 层未实现，`set_path_hint` 当前为空操作）；LPM、admin distance、local_pref、metric、ECMP、pin、drain、reset、dry-run、generation、持久化。
- **HTTP API**：`/v1/status`、`/v1/peers`、`/v1/routes`、`/v1/routes/lookup`、`/v1/routes/explain`、`/v1/routes/pin`、`/v1/routes/drain`、`/v1/routes/reset`、`/v1/routes/{id}`。
- **controller**：openraft 3 节点 HA；HTTP Raft RPC + mTLS；snapshot/manifest 带 epoch、member、underlay addrs；leader failover、partition recovery、crash recovery；member 通过单个 controller URL 接入并由 Raft 复制；`control.iroh_port` 的 iroh 控制入口同样走 Raft（线性化快照读 + Raft 写，2026-11-24 起）。
- **Link-state 自动路由**：两种模式：① member 通过 iroh control stream 直接洪泛 LSA，节点本地 SPF；② controller 汇聚 LSA 并按节点计算。LSA 带 underlay `addrs`，节点会自动发现并连接新 peer；link metric 使用当前 RTT（每 5s 刷新 LSA）+ 跨 AZ penalty；LSA 30s 过期（分布式模式；Raft controller 模式由 leader 周期提交 `ExpireLsa`，`control.lsa_ttl_secs` 可配）；等代价路径生成 ECMP；Ping/Pong heartbeat（2s/7s）自动撤回故障链路。
- **ACL/QoS**：ACL allow/deny（方向、五元组、peer、zone、优先级）；QoS 按类设置 DSCP + 包速率/字节速率 token-bucket（`rate_pps/rate_bps`）+ egress 优先级队列（`qos.queue_depth` 可配，默认 4096）；`/v1/status` 暴露 ACL/QoS/转发 counters 和每 ACL 规则命中数 `acl_hits`；`/metrics` 提供 Prometheus counters/gauges；ACL 拒绝写 `stellaris_audit` 日志；可通过 `GET/PUT /v1/policy` 动态更新并持久化到 `state_dir/policy.json`；在 TUN 收发包路径执行。
- **AZ 选路**：`zone` 标签 + 同 AZ `local_pref` 加成 + 跨 AZ link penalty（`routing.cross_zone_penalty`），`explain` 可见 zone。
- **事件驱动 OS 路由**：RouteEngine 通过 `watch` 通知；非 overlay 前缀变更立即 reconcile，30s fallback。
- **CLI**：`stellaris status`、`peer list`、`route list/lookup/explain/add/delete/pin/unpin/drain/reset`。
- **传输**：iroh 1.5（QUIC）静态 peer；direct/relay 路径与 RTT 可见；固定 UDP 端口，便于 LAN/实验环境直连。
- **数据面**：TUN（Linux/macOS）+ 16 字节 MeshHeader；IPv4 + IPv6 overlay；TTL/转发/anti-spoof；subnet gateway；NAT44/NAT66 public exit；fragment 解析/ACL；TCP MSS clamp、peer path MTU、ICMPv4/v6 PTB；初始 MTU 1100 + 自适应；需要 root/CAP_NET_ADMIN。
- **API/控制面**：非 loopback `api.bind` 必须配置 `api.token`；`api.read_token` 只允许读操作，写操作仍需要 admin token；`api.previous_tokens` / `control.previous_secrets` 支持轮换窗口；controller 可配置 `control.leader_id`，legacy 路径非 leader 拒绝写入（Raft 路径由 quorum/leader hint 处理）；非 loopback `control.bind`/controller iroh 必须配置 `control.secret`。
- **入网安全**：`network.auth.mode = "psk"` 双向 HMAC challenge/response + 可选 allowlist；controller snapshot 支持 Ed25519 签名；`control.members` 支持 allowlist/prefix grant；一次性 `control.join_token` → `POST /v1/join`；member 侧 LSA 前缀 grant、数据面 source grant（转发他人源地址需要 `transit` capability）、`POST /v1/revoke`（可用 `control.admin_secret` 与 member secret 分权）、可选签名 `POST /v1/join`（`require_join_signature`）；join token 配置 hash 入 Raft，配置不一致 join 409。
- **RoutePolicy**：配置化 policy engine（Accept/Deny/SetLocalPref/SetMetric/SetAdminDistance/SetWeight），在 RIB→FIB 前执行；AZ 目前只有 `region` 匹配（`zone` 字段未实现）。
- **测试**：FIB/路由/持久化/报文解析/数据面决策/ACL/QoS/API 鉴权/controller 签名/SPF 单元测试；`demo-two-node.sh` 双节点 iroh；`docker-two-node-tun.sh` 双容器 TUN；`docker-subnet-gateway.sh` a→b→c 1000B ping；`demo-linkstate.sh`/`demo-distributed-linkstate.sh` 自动路由与 `TEST_FAILOVER=1` 撤路；`demo-iroh-controller.sh` iroh control；`demo-controller-discovery.sh` controller 自动发现成员；`test-real-3host-ha.sh` / `test-real-3host-overlay.sh` / `test-real-3host-ipv6.sh` / `test-real-3host-roaming.sh` 真实物理三主机 HA、IPv4/IPv6、roaming。

## 尚未实现（剩余硬化）

- 真实物理三主机 controller/overlay 已完成；真实物理 **多路径/公网 NAT** 仍待覆盖。
- 完整 PMTUD 状态机（现有 peer path MTU + MSS + ICMP PTB）。
- 应用层 fragment reassembly（当前依赖目的端内核重组）。
- 强制 multipath（已有 direct→relay roaming）。
- 磁盘满/撕裂写注入（只读磁盘已测）。
- Windows、低功耗 gateway/leaf、macOS NAT。

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

当前限制：HTTP/iroh 都已支持；controller 使用 openraft quorum；peer 初始仍靠静态配置。

### 7. controller 自动发现成员（无静态 peer）

```bash
./scripts/demo-controller-discovery.sh
```

两个 member 只配置 controller URL 和 `transport.advertise`，**不配置 `[[peers]]`**：

- member LSA 上报 overlay_ip/addrs
- controller 把它们放进 member manifest
- member 从 snapshot 自动 `add_peer` 并建立 iroh 连接
- 脚本检查 `peer list` 出现 `auto-*` 且 `connected: true`

### 8. Raft controller HA（真实三节点）

```bash
# 本机 3 进程 Raft
./scripts/test-controller-raft-3node.sh

# 真实 LAN macvlan 3 controller + mTLS
PARENT=eth0 SUBNET=... ./scripts/test-docker-controller-raft-macvlan.sh

# 真实三地：滚动重启（mTLS）
H1=root@<chengdu> H2=root@<shenzhen> H3=root@<shanghai> \
BIN=/opt/stellaris/stellaris-controller ./scripts/test-real-rolling-restart-ha.sh

# 真实三地：20% 丢包 + 50ms 单向时延下的选举
H1=root@<chengdu> H2=root@<shenzhen> H3=root@<shanghai> \
./scripts/test-real-wan-loss-ha.sh

# 本机：Raft 状态复制（路由/LSA TTL/epoch/签名 join/admin secret）
./scripts/test-controller-state-ha.sh

# 本机：iroh 入口必须经 Raft
./scripts/test-real-iroh-raft.sh

# root + netns：OS 路由安全（默认路由 opt-in、外部路由不覆盖、proto 标记）
sudo BIN=./target/release/stellaris-agent ./scripts/test-netns-route-safety.sh
```

member 只配置一个入口：

```toml
[control]
url = "http://10.0.0.1:7800"
secret = "change-me"
```

controller 集群内部通过 `raft_peers` + mTLS 复制。旧 `control.urls` active-active fanout 已移除；配置中出现会直接报错。

选举超时是正式配置项，默认值按**跨地域**部署取值（深圳/上海/成都三地滚动重启验证通过的值）：

```toml
[control]
raft_dir = "/var/lib/stellaris/raft"
raft_id = 2
raft_bind = "0.0.0.0:5701"
raft_secret = "change-me"
raft_bootstrap = false

# 最小选举超时（ms）；省略即跨地域默认 1000。
# max = 2x，heartbeat = min/4；允许范围 50..=60000。
raft_election_timeout_ms = 1000

[[control.raft_peers]]
id = 1
addr = "203.0.113.10:5701"
[[control.raft_peers]]
id = 2
addr = "203.0.113.11:5701"
[[control.raft_peers]]
id = 3
addr = "203.0.113.12:5701"
```

- 省略 `raft_election_timeout_ms` → `1000/2000/250` ms（min/max/heartbeat），日志
  `source="default-cross-region"`。
- 同机房希望更快换主可显式设 `300`（`600/75`）；跨地域不要低于默认值。
- 越界值（`<50` 或 `>60000`）在配置加载时报错，不静默 clamp。
- `/v1/status` 的 `raft` 字段返回生效的 min/max/heartbeat 与来源。
- 环境变量 `STELLARIS_RAFT_ELECTION_TIMEOUT_MS` 已废弃：仅在 TOML 未配置时生效并打 warn。

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
# OK: link-state route withdrawn after c failure.
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

### 13. mDNS bootstrap discovery（Linux netns）

```toml
[transport]
mdns = true
advertise = ["192.168.1.10:41000"]
```

```bash
sudo BIN=./target/release/stellaris-agent ./scripts/test-linux-netns-mdns.sh
# OK: mDNS discovery + PSK works.
```

mDNS 服务类型：`_stellaris._udp.local.`；发现后仍必须通过 PSK/controller 认证。

### 14. Docker mDNS 完整验证

```bash
BIN=./target/release/stellaris-agent ./scripts/test-docker-mdns.sh
# OK: container mDNS discovery + PSK works.
```

两个 Docker bridge 容器完成 mDNS 发现、iroh 连接、PSK 认证。

### 15. macvlan 真实局域网 mDNS

```bash
PARENT=enp1s0 SUBNET=10.0.10.0/23 GATEWAY=10.0.10.1 \
IP_A=10.0.10.240 IP_B=10.0.10.242 \
BIN=./target/release/stellaris-agent \
./scripts/test-docker-mdns-macvlan.sh
# OK: macvlan mDNS discovery + PSK works on real LAN.
```

用两个 macvlan 容器接入物理 LAN，完整验证 mDNS 发现、iroh 连接和 PSK。

### 16. 真实局域网 mDNS 验证

见 [REAL-LAN-MDNS.md](REAL-LAN-MDNS.md)。已在 macOS + bee 同一 /24 上验证：
- bee agent 发现 macOS mDNS 服务
- macOS `dns-sd` 发现 bee 服务

完整双向 agent 连接受 macOS firewall/local-network 权限影响，未宣称通过。

### 17. UDP bootstrap discovery（Linux netns）

```toml
[transport]
discovery_port = 47000
discovery_broadcast = "192.168.1.255:47000" # 可选；默认 255.255.255.255
```

```bash
sudo BIN=./target/release/stellaris-agent ./scripts/test-linux-netns-discovery.sh
# OK: UDP broadcast discovery + PSK works.
```

发现只产生候选 peer，仍必须通过 PSK/controller 认证。

### 18. Controller + 3 members（本机）

```bash
./scripts/demo-controller-3node.sh
```

一个 controller + 三个 member，验证 controller ACK、snapshot 成员、LSA 路由学习。

### 19. Controller + 3 TUN 节点（Linux netns）

```bash
sudo BIN=./target/release/stellaris-agent \
     CTRL=./target/release/stellaris-controller \
     ./scripts/test-linux-netns-3node-controller.sh
```

验证 controller 路由、LSA、TUN transit、双向 ping/1000B ping 和 controller status；2026-11-24 起失败会以非零退出（有断言）。转发成员需要 `capabilities=["transit"]`。

### 19. 单进程多网络 runtime

```bash
./scripts/demo-single-process-multi-network.sh
# OK: one agent process runs two isolated network runtimes.
```

启动方式：

```bash
stellaris-agent --config net-a.toml --config net-b.toml
```

每个 config 必须有独立 `state_dir` 和 network id/name。

### 20. 多网络凭证隔离

```bash
./scripts/demo-multi-network-isolation.sh
# OK: different network IDs reject the same PSK.
```

### 21.5 3 controller Raft E2E

真实 LAN（Docker macvlan）：

```bash
PARENT=enp1s0 SUBNET=10.0.10.0/23 GATEWAY=10.0.10.1 \
IP1=10.0.10.240 IP2=10.0.10.242 IP3=10.0.10.244 IP_CLIENT=10.0.10.245 \
BIN=./target/release/stellaris-controller \
./scripts/test-docker-controller-raft-macvlan.sh
# OK: 3 macvlan controller raft join/LSA/snapshot/failover/partition-recovery works.
# 脚本自动启用 Raft mTLS
```

```bash
cargo build -p stellaris-agent --bin stellaris-controller
./scripts/test-controller-raft-3node.sh
# OK: 3-controller raft join/LSA/snapshot/failover/crash-recovery works.
```

### 21.6 Raft TLS E2E

```bash
cargo build -p stellaris-agent --bin stellaris-controller
./scripts/test-controller-raft-tls-3node.sh
# OK: 3-controller raft TLS join/LSA/snapshot works.
```

### 21.6 Public exit + NAT44/NAT66

IPv4：

```bash
sudo BIN=./target/release/stellaris-agent ./scripts/test-linux-netns-exit-nat.sh
# OK: public exit + NAT44 works.
# NAT mapping consistent
```

IPv6：

```bash
sudo BIN=./target/release/stellaris-agent ./scripts/test-linux-netns-exit-nat66.sh
# OK: public exit + NAT66 works.
# NAT66 mapping consistent
```

### 21.7 Public exit + NAT44

```bash
sudo BIN=./target/release/stellaris-agent ./scripts/test-linux-netns-exit-nat.sh
# OK: public exit + NAT44 works.
# NAT mapping consistent
```

A 通过 exit B 访问 192.0.2.2；B 安装 MASQUERADE 并转发。

### 21.7 Dataplane IPv6 基础

- `node.overlay_ip` / `network.cidr` 可为 IPv6
- TUN 创建 IPv6 地址
- Linux/macOS IPv6 route 安装
- IPv6 outbound FIB / inbound local delivery 单测通过
- IPv6 gateway 支持 forwarding + NAT66（`ip6tables MASQUERADE`）
- Linux netns IPv6 TUN 双向测试：

```bash
sudo BIN=./target/release/stellaris-agent CTRL=./target/release/stellaris-controller \
  ./scripts/test-linux-netns-ipv6.sh
# OK: IPv6 TUN overlay bidirectional works.
```
- TCP MSS clamp：overlay MTU 1100 时 IPv4 MSS <=1060、IPv6 MSS <=1040
- IPv4/IPv6 分片解析：非首片不读取伪端口，分片 flow hash 保持一致
- 分片 ACL：首片决定 ACL verdict，后续分片复用；未见首片的分片 fail-closed
- 超大 inbound overlay 包会生成 ICMPv4 Fragmentation Needed / ICMPv6 Packet Too Big

### 21.8 Raft mTLS E2E

```bash
cargo build -p stellaris-agent --bin stellaris-controller
./scripts/test-controller-raft-tls-3node.sh
# OK: 3-controller raft TLS join/LSA/snapshot works.
```

脚本生成 CA/server/client 证书，启用 `raft_tls_require_client_cert=true`。

### 21.9 大 snapshot 分块

Raft snapshot > 4 MiB 时客户端自动走：

```text
POST /raft/snapshot/begin
POST /raft/snapshot/chunk
POST /raft/snapshot/finish
```

每块 2 MiB，总大小上限 512 MiB，最终 SHA-256 校验。

### 22. API / controller TLS

```bash
./scripts/test-tls.sh
# OK: API TLS, controller TLS, and member HTTPS snapshot work.
```

配置：

```toml
[api]
tls_cert = "/path/server.pem"
tls_key  = "/path/server.key"

[control]
tls_cert = "/path/server.pem"
tls_key  = "/path/server.key"

# member:
tls_ca = "/path/ca.pem"
```

TLS 只保护 HTTP 控制面；认证仍走 API token / `control.secret`。证书需使用 CA 签发的 server cert，不要把 CA 证书直接当 leaf 使用。

### 23. 旧 fanout/threshold 已移除

`control.urls` 和 `control.controller_threshold` 不再是有效配置：

- 非空 `control.urls` 会配置报错
- `control.controller_threshold != 1` 会配置报错
- 多 controller 一致性由 openraft 负责

### 24. 双网卡/跨批次

```bash
# 批2 双网卡 direct path failover
H1=root@... H2=root@... H3=root@... \
P1=192.168.0.162 P1B=192.168.0.164 P2=192.168.0.161 P3=192.168.0.163 \
./scripts/test-real-dualnic-multipath.sh

# 批1↔批2 公网 direct UDP / relay
./scripts/test-real-crossbatch-direct.sh
./scripts/test-real-crossbatch-relay.sh

# 成都 netns PMTUD 实验（命名空间已预先配置）
HOST=root@47.109.58.88 ./scripts/test-netns-pmtud-lab.sh
```

### 25. 真正的 TUN overlay（两台机器，需要 root）

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
scripts/                # demo-two-node.sh
examples/               # 示例 TOML
```

## 文档

| 文档 | 内容 |
|---|---|
| [ARCHITECTURE.md](ARCHITECTURE.md) | 完整实现架构与后续模块 |
| [PROTOCOL.md](PROTOCOL.md) | 控制协议/API/MeshHeader |
| [PLAN.md](PLAN.md) | 里程碑、Epic、第一 sprint |
| [GAPS.md](GAPS.md) | 能力/测试审计与未验证项 |
| [FOLLOWUP.md](FOLLOWUP.md) | 已接受的边界与后续工作 |
| [TEST-RESULTS.md](TEST-RESULTS.md) | 真实环境测试原始结果 |
| [ADVANCED-ROUTING.md](ADVANCED-ROUTING.md) | 静态路由、AZ 分段、subnet gateway 设计 |
| [PRIORITIES.md](PRIORITIES.md) | 当前缺口、优先级与下一阶段路线 |
| [MEMBERSHIP-AUTH.md](MEMBERSHIP-AUTH.md) | 入网、成员授权、前缀授权设计 |
| [MULTI-NETWORK.md](MULTI-NETWORK.md) | 多网络隔离与单进程多网络设计 |
| [REAL-LAN-MDNS.md](REAL-LAN-MDNS.md) | 真实局域网 mDNS 验证记录 |
| [OPENRAFT-HA.md](OPENRAFT-HA.md) | openraft controller HA 设计与实现记录 |
| [examples/policy.toml](examples/policy.toml) | ACL/QoS 配置示例 |
| [scripts/demo-linkstate.sh](scripts/demo-linkstate.sh) | controller-mediated link-state 演示 |
| [scripts/demo-distributed-linkstate.sh](scripts/demo-distributed-linkstate.sh) | 分布式 LSA/SPF 演示 |
| [stellaris-linking-routing-design.md](stellaris-linking-routing-design.md) | 路由/低功耗设计背景 |
| [stellaris-linking-architecture.md](stellaris-linking-architecture.md) | 早期架构与 Rust 选型 |
| [virtual-network-survey-2026-11.md](virtual-network-survey-2026-11.md) | 方案调研 |

## 已知限制

- controller 已完成 openraft quorum/leader election/mTLS/snapshot/failover；member 入口仍是单 URL（可指向 LB/任一 controller）。旧 fanout 已移除。
- 数据面 IPv4/IPv6 overlay 已启用；应用层 fragment reassembly/完整 PMTUD 状态机仍未实现。
- 初始 bootstrap 仍需要 controller URL 或静态 peer；之后可由 controller manifest/LSA `overlay_ip/addrs` 自动发现/连接。
- agent 的路由写 API 只接受 `scope=local`；network scope 目前只能通过 controller 配置/静态路由（`api.rs:365-369` 会拒绝 network scope）。
- ACL/QoS 支持 API 动态更新 + token-bucket + per-priority/per-class queue depth/bytes + DSCP；内置静态 Web UI（`crates/stellaris-agent/static/index.html`）只覆盖 peers/routes/status/policy。anti-spoof 允许 peer 自身 overlay IP + 它广告的前缀；subnet gateway 的 NAT66 目前仅 Linux（macOS 待做）。
- **控制帧没有 per-member 签名/Hello 挑战**：iroh 连接有 `network.auth.mode = "psk"` 双向认证，但控制帧本身没有逐成员签名；不要把这个 MVP 直接暴露在不可信网络。
- relay 建连、direct→relay 切换已测；relay 故障后会在旧连接关闭时经 `transport.relay_urls` 列表重连（实测约 60s，非秒级切换；多 relay 同时承载未实现）。生产建议自建 relay 并监控（见 AUDIT.md）。
- 2026-11-24 完成静态审计（[AUDIT.md](AUDIT.md)）并修复 P0：LSA 签名、transit 强制、OS 路由防护、iroh 走 Raft、Raft RPC 必须配 `raft_secret` 且有超时、签名 join、admin secret、routes/LSA TTL/epoch 入 Raft、动态 membership。仍没有第三方安全审计，MVP 仅用于开发/实验。
- 2026-11-24 新增的配置：`control.admin_secret`、`control.require_join_signature`、`control.lsa_ttl_secs`、`dataplane.allow_default_route`、`dataplane.replace_existing_routes`、`transport.disable_discovery`（测试用：强制 relay-only）；`transport.listen=false`、`routing.rib_mode!=full`、`set_path_hint` 现在会直接报错（此前被静默忽略）。子网网关/exit 转发需要给对应成员 grant `capabilities = ["transit"]`。

## 贡献

- 每个 PR 关联 issue；Conventional Commits。
- `cargo fmt --check`、`cargo clippy --all-targets -- -D warnings`、`cargo test` 必须全绿。
- 外部输入（packet/API）必须有边界检查/测试。


## 真实物理三主机

使用三台物理/云主机（root SSH，私网互通，已装 Rust）验证：

```bash
export H1=root@<public-1> H2=root@<public-2> H3=root@<public-3>
export P1=<private-1> P2=<private-2> P3=<private-3>
export BIN=/opt/stellaris/stellaris-controller

# Raft mTLS + failover
./scripts/test-real-3host-ha.sh

# IPv4 TUN overlay + 1000/2000-byte ping
export BIN=/opt/stellaris/stellaris-agent
./scripts/test-real-3host-overlay.sh

# IPv6 TUN overlay + 1200-byte ping
./scripts/test-real-3host-ipv6.sh

# direct -> relay roaming（阻断私网/公网 direct UDP）
./scripts/test-real-3host-roaming.sh
```

已在三台同 VPC 云主机上实际跑通：

- 3 controller + Raft mTLS + leader failover
- 3 agent IPv4 overlay，1000/2000-byte ping 0% loss（2000-byte 包经 1366-MTU TUN，验证分片转发 + 目的端重组）
- 3 agent IPv6 overlay，1200-byte ping 0% loss
- direct path -> relay path 切换
- 双网卡 direct path failover（.162 → .164）
- 跨批次公网 direct UDP / relay
- 深圳↔上海 25ms 公网 TUN overlay + 2000-byte 分片 ping
- 深圳/上海 3 controller 公网 quorum + mTLS + failover
- 跨地域 25ms TUN overlay + 2000-byte 分片 ping
- 成都 netns PMTUD：1500/1400/1300、tracepath、PTB 黑洞/恢复
- PMTUD: peer MTU、MSS clamp、TUN 自适应、2 MiB TCP 传输
