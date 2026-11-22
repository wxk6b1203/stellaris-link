# 虚拟组网方案调研：有没有“全都满足”的现成控件？

> 调研时间：2026-11-22　范围：开源/可自建的虚拟组网（overlay）方案
> 结论口径：只写能查到的官方文档、Release、代码或许可证；推测和未确认项会明确标注。

## 0. 先给结论

**有现成的东西，但没有一款同时满足你列出的全部约束。**

最接近的六个方案，各自差 1～3 项：

| 方案 | 一句话定位 | 参照物 | 最大硬伤 |
|---|---|---|---|
| **EasyTier** | 去中心化、自带 OSPF 式自动路由、GUI/Web 控制台、多实例组网 | ZeroTier 的“无中心版” | 规模/安全审计/核心 RPC 鉴权偏弱，LGPL |
| **Tunnet** | Rust 新秀：Direct 无控制面 + Managed 控制面/UI，`tunnet route` 可查每节点路由 | 可自托管的 Tailscale + iroh | 极年轻（v0.9.1/244 stars），控制面不是“节点角色” |
| **ZeroTier** | 成熟的多网络 L2 overlay，Central API/UI，P2P 数据面 | ZeroTier 本尊（最成熟形态） | controller 已转非自由许可；常规模式必须建 TUN（需特权） |
| **Nebula** | 无中心控制面、证书体系、Slack 5 万+ 主机实证 | Slack 内部的安全 Mesh | 没有集中 GUI/API、路由全静态、无 TCP fallback |
| **Tailscale + Headscale** | 体验/ACL/API/规模最好，tsnet 可嵌入、免 root | 商业 SaaS 版 WireGuard 网状网 | 控制面必需；官方控制面闭源，Headscale 有功能差距 |
| **NetBird** | 开源自建版 Tailscale，netstack 全用户态、Dashboard/API | 自建版 Tailscale | Management 强制存在；控制面 AGPL；netstack 只有 SOCKS5 |

如果只能记一句话：**“无中心 + 用户态 + 成熟 API/UI + 大规模”这四件事在现成产品里是互相拉扯的；EasyTier 功能/成熟度平衡最好，Tunnet 形态最接近“控制面可选 + 路由查询 + UI”但最年轻，ZeroTier 最成熟，Nebula 最彻底地去中心，Tailscale/NetBird 体验最好但离不开控制面。**

---

## 1. 需求拆解：哪些是真需求，哪些是“物理上做不到”

先把你的描述拆成 10 条，并标出难度：

| # | 需求 | 难度 | 说明 |
|---|---|---|---|
| 1 | 用户态数据面 | 低 | 主流 overlay 都是用户态进程，不装内核模块 |
| 2 | 可选中心节点、支持 P2P | **高** | 控制面可以没有，但 NAT 穿透通常仍需发现/中继节点 |
| 3 | 构建虚拟网络（L2/L3） | 中 | L3 简单，L2（广播/组播/ARP）难 |
| 4 | 用户态创建网络接口 | **不可能（字面意义）** | 见 1.1 |
| 5 | 加入网络 + 自主发现路由 | 高 | 需要路由协议/拓扑同步，不能只靠静态配置 |
| 6 | 可视化 + 公共 API | 中 | 难在“控制面可选”时还要有统一 API |
| 7 | 安全 | 中 | 加密不难，难的是身份、ACL、审计、前向保密 |
| 8 | 大规模路由 | **高** | 全互联状态 O(N)，中继带宽是瓶颈 |
| 9 | 路由智能化 | 中 | 多数产品只是“打洞优先 + 中继回退 + 延迟测量” |
| 10 | 多网组网 / 网对网 | 中 | 多实例容易，跨网段路由和隔离难 |

### 1.1 必须澄清：“用户态创建网络接口”是个伪命题

TUN/TAP 是**内核对象**，不是用户态能凭空创建的：

- Linux：打开 `/dev/net/tun` 并 `TUNSETIFF`，需要 `CAP_NET_ADMIN`（通常是 root）。
- macOS：创建 `utun` 需要 root；或者走 Network Extension（需要 Apple 授权/签名，仍是系统扩展）。
- Windows：需要安装 WinTun/TAP 驱动（管理员），再由服务创建虚拟网卡。

所以桌面/通用场景只有三种做法，**没有第四种**：

| 模式 | 做法 | 代表 | 代价 |
|---|---|---|---|
| **A. 特权建接口 + 用户态数据面** | root/管理员只负责建 TUN，协议栈和加密都在用户态 | ZeroTier、Tailscale、EasyTier、Nebula、NetBird 常规模式 | 安装/启动需要特权 |
| **B. 无接口 + 用户态协议栈 + 代理/SDK** | 不创建 OS 网卡，用 gVisor/smoltcp 等用户态栈，向上暴露 SOCKS5/HTTP 或 `Dial/Listen` | Tailscale `--tun=userspace-networking` / `tsnet`、NetBird netstack、ZeroTier libzt/pylon、EasyTier `--no-tun` | 应用必须走代理或集成 SDK，不能“透明”访问虚拟 IP |
| **C. 预装驱动/助手** | 先装一次驱动或系统服务，之后普通用户使用 | Windows WinTun、macOS Network Extension、ZeroTier 服务 | 首次安装仍需管理员，且要做签名/公证 |

> 特例：Linux rootless 容器可以用 `slirp4netns`/`pasta` 在用户命名空间里建 tap，但这只解决“本地容器出网”，不是跨主机 overlay，也不适用于桌面应用透明访问。它不改变上面的结论。

**结论：**
- 你要“应用不用改、透明访问虚拟 IP” → 必须接受 A 或 C，**一定需要一次特权安装**。
- 你要“完全免 root、零安装” → 只能选 B，**没有系统级网卡**，只有代理/SDK。
- 任何声称“纯用户态创建网卡”的产品，基本都在偷换概念（指数据面），或者依赖了预装驱动/助手。

这条会直接筛掉一半候选：**Nebula 的 `tun.disabled` 只能做 lighthouse/relay，不能过 IP；ZeroTier 常规模式必须 TUN；EasyTier/NetBird/Tailscale 才有真正可用的“无 TUN”模式。**

---

## 2. 六个主方案逐一分析

> 下面按“成熟度/通用性”排序；Tunnet 因为最贴近本轮“控制面可选 + 每节点路由查询 + UI”的需求，单独放在 2.6，成熟度也最低。

### 2.1 EasyTier：功能重合度最高，但最年轻

- **版本/许可**：v2.7.1（2026-11-16），Rust，LGPL-3.0，约 1.5 万 stars。
- **中心节点**：**不需要**。节点对等，可用 `-p` 手动连任意节点；也可用公共共享节点辅助发现/中继，共享节点可自建，且“就是一个普通 EasyTier 网络”。控制面是 OSPF 式链路状态同步（`SyncRouteInfo`），不是厂商服务器。
- **用户态/免 root**：数据面可用 smoltcp 用户态栈；官方文档称 `--no-tun` 时**能被虚拟 IP 访问（TCP/UDP/ICMP）**、可做子网代理，但**不能主动访问别人**；主动访问要用 `--socks5` 或 `--port-forward`。TUN 模式在 Linux/Windows/macOS 仍需 root/管理员（macOS 有 Network Extension 代码路径，但发布版是否默认启用未确认）。
- **路由/多网**：子网代理自动同步并下发系统路由；默认最短跳数，`--latency-first` 延迟优先，维护两套下一跳；P2P 失败自动回退中继；支持 `--lazy-p2p` 降低 O(N²) 打洞。单进程多实例（多个 `-c`）、网对网、WireGuard 接入、端口转发、SOCKS5、出口节点。
- **API/UI**：桌面 GUI、Android/iOS、自建 Web 控制台（`easytier-web`）；核心是 protobuf RPC（`--rpc-portal`，默认 15888），CLI 可 `-o json`；**没有核心侧 HTTP REST**，且**未见 RPC 内建鉴权**，必须靠绑定 localhost/白名单/防火墙。Web 控制台文档还提示存在默认 `admin`/`user` 账号，生产必须改。
- **安全**：AES-GCM/WireGuard/Noise Secure Mode、ACL（IP/组/端口/限速）；但**没有公开的第三方安全审计**，旧模式下 `network_secret` 泄漏=全网可入。
- **规模**：官方没给节点数/压测；单流约 1.4 Gbps；链路状态全图使每节点状态随 N 线性增长，中继带宽是短板，社区有公网中继丢包报告。
- **适合**：想快速搭“无中心、能自动路由、有 GUI”的网；POC、内部工具、游戏/物联网组网。
- **不适合**：强合规、大企业 SSO/审计、需要成熟 SLA 的场景。

### 2.2 ZeroTier：最成熟，但 controller 许可变了

- **版本/许可**：1.16.2（2026-05）；Agent/core 是 MPL-2.0，**controller 在 `nonfree/`，2025 起改为 Source-Available，仅非商业免费，商业自建需授权**；1.16.0 起默认二进制不再包含 controller。
- **中心节点**：**每个网络必须有 controller**（签发成员证书、下发配置，Network ID 前 10 位就是 controller 地址）。controller 可自建（本地 `/controller` JSON API、`controller.d`），但受上面许可限制。唯一“无 controller”是 **ad-hoc 网络**：公开、主要 IPv6/6plane、仅 UDP/TCP 单播，不适合私密企业网。底层仍有官方 planet 根（多台）做发现/中继，可自定义 planet（企业向）。
- **用户态/接口**：协议栈在用户态进程内，但**建 TUN/TAP 要特权**：Linux `/dev/net/tun`，macOS 需要 root/系统扩展（feth/kext，常见 `PORT_ERROR`），Windows 虚拟网卡驱动。**真正免 TUN/免 root 的是 `libzt`/`pylon`**（进程内 socket 库 + SOCKS5，不创建接口）。
- **路由/多网**：单节点可同时加入多个网络（原生多网），Managed Routes 由 controller 下发（**不是动态路由协议自动发现**），Flow Rules 是 L2–L7 规则引擎（自定义规则仅高版本套餐）；支持 L2 桥接、多播、DNS、ZTNA。
- **API/UI**：本地 JSON API（`127.0.0.1:9993`，`X-ZT1-Auth`，含 `/controller`、`/metrics`）+ Central API v2（2026-04，OpenAPI 3.1、service account、webhook）+ New Central UI。第三方 ztncui 已基本停更。
- **安全**：Curve25519/Ed25519 + Salsa20/Poly1305；**官方明确没有前向保密**；没有 “network secret” 概念，私密性靠 `private` + 成员授权 + controller 密钥。
- **规模**：官网称 4M+ 设备；单 controller 理论 2²⁴ 网络/数百万设备。
- **适合**：要多网络、L2、成熟 API/UI、异构设备接入；能接受 controller 许可成本。
- **不适合**：要求全开源商用自建、要求前向保密、不能给用户 root/管理员。

### 2.3 Nebula：最彻底的“无中心”，但最不像产品

- **版本/许可**：v1.12.0（2026-10-29），MIT，约 1.85 万 stars，Slack 出品。
- **中心节点**：**没有控制面**。CA 离线签证书；lighthouse 只做地址登记/发现（默认 10s 上报），**可以完全不要**，用 `static_host_map` 直连；relay 是独立角色，任何节点都能当，不要求是 lighthouse。官方称“没有 lighthouse 也能组网”，但 NAT 穿透实践上通常至少需要一个可达节点。
- **用户态/接口**：`tun.disabled: true` 可让 lighthouse/relay **免 root 运行**，但官方明确：**该节点不能过 IP 流量、不能代理/转发**。常规节点 Linux 可给 `CAP_NET_ADMIN` 降权，但仍要建 TUN；macOS/Windows 建 TUN 仍需 root/管理员。
- **路由/多网**：**静态路由** `tun.unsafe_routes`（`route`/`via`/`mtu`/`metric`，v1.10 起支持 ECMP 多网关/权重），没有 BGP/OSPF/自动路由学习；lighthouse 只发现“peer 在哪”，不传播“peer 后面有什么网段”。单实例单 overlay，多网要多个实例。
- **API/UI**：**没有集中 GUI/API**；只有本地 `nebula ctl` 控制套接字（JSON 输出）、只读 info API（Unix socket 查证书身份）、Prometheus/Graphite 指标、SSH debug console。图形化要靠商业版 Managed Nebula 或社区控制面。
- **安全**：自建 PKI（CA/证书绑定 IP、名称、groups、unsafeNetworks）、Noise `ix_psk0`、X25519 + AES-256-GCM、防火墙按 group/CIDR、FIPS 模式、CA 轮换。
- **规模**：官方称 “tens of thousands”；文档史实 Slack 全球 5 万+ 生产主机（2021-12）。
- **适合**：大规模、自持 CA、无中心、极致简单稳定；能接受手工配置和没有 UI。
- **不适合**：要开箱即用的可视化/API、要动态路由、要免 root 的普通节点、要 TCP fallback。

### 2.4 Tailscale + Headscale：体验/规模最好，但控制面是硬依赖

- **版本/许可**：Tailscale 1.104/1.105（2026-11），客户端 BSD-3；官方控制面闭源。Headscale v0.29.7（2026-10-30），BSD-3。
- **中心节点**：**必需**。coordination service 负责身份、ACL→包过滤、NAT 协调、DERP 选路；数据面是设备间 WireGuard，能打洞就直连，失败回落 DERP。Headscale 可自建替代，但仍是中心。
- **用户态/接口**：`tailscaled --tun=userspace-networking` 无 TUN、**确实免 root**，退化为进程内 netstack + SOCKS5（v1.8+）/HTTP 代理（v1.16+）；本机应用只有走代理的进程能用，**不产生 OS 可见接口**。userspace 模式也能做 subnet router/exit node（netstack 转发），但只支持 TCP/UDP，性能低于内核。要“嵌入应用”用 **tsnet**：Go 库，进程内 TCP/IP 栈，`Dial/Listen`，同一进程多个独立节点，无需 root/daemon。
- **路由/多网**：subnet router、exit node、MagicDNS、ACL/Grants、多 tailnet（同组织/同 IdP/同域名）；Headscale 支持 routes/exit node/ACL/MagicDNS/内嵌 DERP，但 **Funnel、网络流日志、OIDC 组进 ACL 缺失**，无内置 UI，单实例单 tailnet。
- **API/UI**：官方 REST API v2 + OAuth + 管理台 + ACL 测试；Headscale 有 gRPC/REST，社区 headscale-ui。
- **规模**：官方未公布单 tailnet 硬上限（未确认）；公开数据约 250 万活跃设备、数万企业客户（2026，媒体/官网口径）。
- **适合**：要最少运维、强 ACL/MagicDNS、可嵌入 tsnet、能接受中心控制面。
- **不适合**：硬性“无中心”、要完全开源自建且功能对齐官方、要 Funnel/流日志。

### 2.5 NetBird：开源自建 + 用户态 netstack，最像“自建 Tailscale”

- **版本/许可**：v0.83.2（2026-11-20），约 3.1 万 stars。客户端 BSD-3；`management/`、`signal/`、`relay/` 是 **AGPLv3**。
- **中心节点**：**Management 强制**（注册、网络地图、IPAM、ACL/DNS 下发），Signal 只交换候选地址，Relay 是 TURN/WebSocket 兜底；三者都可自建（combined 单容器），可离线/air-gapped。
- **用户态/接口**：`NB_USE_NETSTACK_MODE=true` 用 gVisor netstack 替代 TUN，普通用户可跑；主要暴露 **SOCKS5**（默认 127.0.0.1:1080，无认证），**不支持 DNS**，只能按 IP 访问；没有透明代理/系统接口。`nblink` 是 NetBird 提供的免 root 端口转发工具（2026-11 文档），但目前**只支持 HTTP**，TCP/UDP/SOCKS5 计划中。
- **路由/多网**：Networks（Network/Resource/Access Policy/Routing Peer）、Routes（旧，deprecated）、Exit nodes；路由由管理员在 Dashboard 定义后自动下发，**不是自主发现**；一个账号可建多个 Network，多租户仅 Cloud MSP。
- **API/UI**：Dashboard + REST API + service account/PAT + 审计/活动日志；流量事件、SIEM、SCIM、EDR、peer approval 等需商业许可。
- **安全**：WireGuard、SSO/OIDC、setup key、ACL（nftables 落地）、Posture Checks（OS/版本/进程/证书等）。
- **规模**：官方 sizing 给出 6,000 用户实例、单 peer 31 Gbps（64 vCPU），用户态 datapath 约 6.8 Gbps 封顶。
- **适合**：要开源自建、Dashboard/API、P2P、netstack 免 root；能接受中心 Management。
- **不适合**：硬性无中心、要无 AGPL 约束的控制面、要 netstack 下透明访问/DNS。

### 2.6 补充：Tunnet（Rust，最贴近本轮新需求）

- **版本/许可**：v0.9.1（2026-09-02），Rust 2024，约 244 stars。agent/runtime/SDK 是 **MPL-2.0**；控制面/管理/仪表盘是 **AGPL-3.0-only**；protocol/clients 是 **Apache-2.0**；AGPL 组件可买商业许可。
- **控制面**：**两态**。Direct 模式完全无控制面（iroh-docs CRDT + Mainline DHT + signed grants/epochs/revocations），一个 agent 可加入多个 Direct 网络；Managed 模式有独立 control plane + management API + Dashboard + PostgreSQL，可自托管。
- **用户态/接口**：TUN + QUIC/iroh；需要 root/管理员建 TUN（文档未提无 TUN 模式）。
- **路由/多网**：每节点 `tunnet route list` 可查 subnet/hostname/exit 路由；支持 subnet routes、hostname routes、HA gateways、exit nodes、split tunnels、gossip presence；Direct 模式多网络。
- **API/UI**：Managed 有 Dashboard/REST 管理 API；Direct 模式明确没有 Dashboard/SSO/集中策略。
- **规模/成熟度**：非常年轻（0.9.x，244 stars，2026-11 仍有提交），规模未验证；**适合作为架构参考/测试 oracle，不建议直接依赖或 fork**。
- **适合**：要 Rust、要“无控制面 + 有控制面”两种形态、要现成 UI/路由 CLI 的团队。
- **不适合**：要“任意节点可当 controller”、要成熟 SLA/大规模验证。

### 2.7 其他值得知道的（一句话版）

| 方案 | 是否有中心 | 用户态/免 root | API/UI | 结论 |
|---|---|---|---|---|
| **n2n** | 通常必须有 supernode（可自建，否则要手工静态指定 peer） | 否，edge 要 root 建 TAP | 无 | 老牌轻量 L2，发布停滞（3.1.1/2022） |
| **tinc** | **无中心**，元连接自动全网状 | 否，TUN/TAP + root | 无 | 无 STUN/TURN 式打洞，静态配置，老派可靠 |
| **VpnCloud** | **无中心** P2P L2 | 否 | 无 | 2021 后无发布，不宜产品化 |
| **OpenP2P** | 无中心（共享节点辅助） | 是（应用层） | 有 GUI/API | **不是 L2/L3 overlay**，只是端口转发/共享 |
| **Netmaker** | 必须有 server（可自建/云） | 否（userspace WG 仍要 TUN） | 有 UI/REST | 自建 WireGuard 编排，非免 root |
| **OpenZiti** | controller + edge routers | 部分（SDK 可嵌入） | 有 console/REST | 零信任 fabric，**不保证 P2P**，重 |
| **Pangolin** | 必须自建 | 客户端用户态，服务端中心 | 有 GUI/API | 反向代理/ZTNA，**不是虚拟网卡 overlay** |
| **Yggdrasil / cjdns** | 无中心 | 否（TUN） | 弱 | 全局 IPv6 mesh，自动路由，但不是“加入一个 LAN”的语义 |

> 如果你的“控件”指**可嵌入的库**，最现实的三个是：`tsnet`（Go，需 Tailscale/Headscale）、`libzt`（C/C++，需 ZeroTier controller）、`wireguard-go/tun/netstack`（Go，低层，自己搭控制面）。EasyTier/NetBird/Nebula 都是 daemon/sidecar，不是嵌入式控件。

---

## 3. 对比矩阵

### 3.1 架构与能力

| 方案 | 中心节点 | 控制面 | 数据面 P2P | 免 root | TUN 依赖 | 路由自动化 | 智能选路 | 多网络 | 规模证据 |
|---|---|---|---|---|---|---|---|---|---|
| EasyTier | 不需要（共享节点可选） | 无中心，链路状态 | ✅ | 🟡 仅 `--no-tun` 被访问端 | 常规要 | ✅ 子网路由自动同步 | ✅ 延迟/跳数双路径、中继回退 | ✅ 多实例/网对网 | 无官方规模数据，1.4 Gbps |
| Tunnet | 可选（Direct 无 / Managed 有） | Direct 无 / Managed 中心 | ✅ | ❌ TUN 需特权 | 是 | 🟡 Direct 用 CRDT，Managed 控制面推送 | 🟡 iroh 路径/HA gateway | ✅ Direct 多网 | v0.9.1，规模未知 |
| ZeroTier | controller 必需（ad-hoc 例外） | controller 中心 | ✅ | 🟡 libzt/pylon | 常规要 | 🟡 controller 下发 Managed Routes | ✅ Bond 多路径/relay | ✅ 原生多网 | 4M+ 设备 |
| Nebula | 不需要（lighthouse 可选） | 无中心，CA 离线 | ✅ | ❌ 仅 lighthouse/relay | 常规要 | ❌ 全静态 | 🟡 打洞/relay/ECMP 静态 | 🟡 多实例 | Slack 5 万+ 主机（2021） |
| Tailscale | 必需（官方/Headscale） | 中心 | ✅ | ✅ userspace/tsnet | 否（userspace） | ✅ 控制面下发 subnet/exit | ✅ DERP/直连/route selection | 🟡 多 tailnet | 250 万+ 活跃设备（公开数据） |
| NetBird | 必需（可自建） | 中心 | ✅ | ✅ netstack | 否（netstack） | 🟡 管理员定义后下发 | ✅ ICE/relay/exit | ✅ 多 Network | 6,000 用户/31 Gbps |
| n2n | supernode 必需 | 中心发现 | ✅ | ❌ | 是 | ❌ | ❌ | ✅ 多 community | 中 |
| tinc | 无 | 无 | ✅ 全网状 | ❌ | 是 | ✅ 元连接 | ❌ | ✅ 多 netname | 中 |
| Netmaker | server 必需 | 中心 | ✅ | ❌ | 是 | 🟡 控制面下发 | 🟡 | ✅ | 中 |
| OpenZiti | controller 必需 | 中心 | ❌ 走 fabric | 🟡 | tunnel 要 | ✅ 智能选路 | ✅ | ✅ | 大 |

### 3.2 工程与合规

| 方案 | 公共 API | GUI | 安全 | 许可 | 成熟度/维护 | 主要短板 |
|---|---|---|---|---|---|---|
| EasyTier | 🟡 protobuf RPC（无核心 REST） | ✅ 桌面 + Web | 🟡 加密/ACL 齐全，无审计 | LGPL-3.0 | 活跃，较年轻 | RPC 无鉴权、默认账号、规模未验证 |
| Tunnet | 🟡 CLI + 管理 REST | ✅ Dashboard（Managed） | ✅ QUIC/iroh + ACL/策略 | MPL-2.0 + AGPL 控制面 | 很年轻（0.9.x） | 控制面非节点角色、规模未知 |
| ZeroTier | ✅ 本地 + Central v2 | ✅ Central | 🟡 无前向保密 | MPL-2.0 + controller 非自由 | 很成熟 | controller 商业授权、TUN 特权 |
| Nebula | ❌ 仅本地 ctl/info | ❌ | ✅ PKI/Noise/组防火墙 | MIT | 很成熟 | 无 UI/API、静态路由、无 TCP fallback |
| Tailscale | ✅ v2 | ✅ 官方 | ✅ ACL/SSO/Tailnet Lock | BSD-3（客户端） | 很成熟 | 控制面闭源/必需 |
| Headscale | ✅ gRPC/REST | 🟡 社区 UI | ✅ ACL/Grants | BSD-3 | 活跃 | Funnel/流日志/OIDC 组缺失，单 tailnet |
| NetBird | ✅ REST | ✅ Dashboard | ✅ SSO/ACL/Posture | BSD-3 + AGPL 控制面 | 活跃，0.x | Management 必需、netstack 无 DNS |
| n2n | ❌ | ❌ | 🟡 老 | GPL-3.0 | 发布停滞 | 无 API/UI |
| tinc | ❌ | ❌ | 🟡 老 | GPL-2.0+ | 稳定但慢 | 无 STUN 式打洞/API |
| Netmaker | ✅ REST | ✅ | ✅ | Apache-2.0（pro 商业） | 活跃 | 控制面必需、仍需 TUN |
| OpenZiti | ✅ REST | ✅ console | ✅ 零信任 | Apache-2.0 | 企业级 | 非 P2P、复杂 |

> 图例：✅ 满足/强；🟡 部分/有条件；❌ 不满足/没有。

---

## 4. 怎么选：按“第一硬约束”决策

### 4.1 决策树

```
你的第一硬约束是什么？

├─ 绝对不能有中心控制面
│   ├─ 规模/安全优先，能接受手工配置 → Nebula
│   ├─ 要 GUI/自动路由/多网，规模不大 → EasyTier
│   └─ 极小规模、老派静态 mesh → tinc
│
├─ 必须免 root / 嵌进应用
│   ├─ 能接受 Tailscale/Headscale 控制面 → tsnet
│   ├─ 能接受 ZeroTier controller → libzt/pylon
│   ├─ 能接受 NetBird Management → netstack
│   └─ 要无中心 → EasyTier --no-tun（但只能被访问 + SOCKS5/端口转发）
│
├─ 要多网络 + 成熟 API/UI + 大规模
│   ├─ 能接受 controller 商业许可 → ZeroTier
│   ├─ 能接受中心 Management/AGPL → NetBird 自建
│   └─ 能接受官方控制面 → Tailscale
│
├─ 要 Rust + 控制面两态 + 现成 UI/路由 CLI
│   └─ Tunnet（Direct/Managed；但很年轻，控制面不是节点角色）
│
└─ 要“全都差不多”，先做 POC
    → EasyTier（最快看到效果） + Nebula（验证无中心大规模） 各搭一套
```

### 4.2 按场景的直接建议

| 场景 | 推荐 | 代价/注意 |
|---|---|---|
| 个人/小团队，想 10 分钟组网，最好免 root | **EasyTier** `--no-tun` + 共享节点 | 只能被访问端；主动访问走 SOCKS5；生产要改默认账号、锁 RPC |
| 企业多网络、L2、要 API/UI、能接受许可 | **ZeroTier** | controller 商业授权；TUN 需管理员；无 PFS |
| 大规模、自持 CA、绝对无中心 | **Nebula** | 无 UI/API、路由静态、配置重；普通节点仍需 root/CAP_NET_ADMIN |
| 要最少运维、强 ACL、可嵌入应用 | **Tailscale + Headscale/tsnet** | 控制面必需；Headscale 有功能差距 |
| 要开源自建、Dashboard/API、P2P、netstack | **NetBird** | Management 强制；控制面 AGPL；netstack 无 DNS |
| 只要端口级内网穿透，不要虚拟网卡 | **OpenP2P / frp** | 不是 overlay，没有路由发现 |
| 要零信任应用访问，不要 P2P | **OpenZiti / Pangolin** | 中心 fabric/反代，不是虚拟 LAN |

### 4.3 “最接近全都要”怎么排

按你的 10 条需求做**主观重合度**（不是性能排名）：

1. **EasyTier**：无中心、自动路由、多网、GUI、用户态/免 root 都有；差在规模证据、安全审计、核心 API 鉴权。**功能最像，成熟度最不像。**
2. **ZeroTier**：多网、API/UI、P2P、用户态数据面、规模都强；差在 controller 许可、TUN 特权、无 PFS。**最成熟，但“无中心”不彻底。**
3. **Nebula**：无中心、大规模、安全最强；差在 UI/API、动态路由、免 root 数据面。**最纯粹，最不产品化。**
4. **Tailscale/Headscale**：体验、ACL、API、规模、tsnet 都强；差在控制面必需。**最好用，但“无中心”直接不满足。**
5. **NetBird**：开源自建、API/UI、netstack 免 root；差在 Management 强制、AGPL、netstack 能力有限。**最像自建 Tailscale。**
6. **Tunnet**：形态最接近你的新要求（Rust、Direct 无控制面 / Managed 有控制面+UI、每节点 `tunnet route`），但 v0.9.1/244 stars，成熟度最低；暂不作为生产首选，作为架构参考/测试 oracle 最合适。

### 4.4 市场空位在哪

- **“无中心 + 企业级 API/UI + 大规模”没有一款同时做到**：Nebula 有“无中心 + 大规模”，但没有集中 API/UI；EasyTier 有“无中心 + API/UI”，但规模/审计未验证；ZeroTier 有“API/UI + 大规模”，但控制面非自由且必须有 controller。
- **“控制面三态（无 / 节点角色 / 独立服务）+ 每节点路由查询 API + UI”是明确的空位**：Tunnet 有“无 / 独立服务”，但没有“任意节点当 controller”；ZeroTier 有“节点角色”，但没有“无控制面”；EasyTier 有“无控制面”，但没有 controller 角色。
- **“可嵌入 SDK + 无中心”也基本空白**：`tsnet`/`libzt` 都依赖中心控制面；`netstack` 只是底层积木，不提供发现/路由/策略。
- 因此，如果做产品，差异化最可能是：**把 Nebula 级的安全/规模，和 EasyTier 级的自动路由/UI 结合，并把控制面做成“单机 / 自建 / 托管”三种形态可选**。这也是 `stellaris-linking` 这类项目最有机会的位置。

---

## 5. 如果你要做的是 `stellaris-linking`

> 更细的“三态控制面 + 每节点路由查询 API + Rust 技术栈/里程碑”见：[stellaris-linking-architecture.md](stellaris-linking-architecture.md)。

从目录名看，你更像要**做一个产品/控件**，而不只是选一个用。这里给三条路线，按投入从低到高：

### 路线 A：Fork EasyTier，补产品化（最快，3～6 个月）

- **做什么**：保留它的 P2P/OSPF 路由/多实例/子网代理；外面加 REST/GraphQL API、RPC 鉴权、租户/网络模型、审计、Web 控制台加固、Prometheus 端点、规模压测。
- **优点**：不用从零写 NAT 穿透、路由收敛、跨平台 TUN；功能重合度立刻到 80%。
- **风险**：LGPL-3.0（Rust 静态链接的合规要法务评估）；上游架构改动跟随成本；规模/安全需要自己补。
- **关键改造**：`--rpc-portal` 默认只绑 localhost + token；去掉默认 `admin/user`；给 `--no-tun` 加 HTTP CONNECT/SOCKS5 鉴权；补 macOS Network Extension 签名；补 1000+ 节点收敛测试。

### 路线 B：WireGuard 数据面 + 自研控制面（最可控，12～18 个月）

- **数据面**：`wireguard-go`（用户态 WireGuard）+ `tun/netstack`（gVisor 用户态 TCP/IP）；需要 TUN 时用系统 TUN，不需要时用 netstack + SOCKS5/SDK。
- **NAT 穿透**：Pion ICE，或参考 `frp/pkg/nathole` 的 NAT 分类 + 打洞；STUN 参考 `tailscale/net/stun`、`net/netcheck`、`net/portmapper`。
- **中继**：QUIC/WebSocket 隧道（参考 `cloudflared/carrier`），或 DERP 式 relay；TURN 可用 coturn。
- **路由**：EasyTier 式链路状态（序列号 + TTL + 子网路由公告），或 Babel/OSPF 简化版；必须做 route aggregation、lazy P2P、relay 选择，否则 1000 节点就崩。
- **控制面（可选）**：Headscale 式中心（身份/ACL/IPAM/证书）+ 可嵌入的单机模式；无中心时用 network secret + 本地配置 + gossip。
- **优点**：许可干净（WireGuard MIT/BSD、gVisor Apache-2.0、Pion MIT），可控可审计，能做成真正的“控件”。
- **风险**：NAT 穿透、跨平台接口、路由收敛、安全审计四座大山；建议只做 1～2 个平台先验证。

### 路线 C：tsnet / NetBird 二开（最快上线，但中心化）

- **tsnet + Headscale**：Go 项目直接嵌入，`Dial/Listen` 即用，免 root；控制面用 Headscale 自建。适合“应用内嵌组网”的控件。
- **NetBird 自建**：直接拿它的 Management/Signal/Relay + 客户端，补自己的 UI/业务；注意控制面 AGPL。
- **优点**：1～3 个月可上线，安全/ACL/规模经过验证。
- **代价**：永远有中心；Headscale 功能差距；NetBird 0.x 变动快。

### 5.1 可复用的本地参考仓库

| 本地路径 | 能复用什么 | 许可/注意 |
|---|---|---|
| `wireguard-go/tun/netstack/tun.go` | `CreateNetTUN()` 返回 `tun.Device` + `Net`，直接 `DialTCP/UDP`、`ListenTCP/UDP`、`DialPing`，无需 OS 接口 | MIT；gVisor 依赖较重 |
| `tailscale/tsnet/` | 嵌入式节点：`Server.Dial/Listen`、`LocalClient`、多实例、无 root | BSD-3；需要 Tailscale/Headscale 控制面 |
| `tailscale/wgengine/netstack/` | 生产级 gVisor netstack 集成、subnet/exit 转发 | BSD-3；与 Tailscale 内部耦合深 |
| `tailscale/net/netcheck`、`net/portmapper`、`net/stun` | NAT 类型检测、UPnP/PMP/PCP 端口映射、STUN | BSD-3；可直接抽用 |
| `tailscale/derp/` | DERP 式中继协议/客户端/服务端 | BSD-3；协议与 Tailscale 生态绑定 |
| `frp/pkg/nathole/` | NAT 分类、打洞模式推荐、成功回馈 | Apache-2.0；偏 TCP/UDP 端口级 |
| `frp/pkg/vnet/` + `doc/virtual_net.md` | Alpha 的 TUN 虚拟网络（frp VirtualNet） | Apache-2.0；alpha，仅 Linux/macOS，需 root |
| `cloudflared/carrier/` | QUIC/WebSocket 隧道传输 | Apache-2.0；偏反向隧道，不是 overlay |
| `ZeroTierOne/node/Bond.hpp`、`Topology.hpp` | L2、多路径 Bond、peer/relay 拓扑设计参考 | MPL-2.0；controller 在 `nonfree/`，勿混用 |
| `ZeroTierOne/service/OneService.cpp` | 本地 JSON API 路由设计（`/network`、`/peer`、`/metrics`） | MPL-2.0；可参考 API 形状 |

### 5.2 不要自己从零造的东西

- 加密算法/握手：用 WireGuard/Noise，不要自研。
- NAT 穿透：STUN/ICE/打洞，直接用 Pion/frp/tailscale 的实现。
- 中继/TURN：coturn 或 DERP 式实现。
- 跨平台驱动：WinTun、macOS Network Extension、Linux TUN，不要自己写驱动。
- 控制面身份：OIDC/SSO、证书轮换，接现有 IdP。

### 5.3 选型/验收清单（POC 时逐条打勾）

- [ ] 两端都在 symmetric NAT / CGNAT 下，能否直连？不能时 relay 延迟/带宽是否可接受？
- [ ] macOS 非 root、Windows 非管理员能否完成你要求的模式？失败时错误是否可诊断？
- [ ] 1,000 节点（或你的目标规模）路由收敛时间、内存、CPU、重连风暴表现？
- [ ] 中继节点 100 Mbps / 1 Gbps 时的延迟、丢包、公平性？
- [ ] RPC/API 是否默认鉴权？Web 控制台是否有默认口令？能否只绑 localhost？
- [ ] 多网络网段冲突、隔离、跨网访问策略是否可控？
- [ ] 升级/回滚是否兼容？配置是否可声明式管理/导出？
- [ ] 许可证是否允许你的分发方式（LGPL 静态链接、AGPL 控制面、controller 商业授权）？
- [ ] 安全：是否前向保密、是否审计、密钥轮换、ACL 默认拒绝？
- [ ] 可观测性：是否有 Prometheus/日志/事件/拓扑图？ API 能否自动化？

---

## 6. 最终建议

1. **先做 1 天 POC**：EasyTier 两节点 `--no-tun` + 一个共享节点，验证“免 root 被访问 + SOCKS5 主动访问 + GUI 看拓扑”；同时用 Nebula 两节点 + lighthouse，验证“无中心 + 证书 + 静态路由”。这两个 POC 能让你很快感受两种极端的取舍。
2. **如果“无中心”是硬约束**：生产选 **Nebula**（大规模/安全）或 **EasyTier**（功能/UI）；接受“没有集中 API/UI”或“规模/审计待验证”。
3. **如果“成熟/多网/API”优先**：选 **ZeroTier**（接受 controller 许可）或 **NetBird 自建**（接受 Management 强制/AGPL）；要最少运维就 **Tailscale + Headscale**。
4. **如果要做产品**：不要在“全都要”上硬刚；先选一个**明确的取舍**：
   - 卖“无中心/数据主权” → Nebula/EasyTier 路线；
   - 卖“开箱即用/企业 ACL” → NetBird/Tailscale 路线；
   - 卖“可嵌入控件” → tsnet/libzt/netstack 路线。
5. **一句话**：现成的东西存在，但你要的是一套**组合 + 二次开发**，不是一个“打开开关就全都有”的控件。

---

## 7. 主要参考

**EasyTier**
- https://github.com/EasyTier/EasyTier （v2.7.1，LGPL-3.0）
- https://easytier.cn/guide/network/no-root.html （--no-tun 能力边界）
- https://easytier.cn/guide/network/decentralized-networking.html （无中心）
- https://easytier.cn/guide/network/web-console.html （自建 Web 控制台/默认账号）
- https://easytier.cn/guide/network/point-to-networking.html （子网代理自动路由）
- https://easytier.cn/guide/config/acl.html （ACL）
- https://easytier.cn/guide/network/secure-mode.html （Noise Secure Mode）

**ZeroTier**
- https://github.com/ZeroTier/ZeroTierOne （v1.16.2）
- https://github.com/ZeroTier/ZeroTierOne/blob/dev/nonfree/LICENSE.md （controller 非自由许可）
- https://docs.zerotier.com/controller/ （本地 controller API）
- https://docs.zerotier.com/protocol/ （ad-hoc、无 PFS）
- https://docs.zerotier.com/proxy/ （libzt/pylon 免 TUN）
- https://docs.zerotier.com/what-is-a-controller/ （2²⁴ 网络/数百万设备）

**Nebula**
- https://github.com/slackhq/nebula （v1.12.0，MIT）
- https://nebula.defined.net/docs/config/tun/ （tun.disabled 边界）
- https://nebula.defined.net/docs/guides/host-discovery/ （lighthouse 只做发现）
- https://nebula.defined.net/docs/guides/unsafe_routes/ （静态路由/ECMP）
- https://nebula.defined.net/docs/guides/local-control-and-info-api/ （本地 ctl/info API）
- https://nebula.defined.net/docs/guides/running-nebula-as-non-root/ （CAP_NET_ADMIN）

**Tailscale / Headscale**
- https://github.com/tailscale/tailscale （BSD-3）
- https://tailscale.com/docs/concepts/userspace-networking （userspace 模式）
- https://tailscale.com/docs/reference/kernel-vs-userspace-routers （netstack 转发限制）
- https://tailscale.com/docs/features/tsnet （嵌入式）
- https://github.com/juanfont/headscale/blob/main/docs/about/features.md （Headscale 差距）

**NetBird**
- https://github.com/netbirdio/netbird （v0.83.2）
- https://docs.netbird.io/about-netbird/how-netbird-works （Management/Signal/Relay）
- https://docs.netbird.io/use-cases/cloud/netbird-on-faas （netstack）
- https://docs.netbird.io/client/nblink （免 root HTTP 转发）
- https://github.com/netbirdio/netbird/blob/main/LICENSE （BSD-3 + AGPL 控制面）

**Rust 参考**
- https://github.com/tunnetio/Tunnet （Tunnet：Direct/Managed、route CLI、Dashboard）
- https://github.com/n0-computer/iroh （P2P QUIC/打洞/relay）
- https://github.com/tun-rs/tun-rs （跨平台 TUN）
- https://github.com/databendlabs/openraft （controller HA）

**其他**
- https://github.com/ntop/n2n （n2n）
- https://www.tinc-vpn.org/ （tinc）
- https://github.com/dswd/vpncloud （VpnCloud）
- https://github.com/openp2p-cn/openp2p （OpenP2P）
- https://github.com/gravitl/netmaker （Netmaker）
- https://github.com/openziti/ziti （OpenZiti）
- https://github.com/fosrl/pangolin （Pangolin）
