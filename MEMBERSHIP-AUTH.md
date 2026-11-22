# 入网与成员授权 — 设计

> 状态：设计稿；已实现 **PSK 双向 HMAC 入网认证 + allowlist**、controller Ed25519 snapshot 签名、controller 侧 member/prefix grant 校验、一次性 join token（HTTP `/v1/join`）、**独立 Ed25519 signed membership manifest（`GET /v1/manifest`）**、member 侧 LSA prefix 强制。
> 关联：[PRIORITIES.md](PRIORITIES.md)、[OPENRAFT-HA.md](OPENRAFT-HA.md)、[PROTOCOL.md](PROTOCOL.md)
> 目标：把“谁能加入网络、谁能让别人加入、谁能广告哪些前缀”设计清楚，再实现。

---

## 0. 先定义三个不同的问题

很多方案把这三件事混在一起，最后必然出问题：

1. **身份（Identity）**
   这个节点是谁？= Ed25519 公钥 / iroh EndpointId / NodeId。

2. **成员资格（Membership）**
   这个节点是否属于这个 Network？决定能不能交换数据/LSA。

3. **路由授权（Route Authorization）**
   这个成员能不能广告某个前缀、当 gateway、当 exit？决定流量能不能被劫持。

**成员资格 ≠ 路由授权。**
一个合法成员不应该自动获得“广告任意 0.0.0.0/0”的权利。

---

## 1. 信任根与角色

| 角色 | 职责 | 密钥 |
|---|---|---|
| Network Owner / Admin | 创建网络、定义入网策略、签发 join token | admin key（离线/HSM 更佳） |
| Controller | 审批加入、签发 membership manifest、下发路由 | controller Ed25519 key |
| Member / Agent | 运行数据面、提交 LSA、接收 manifest | node Ed25519 key（iroh endpoint） |
| Gateway / Exit | 广告 underlay 前缀、转发 | node key + `can_route` capability |

安全不变量：

- 控制器必须能验证“申请者拥有其 NodeId 对应的私钥”。
- 控制器签发的 membership 必须绑定 `network_id + node_id + overlay_ip + capabilities + epoch`。
- 非成员不能加入数据面，也不能提交 LSA。
- 成员只能广告被授权的前缀。
- 多网络之间不能重放凭证（domain separation）。
- 旧 controller/旧 epoch 不能继续写入。

---

## 2. 入网场景总览

| 场景 | 信任根 | 谁批准 | 凭证 | 适用 |
|---|---|---|---|---|
| 无 controller，小型/实验 | 共享 PSK | 无中心；持有 PSK 即可 | network PSK | 家庭/实验/离线 |
| 无 controller，受控 | 静态 allowlist + PSK | 管理员改配置 | PSK + allowed NodeIds | 小集群 |
| 单 controller | controller key | controller 自动/手工审批 | join token → signed manifest | 生产默认 |
| 多 controller | controller key set / quorum | leader/多数 controller | signed manifest | HA |
| 多网络 | 每网络独立 root | 每网络独立 controller/admin | 每网络独立凭证 | 多租户/多环境 |

---

## 3. 场景 A：没有 controller

### 3.1 最简单：共享 PSK

管理员生成：

```text
network_id + network_secret（高熵）
```

通过安全渠道分发给每个节点：

```toml
[network.auth]
mode = "psk"
secret = "..."
```

节点连接时执行 **双向 HMAC challenge/response**（已实现）：

```text
client -> server: network_id, node_id, nonce_c, HMAC(secret, domain|network|node|nonce_c)
server -> client: nonce_s, HMAC(secret, domain|network|node_c|node_s|nonce_c|nonce_s)
```

- 双方都证明持有 PSK；
- nonce 防重放；
- `network_id` 防跨网络重放；
- iroh TLS 负责链路机密性/完整性；
- 认证通过后才允许数据/LSA。

### 3.2 加强：PSK + allowlist

```toml
[network.auth]
mode = "psk"
secret = "..."
allowed_nodes = ["<node-a>", "<node-b>"]
```

- 知道 PSK 但不在 allowlist 的节点仍被拒绝。
- 适合 10～100 节点的小集群。
- 新增节点需要管理员更新每个节点的 allowlist（或至少 gateway/seed）。

### 3.3 谁处理“加入”？

没有 controller 时，**没有在线审批者**。加入 = 管理员在带外完成：

1. 生成/分发 PSK；
2. 把新节点 NodeId 加入 allowlist（可选）；
3. 给新节点 seed/peer 地址；
4. 新节点启动，PSK 握手通过即加入。

### 3.4 撤销

- 轮换 PSK（全量）/移除 allowlist（需要节点重启或热加载）。
- 无 controller 时无法瞬时撤销单个节点；只能缩短凭证寿命或引入 controller。
- 这是无 controller 模式的固有限制，不应假装支持即时吊销。

### 3.5 优点/缺点

优点：零依赖、离线可用、部署简单。
缺点：PSK 泄露 = 全网可加入；无在线审批；无细粒度前缀授权；撤销困难。

---

## 4. 场景 B：单个 controller

### 4.1 加入流程

```text
Admin creates network + join policy
        │
        ▼
Member generates NodeId key
        │
        ▼
Member -> Controller: JoinRequest {
  network_id, node_id, overlay_ip?, capabilities?,
  join_token, nonce, timestamp,
  signature(node_key, transcript)
}
        │
        ▼
Controller verifies token + signature + policy
        │
        ├─ auto-approve → MemberGrant + signed manifest
        └─ manual-approve → pending; admin approves
        │
        ▼
Member stores manifest; uses it for peer auth
```

### 4.2 Join token

两种：

- **一次性 token**：`id + secret`，controller 存 hash，使用后删除；
- **签名 token**：admin/controller 签 `{network, expires, max_uses, caps}`，可离线分发。

推荐一次性 token + 短有效期；token 只用于“申请加入”，不是长期数据面凭证。

### 4.3 Membership manifest

```rust
struct MembershipManifest {
    network: NetworkId,
    epoch: u64,
    generation: u64,
    issued_at: u64,
    expires_at: u64,
    controller: NodeId,
    members: Vec<MemberGrant>,
    signature: Ed25519,
}

struct MemberGrant {
    node_id: NodeId,
    overlay_ip: IpAddr,
    addrs: Vec<SocketAddr>,
    capabilities: Capabilities, // member | gateway | exit | relay?
    allowed_prefixes: Vec<IpNet>,
    zones: Vec<String>,
}
```

- Controller key 签发；
- member 配置 `controller_public_keys`；
- peer 连接时交换 manifest/grant，验证签名；
- LSA 的 prefixes 必须是 `allowed_prefixes` 子集，否则拒绝/降级。

### 4.4 Controller 不可用时加入

- 首次加入必须能联系 controller；否则只能使用预置的短期 manifest（bootstrap token）。
- 已加入成员保留最后 manifest 到过期；过期后进入只读/不允许新 peer。
- 不要让“controller 不可用”自动退化为 PSK 或 allow-any。

### 4.5 Controller 撤销

- controller 生成新 epoch/generation 的 manifest，移除成员；
- member 拉取/接收新 manifest；
- peer 校验 epoch/generation；旧 manifest 被拒绝；
- 被撤销节点保留本地 FIB 但无法新增 peer/路由；数据面可按策略立即丢弃其流量。

---

## 5. 场景 C：多个 controller

### 5.1 目标

- 无单点；
- 多 controller 对“谁加入/谁被撤销/哪些前缀合法”达成一致；
- member 能验证“这个 manifest 是合法 controller 签的”；
- 旧 controller 不能继续签发。

### 5.2 方案阶段

**C0（当前 fanout）**：

- 多个 controller 各自签发 HMAC snapshot；
- member 选择最高 `(epoch,generation)`；
- 没有 quorum，可能 split-brain；只用于过渡。

**C1（controller key set + leader）**：

- 每个 controller 有 Ed25519 key；
- member 配置 `controller_keys = [k1,k2,k3]`；
- 只接受 **leader** 的 manifest；
- controller 间用 leader lease/epoch fence；
- 仍不是 Raft，但能防止旧 leader 继续写。

**C2（openraft）**：

- controller 是 Raft voters；
- membership/route/LSA/ACK 通过 Raft log 提交；
- manifest 由 leader 签发，带 Raft term/epoch；
- member 只信任当前 leader + 签名；
- 详见 [OPENRAFT-HA.md](OPENRAFT-HA.md)。

### 5.3 多 controller 下的加入

- JoinRequest 发给 leader；follower 返回 leader hint。
- Leader 把 `AddMember` 写 Raft log；提交后签发 manifest。
- 多数 controller 确认后，成员才拿到有效 grant。
- 如果 leader 不可用，加入失败/重试；不在 minority 上“本地批准”。

### 5.4 多 controller 下的撤销

- `RevokeMember` 写 Raft log，epoch+1；
- 新 manifest 广播/拉取；
- 旧 manifest 在 grace period 后失效；
- 被撤销节点不能提交 LSA/路由。

### 5.5 信任配置

```toml
[control]
controller_keys = ["<ed25519-1>", "<ed25519-2>", "<ed25519-3>"]
# 或 threshold = 2
```

- member 不信任“任意 controller”，只信任配置的 key set；
- 支持 key rotation（old+new 双信任窗口）；
- 禁止 TOFU 静默接受新 controller key。

---

## 6. 场景 D：一个节点加入多个网络

### 6.1 原则

- **每网络独立身份上下文/凭证**，不能把网络 A 的 PSK/manifest 用于网络 B；
- 所有签名/HMAC transcript 必须包含 `network_id`；
- 每个网络独立 TUN、FIB、ACL、QoS、route engine；
- 跨网络转发明确禁止（除非未来做显式 gateway policy）。

### 6.2 当前实现

当前 agent 进程是 **单 NetworkConfig / 单 TUN / 单 FIB**。一个节点加入多个网络有两种落地方式：

1. **每网络一个 agent 进程**（当前可用）：
   - 不同 state_dir、TUN name、API port、overlay CIDR；
   - 同一 NodeId 可以复用，但每个网络独立 manifest/PSK；
   - 简单、隔离好，资源开销较大。

2. **单进程多网络**（P1）：
   - `Vec<NetworkRuntime>`；
   - 每网络独立 FIB/Policy/PeerRegistry/TUN；
   - 共享 iroh endpoint 时，连接上必须绑定 network；
   - 推荐每个网络独立 iroh endpoint/ALPN 或 network tag，避免串网。

### 6.3 凭证隔离

- PSK 派生 key：`HKDF(network_secret, salt=network_id)`，不同网络不同 key；
- manifest 签名覆盖 `network_id`；
- nonce 缓存按 `(network_id,node_id)` 分区；
- 禁止跨网络重放 LSA/ACK/Hello。

### 6.4 多网络地址

- overlay IP 可以重叠（不同 network namespace/TUN）；
- underlay 地址可共享，但 peer 必须绑定 network；
- controller 每网络独立，或 shared controller 带 network scope + RBAC。

---

## 7. 前缀授权（Route Authorization）

### 7.1 规则

```text
member 默认只能广告：
  - 自己的 overlay /32
  - manifest 中 allowed_prefixes
gateway/exit 才能广告其他前缀
```

### 7.2 检查点

1. controller 收到 LSA：检查 origin 的 grant；
2. member 收到 LSA：检查 origin 的 grant/manifest；
3. dataplane anti-spoof：源地址属于该 peer 的 grant；
4. controller 生成 snapshot：只包含授权前缀；
5. UI/explain：显示“未授权/拒绝原因”。

### 7.3 无 controller 模式

- 用静态 `PeerConfig.advertised` 作为 grant；
- 自动发现的动态 peer 只能广告自己的 /32，除非配置明确授权；
- 不要默认允许任何动态 peer 广告任意前缀。

---

## 8. 失败与边界

| 情况 | 行为 |
|---|---|
| controller 不可达（首次加入） | 加入失败；使用预置 bootstrap manifest 才可离线 |
| controller 不可达（已加入） | 保留最后 manifest 到 TTL；写操作暂停；不降级为 allow-any |
| manifest 过期 | 不接新 peer/新路由；已有流量按策略 |
| token 泄露 | 一次性 token 吊销；短 TTL；审计 |
| PSK 泄露 | 轮换 PSK；无 controller 时无法瞬时单点撤销 |
| 多 controller 分区 | 只有 quorum/leader 能签发；minority 拒绝写 |
| 旧 leader 恢复 | epoch/term fence；旧 manifest 被拒 |
| 跨网络重放 | transcript 绑定 network_id；拒绝 |
| 时钟偏差 | token/manifest 用 ±5min 窗口；nonce 缓存 |
| 节点 key 丢失 | 重新生成 NodeId；重新加入；旧 grant 吊销 |

---

## 9. 协议与代码落点

### 9.1 已实现

- `NetworkAuthConfig`：`none | psk` + `secret` + `allowed_nodes`；
- iroh 连接建立后、数据/LSA 前做 PSK handshake；
- 错误 secret 拒绝连接；
- controller Ed25519 snapshot 签名 + member `controller_keys` 校验；
- controller `control.members` allowlist / 每 member prefix grant；
- member 侧 controller threshold（同一 payload 至少 N 个不同 controller 签名）；
- member 侧对 LSA prefix 的 grant 强制（`lsa_authorized`）；
- 一次性 join token：`POST /v1/join`，member `control.join_token` 自动申请；token 支持 `expires_at`，过期/复用拒绝；
- `POST /v1/revoke`：撤销 member，移除其 grant/LSA/ACK，generation+1；strict membership 下空 grant 不会退化为 allow-all；
- membership grant 和已消费 join token 持久化到 `state_dir/controller-members.json`；LSA 表持久化到 `state_dir/controller-lsas.json`（30s TTL 内恢复）；controller 重启后保持；
- 独立 signed membership manifest：`GET /v1/manifest`，member 校验 Ed25519/expiry 后更新 grants；
- 未授权 LSA origin、overlay_ip、prefix、link target 被拒绝；
- 数据面 source 按 grant 检查；forwarding member 可携带其他已授权成员源地址；`transit` 保留给 gateway/exit 策略；
- 测试：`demo-psk-join.sh`、`demo-iroh-controller.sh`、`join_token_admits_once_and_grants_prefix`。

### 9.2 待实现

- 数据面前缀已由 controller grant + `transit` capability 约束；
- multi-network runtime；
- openraft command integration。

---

## 10. 推荐实现顺序（P0）

1. **PSK + allowlist**（已完成）
2. **Controller key + signed snapshot**（替代 shared HMAC）
3. **Join token + MembershipManifest/MemberGrant**
4. **Prefix authorization 检查**
5. **多 controller key set / leader fence**
6. **多网络 credential isolation**（先每网络进程，后单进程多 runtime）
7. **真实 3 节点测试 + 撤销/过期测试**

---

## 11. 测试矩阵

| 测试 | 期望 |
|---|---|
| 正确 PSK | 连接成功，数据/LSA 可用 |
| 错误 PSK | 连接拒绝，peer 不 connected |
| allowlist 外节点 | 拒绝 |
| 无 controller 离线加入 | PSK+seed 可加入 |
| 单 controller 正确 token | 签发 manifest |
| 过期/复用 token | 拒绝 |
| 无 grant 的前缀 LSA | 拒绝/过滤 |
| gateway 授权前缀 | 接受 |
| 撤销后旧 epoch | 拒绝 |
| 多 controller 少数派 | 不能签发 |
| 多网络跨用 PSK/manifest | 拒绝 |
| manifest 过期 | 不接新 peer |

---

## 12. 一句话

**没有 controller 时，加入是管理员带外分发 PSK/allowlist；有 controller 时，加入是 controller 验证 token 后签发 membership grant；多 controller 必须只让 leader/quorum 签发；多网络必须每个网络独立凭证和状态。**
