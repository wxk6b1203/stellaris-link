# 入网与成员授权 — 实现说明

> 实现状态（2026-11-25）：**入网只有一种凭据** —— controller 签名的
> `MembershipCredential`。PSK、join token、`admission.mode` 的
> `legacy`/`allowlist` 已删除。签发入口是 `POST /v1/enroll`（HTTP，签名请求）
> 与 iroh 控制通道的 `Request::Enroll`（连接已由 node key 认证，无需额外签名）。
> 撤销、续签、grant 更新与 revision 防回滚均已落地。

> 关联：[PROTOCOL.md](PROTOCOL.md)、[OPENRAFT-HA.md](OPENRAFT-HA.md)、
> [README.md](README.md) §13。

---

## 0.1 三种认证模式

| `network.auth.mode` | 用途 | 认证方式 | 动态成员 |
|---|---|---|---|
| `none` | 隔离实验 | 无 | ❌ |
| `static` | 无控制面小网（2–10 台） | 只接受 `[[peers]]` 里的 node key；iroh 握手已完成 key 认证 | ❌（discovery 只能提供候选，未知 key 被拒） |
| `controller` | 生产/多节点 | controller 签名凭据（本文 §2–§5） | ✅ |

`static` 是 WireGuard 式模型：身份 = Ed25519 公钥（iroh endpoint id），授权 =
peer 的 `overlay_ip` + `advertised`，撤销 = 从配置删除。没有共享秘密，也没有
过期/自动轮换；需要这些时用 controller 或离线签发凭据。

## 0. 三个问题，三层解决

| 问题 | 答案 | 落点 |
|---|---|---|
| 这个节点是谁？ | Ed25519 公钥 = NodeId = iroh endpoint id | `identity.key` |
| 它是否属于这个网络？ | controller 签名的 `MembershipCredential` | iroh 握手 |
| 它能广告/转发什么？ | 凭据里的 `prefixes` + `capabilities` | LSA 校验、数据面 anti-spoof |

成员资格 ≠ 路由授权：一个合法成员默认只能使用自己的 overlay `/32`，要广告额外前缀或
转发他人源地址，必须在凭据里显式授予（`prefixes`、`transit`/`gateway`/`exit`）。

---

## 1. 信任根

| 角色 | 职责 | 密钥 |
|---|---|---|
| Controller | 决定谁能入网、签发凭据、撤销成员 | controller Ed25519 key（Raft leader 用自身 key 签） |
| Member | 提交 LSA、转发自己获授权的前缀 | node Ed25519 key（iroh endpoint） |
| Admin | 审批/撤销/改 grant | `control.admin_secret`（与 member secret 分权） |

节点只信任 `control.controller_keys` 里列出的 controller 公钥。HA 部署时把每个
controller 的 NodeId 都列进去；凭据的 `issuer` 必须是其中之一。

---

## 2. 凭据格式

```json
{
  "credential": {
    "network": "<network id>",
    "node": "<node id hex>",
    "overlay_ip": "10.7.0.2",
    "prefixes": ["192.168.50.0/24"],
    "capabilities": ["member"],
    "revision": 3,
    "issued_at": 1763996400,
    "not_after": 1764000000
  },
  "issuer": "<controller node id hex>",
  "signature": "<hex ed25519>"
}
```

签名字节：`stellaris-credential-v1|` + issuer 的 32 字节 + 凭据的规范化 JSON。

验证方（每个 peer）检查五件事：

1. `credential.network == 本地 network`（防跨网络重放）；
2. `credential.node == conn.remote_id()`（凭据只能由持有对应私钥的节点使用）；
3. `issuer ∈ control.controller_keys`；
4. Ed25519 签名有效；
5. `not_after > now` 且 `revision >= 本地已见该节点的最高 revision`。

凭据是**能力**而不是秘密：可以公开出示，对端验签即可，因此不需要在任何两个节点之间
分发密钥。这是它取代 PSK 的根本原因。

---

## 3. 签发、续签、落盘

```
member                         controller
  |-- POST /v1/enroll (signed) -->|
  |<-- 200 {credential} ----------|   已预注册 / 已审批
  |<-- 202 {pending:true} --------|   未知节点，进入 Raft 待审队列
  |<-- 403 revoked/denied --------|
```

- **预注册**：`[[control.members]]` 里的节点 enroll 时直接签发。
- **审批**：未知节点进入 `ControllerCommand::RequestAdmission`（Raft 复制）；
  管理员 `POST /v1/admissions/{node}/approve` 后，下次 enroll 拿到凭据。
- **续签**：member 在 `credential_ttl_secs` 的 2/3 时自动重新 enroll；
  凭据落盘到 `state_dir/credential.json`，重启后先复用，过期再续。
- **改授权**：`POST /v1/members/{node}/grants` 更新前缀/能力并递增 revision，
  不需要重新入网；member 下次续签拿到新凭据。

HTTP enroll 请求由节点私钥签名（`stellaris-enroll-v1|network|node|overlay|zone`），
因此抓包重放最多让 controller 重签一张同 node 的凭据，无法冒用身份。iroh enroll
没有签名步骤：QUIC 连接已经用 node key 认证，`conn.remote_id()` 就是身份。

---

## 4. 握手

连接建立后，双方在一条 bi-stream 上各发一帧 `SignedCredential`：

- 发起方：open_bi → 写自己的凭据 → 读对端凭据 → 验证；
- 接受方：accept_bi → 读对端凭据 → 验证 → 写自己的凭据。

验证通过后，双方把对方凭据转成 `Grant` 装进 `state.grants`，用于：

- 数据面 anti-spoof：源地址必须属于该 peer 的 overlay `/32` 或授权前缀；
  转发别人的源地址需要 `transit`/`gateway`/`exit` capability；
- LSA 校验：`lsa.origin` 必须有 grant，`overlay_ip` 必须与 grant 一致，
  LSA 里的前缀必须在 grant 内。

握手失败（无凭据、过期、revision 回滚、issuer 不受信）直接关闭连接并每 2s 重试；
`network.auth.mode = "controller"` 时不接受任何非凭据连接（fail-closed）。

---

## 5. 撤销

撤销的路径只有一条：controller 的成员表变化。

1. `POST /v1/revoke`、`deny`，或从 `control.members` 删除；
2. model 移除成员、递增该节点的 `member_revisions`、写入 `revoked` tombstone；
3. member 在下一个快照（≤10s）发现该节点不在 members 里：
   主动 `close` 连接（QUIC close code 3）、删除本地 grant，并把该节点的本地
   revision 下限抬到 `旧值 + 1`——即使撤销前签出的凭据还没过期，重连也会被拒；
4. 该节点后续 enroll 返回 403（tombstone），除非管理员重新 approve；
5. 即使对方重放撤销前的旧凭据，`revision` 也更低，会被拒绝；
6. `not_after` 兜底：controller 不可达时，最迟一个 TTL 后凭据自然失效。

---

## 6. 配置

controller：

```toml
[control]
secret = "member-secret"        # enroll 的共享门禁（可省略则仅靠签名+审批）
admin_secret = "admin-secret"   # admissions/revoke/grants
raft_dir = "/var/lib/stellaris/raft"
raft_secret = "raft-secret"
credential_ttl_secs = 3600

[[control.members]]             # 预注册（可选）
node_id = "<node>"
overlay_ip = "10.7.0.2"
prefixes = ["192.168.50.0/24"]
capabilities = ["member"]
```

member：

```toml
[network.auth]
mode = "controller"             # 唯一的生产模式

[control]
endpoint_id = "<controller endpoint>"   # 或 url = "https://controller:5801"
secret = "member-secret"
controller_keys = ["<controller node id>"]
```

`static` 模式示例（无需 controller）：

```toml
[network.auth]
mode = "static"

[[peers]]
name = "b"
endpoint_id = "<b node id>"
overlay_ip = "10.7.0.2"
advertised = ["192.168.50.0/24"]
```

`mode = "none"` 仅用于隔离实验：没有任何成员认证，discovery 需要
`transport.allow_unauthenticated_discovery = true` 才能开启。

---

## 7. 与旧机制的关系

| 旧机制 | 状态 | 原因 |
|---|---|---|
| `network.auth.mode = "psk"` + `secret` | 删除 | 整网共享秘密：无 per-node 撤销、轮换需全网、任意持有者可冒充 |
| `network.auth.allowed_nodes` | 删除 | 与 `control.members` 重复，且只是静态名单 |
| `control.join_token(s)` | 删除 | bearer token 可自助入网；scope 烧在 token 里，泄露即授权 |
| `control.require_join_signature` | 删除 | enroll 一律要求签名（iroh 侧由连接天然保证） |
| `admission.mode = legacy/allowlist/approve` | 删除 | 收敛成一条路径：预注册直接签发，否则审批 |
| `POST /v1/join` | 替换 | `POST /v1/enroll`，返回签名凭据而不是成员资格 |

---

## 8. 残余风险

- **controller 是单点信任**：controller 私钥泄露 = 可以给任意节点签发凭据。
  建议 controller key 离线保存/HSM，`controller_keys` 支持多把以便轮换。
- **没有逐帧签名**：连接由凭据认证，LSA 有 Ed25519 签名，但数据/控制帧本身不逐帧签名；
  连接内仍信任对端。
- **时钟**：`not_after` 依赖节点时钟大致同步；偏差过大会导致误拒，需要 NTP。
- **凭据可见性**：凭据不是秘密，泄露不构成风险；真正要保护的是 node 私钥和 controller 私钥。
- **HA 签发**：每个 controller 用自身 key；member 需要信任全部 controller key，
  且 `revision` 必须在 Raft 内单调（当前由 model 保证）。

---

## 9. 验证

- 单元：`credential::tests`（签名/篡改/过期/跨网络/revision 回滚/续签时机）、
  `controller_model::tests`（revision、tombstone、确定性快照）。
- 集成：`controller::tests::pre_registered_member_receives_credential`、
  `enrollment_is_queued_then_approved`、`enrollment_is_signed_admin_scoped_and_revocable`、
  `enrollment_rejects_a_signature_from_another_key`、
  `control_client::tests::http_enrollment_installs_a_credential`、
  `transport::tests::controller_credentials_gate_connections_and_install_grants`。
- 多进程/多机脚本：`scripts/` 下的 controller 测试已改为预注册或 enroll+approve 流程。
