# Stellaris Linking — Protocol & API

> 版本：v0.1（2026-11-22）
> 配套：`ARCHITECTURE.md`
> 范围：控制面 wire protocol、RouteQuery/RouteAdjust HTTP API、CLI 映射、版本/安全约定。
>
> **实现状态（2026-11-25）**：入网改为 controller 签名的成员凭据（`/v1/enroll`、iroh `Request::Enroll`），PSK/join token/`admission.mode` 已删除；HTTP controller 含 openraft HA、mTLS、snapshot/manifest、revoke/ack、`/v1/admissions`、`/v1/members/{node}/grants`、`/v1/raft/*`；iroh control 已实现 JSON 帧（签名 LSA/ACK、线性化快照）并走 Raft；ACL 支持 `deny_action=reject` 回 ICMP，数据面做分片重组。本文中的 protobuf/8MiB/Hello/nonce/Delta、`/v1/paths`、SSE、history/rollback 等仍是设计目标，未实现项以 [AUDIT.md](AUDIT.md) §5/§7 为准。

---

## 0. 总览

Stellaris 有两套接口：

| 接口 | 传输 | 编码 | 用途 |
|---|---|---|---|
| **Control protocol** | iroh bi-stream，ALPN `stellaris/control/1` | protobuf（`prost`） | agent ↔ controller：认证、manifest、snapshot/delta、route intent、ACK、heartbeat |
| **Management API** | HTTP/JSON（本地 Unix socket / 127.0.0.1 / overlay） | JSON + OpenAPI | CLI/UI/自动化：状态、路由查询/调节、诊断 |

数据面单独：

| 接口 | 传输 | 编码 | 用途 |
|---|---|---|---|
| **Data plane** | iroh datagram，ALPN `stellaris/data/1` | `MeshHeader` + IP packet | 承载 overlay IP 包 |
| **Overlay RouteQuery**（可选） | iroh bi-stream，ALPN `stellaris/query/1` | protobuf/JSON | 节点间只读路由查询 |

---

## 1. 控制面协议

### 1.1 ALPN 与帧

```text
ALPN: stellaris/control/1
```

每一帧：

```text
+----------------+----------------+-------------------------------+
| length: u32 BE | flags: u8      | protobuf Envelope (length B)  |
+----------------+----------------+-------------------------------+
```

- `length` = payload 字节数（不含 length 和 flags）；最大 **8 MiB**；总帧 5 + length。
- `flags`：bit0 = zstd 压缩；其余保留。
- 一条 iroh bi-stream 上可复用多个请求；`request_id` 关联请求/响应。
- 控制流与数据流分开 ALPN；控制流不承载 IP 包。

### 1.2 Envelope

```proto
syntax = "proto3";
package stellaris.control.v1;

message Envelope {
  uint32 version = 1;       // 1
  uint32 flags = 2;
  uint64 request_id = 3;
  oneof body {
    Hello hello = 10;
    HelloAck hello_ack = 11;
    JoinRequest join_request = 12;
    JoinResponse join_response = 13;
    SyncRequest sync_request = 14;
    Snapshot snapshot = 15;
    Delta delta = 16;
    RouteIntent route_intent = 17;
    RouteAck route_ack = 18;
    Heartbeat heartbeat = 19;
    Revoke revoke = 20;
    Error error = 21;
  }
}
```

### 1.3 认证

```proto
message Hello {
  bytes network_id = 1;     // UUID bytes
  bytes node_id = 2;        // Ed25519 public key
  uint64 epoch = 3;
  bytes nonce = 4;          // 32 random bytes
  int64 timestamp = 5;      // unix seconds
  bytes signature = 6;
  Capabilities caps = 7;
  string agent_version = 8;
}

message HelloAck {
  uint64 epoch = 1;
  bytes controller_id = 2;
  bytes nonce_echo = 3;
  int64 timestamp = 4;
  bytes signature = 5;
  uint64 manifest_generation = 6;
}

message Capabilities {
  bool can_route = 1;
  bool can_controller = 2;
  bool can_relay = 3;
  RibMode rib_mode = 4;
  uint32 max_routes = 5;
  uint32 mtu = 6;
}

enum RibMode { RIB_MODE_UNSPECIFIED = 0; RIB_MODE_FULL = 1; RIB_MODE_CACHE = 2; RIB_MODE_NONE = 3; }
```

`Hello.signature` 签名内容（domain separation）：

```text
transcript = b"stellaris-control-v1"
          || network_id (16)
          || node_id (32)
          || epoch (u64 BE)
          || timestamp (i64 BE)
          || nonce (32)
          || controller_id (32)
signature = Ed25519(node_key, SHA256(transcript))
```

- controller 校验：成员存在、epoch 匹配/可接受、timestamp ±5min、nonce 未复用、签名有效。
- `HelloAck.signature` 用 controller key 签同一 transcript + nonce_echo，agent 校验。
- 失败：返回 `Error{code=UNAUTHENTICATED|EPOCH_MISMATCH|NOT_MEMBER}`，关闭连接。

> **当前实现（2026-11-25）**：上面的 Hello 仍是设计目标。实际握手是在 iroh 连接上的一条
> bi-stream 里各发一帧 JSON `SignedCredential`（见 §10.1），由对端验证
> `network`、`node == conn.remote_id()`、`issuer ∈ controller_keys`、Ed25519 签名、
> `not_after`、`revision`。没有共享秘密，没有 nonce。

### 1.4 加入/同步

```proto
message JoinRequest { bytes network_id = 1; bytes node_id = 2; string invite = 3; }
message JoinResponse { bytes network_id = 1; bytes assigned_ip = 2; bytes manifest = 3; }

message SyncRequest {
  uint64 known_manifest_generation = 1;
  uint64 known_route_generation = 2;
}

message Snapshot {
  bytes manifest_payload = 1;   // postcard(Manifest)
  bytes manifest_signature = 2; // Ed25519
  uint64 manifest_generation = 3;
  uint64 route_generation = 4;
  repeated RouteEntry routes = 5;
  bytes checksum = 6;           // BLAKE3 of routes
}

message Delta {
  uint64 base_generation = 1;
  uint64 new_generation = 2;
  repeated RouteOp ops = 3;
  bytes checksum = 4;
}
```

- 签名对象（manifest/route intent）用 **postcard** 编码，避免 protobuf 非确定性；signature 覆盖 `domain || postcard_bytes`。
- `Snapshot` 超过 8 MiB 时：先压缩；仍超则分块（v2）；v1 限制 10k 路由。
- `Delta.base_generation` 与 agent 当前不一致 → agent 回 `SYNC_GAP`，controller 发全量。

### 1.5 路由对象

```proto
message RouteEntry {
  bytes id = 1;              // UUID
  bytes network_id = 2;
  bytes prefix = 3;          // 4/16 bytes + prefix_len
  uint32 prefix_len = 4;
  RouteSource source = 5;
  bytes origin = 6;
  bytes next_hop = 7;
  uint32 admin_distance = 8;
  uint32 local_pref = 9;
  uint32 metric = 10;
  uint32 weight = 11;
  bool pin = 12;
  uint64 generation = 13;
  int64 expires_at = 14;
  PathHint path_hint = 15;
}

enum RouteSource { ROUTE_SOURCE_UNSPECIFIED = 0; CONNECTED = 1; STATIC = 2; CONTROLLER = 3; LINK_STATE = 4; AGGREGATE = 5; DEFAULT = 6; }
enum PathHint { PATH_HINT_UNSPECIFIED = 0; AUTO = 1; DIRECT = 2; RELAY = 3; AVOID_RELAY = 4; }

message RouteOp {
  oneof op {
    RouteEntry upsert = 1;
    bytes delete_id = 2;
    bytes reset_prefix = 3;  // 可选
  }
}
```

### 1.6 RouteIntent / ACK

```proto
message RouteIntent {
  bytes intent_id = 1;
  bytes network_id = 2;
  Scope scope = 3;
  bytes payload = 4;        // postcard(RouteChange)
  bytes signature = 5;      // controller key
  uint64 generation = 6;
  int64 expires_at = 7;
}

enum Scope { SCOPE_UNSPECIFIED = 0; LOCAL = 1; NETWORK = 2; }

message RouteAck {
  uint64 generation = 1;
  bytes applied_hash = 2;   // BLAKE3(FIB)
  repeated string errors = 3;
}
```

- agent 校验 `generation` 单调、签名有效、scope/角色允许；应用后 ACK。
- controller 记录 `applied_status`；若 hash 不匹配 → 全量重同步。
- 重复 intent 幂等（intent_id + generation）。

### 1.7 Heartbeat / Revoke / Error

```proto
message Heartbeat {
  uint64 manifest_generation = 1;
  uint64 route_generation = 2;
  bytes fib_hash = 3;
  int64 timestamp = 4;
}

message Revoke {
  bytes node_id = 1;
  uint64 epoch = 2;
  string reason = 3;
  bytes signature = 4;
}

message Error {
  ErrorCode code = 1;
  string message = 2;
  string detail = 3;
}

enum ErrorCode {
  ERROR_UNSPECIFIED = 0;
  UNAUTHENTICATED = 1;
  EPOCH_MISMATCH = 2;
  NOT_MEMBER = 3;
  SYNC_GAP = 4;
  INVALID_REQUEST = 5;
  RATE_LIMITED = 6;
  INTERNAL = 7;
  UNAVAILABLE = 8;
}
```

### 1.8 时序

首次加入：

```text
agent                          controller
  |-- iroh connect(ALPN) ---------->|
  |-- Hello ------------------------>|
  |<--------------------- HelloAck --|
  |-- SyncRequest(0,0) ------------->|
  |<--------------------- Snapshot --|
  |-- RouteAck --------------------->|
  |-- Heartbeat -------------------->|
```

增量：

```text
controller                     agent
  |-- RouteIntent/Delta ----------->|
  |<--------------------- RouteAck --|
  |<--------------------- Heartbeat -|
```

重连 gap：

```text
agent: SyncRequest(known_route_gen=41)
controller: Delta(base=41) 或 Snapshot
agent: 应用 + RouteAck
```

---

## 2. 数据面协议

### 2.1 ALPN

```text
ALPN: stellaris/data/1
```

- 每个 peer 一条 iroh connection（可多网络复用）。
- 连接建立后，先通过控制流/`Hello` 认证网络成员；数据 datagram 只发 `MeshHeader + IP packet`。
- 未认证连接不接收数据。

### 2.2 MeshHeader（16 字节）

```text
+--------+--------+--------+--------+---------------------------+
| ver    | flags  | ttl    | rsv    | network_hash (u32)        |
+--------+--------+--------+--------+---------------------------+
| flow_hash (u32)              | reserved (u32)                 |
+------------------------------+--------------------------------+
| IP packet ...
```

- 网络字节序；`ver=1`。
- `flags`：bit0=control，bit1=ECN；其余 0。
- `ttl`：默认 64；转发减一；0 丢弃。
- `network_hash`：`SHA-256(network_id)` 前 32 位（不再使用 xxhash64）；manifest 启动时检测碰撞。
- `flow_hash`：5 元组哈希；0 表示未计算。
- 最大 datagram = `HEADER(16) + IP packet`；MTU 由 `max_datagram_size()` 推导。

### 2.3 认证与 anti-spoof

- 连接身份 = iroh endpoint key；`Hello` 绑定 network/epoch/nonce。
- 入站源 IP 必须在 peer 的 `allowed_src`：
  - 自己的 mesh IP/32；
  - 它通告的 subnet 前缀（`can_route`）；
  - 显式允许的 NAT 源（v2）。
- 失败：丢包 + `spoof_drop` + 限流日志。

### 2.4 Overlay RouteQuery（可选）

```text
ALPN: stellaris/query/1
```

- 只读；请求/响应 protobuf 或 JSON；mTLS/iroh 连接。
- 用于节点间排障/全局视图；默认关闭，ACL 限流。
- 请求：`Lookup{dst}`、`ListRoutes{view}`、`Explain{dst}`。
- 响应：同 HTTP API 的 `RouteExplain` schema。

---

## 3. HTTP Management API

### 3.1 约定

- Base：`/v1`；本地 Unix socket 或 `127.0.0.1`。
- Content-Type：`application/json`。
- 认证：`Authorization: Bearer <token>`；本地 socket 也要求 token（文件权限 + token 双保险）。
- 错误：

```json
{
  "code": "INVALID_ARGUMENT",
  "message": "prefix overlaps with existing route",
  "details": {"prefix": "10.7.0.0/16"},
  "tx_id": "tx-..."
}
```

- 幂等：`Idempotency-Key`；并发：`If-Match: <generation>`。
- 所有时间 RFC3339；所有 IP/CIDR 字符串。

### 3.2 查询

```http
GET /v1/status
GET /v1/peers
GET /v1/paths?peer=<node_id>
GET /v1/routes?view=intent|rib|fib&family=ipv4|ipv6
GET /v1/routes/lookup?dst=10.7.0.5
GET /v1/routes/explain?dst=10.7.0.5&verbose=true
GET /v1/events
```

`GET /v1/status`：

```json
{
  "node_id": "ed25519:...",
  "network_id": "018f...",
  "role": "member",
  "control_mode": "embedded",
  "rib_mode": "cache",
  "generation": 42,
  "controller": "ed25519:...",
  "uptime_secs": 3600,
  "tun": {"name": "stellaris0", "mtu": 1280},
  "transport": {"relay": "https://relay.example.com", "direct_peers": 3, "relay_peers": 1}
}
```

`GET /v1/routes/explain`：

```json
{
  "dst": "10.7.0.5",
  "selected": {
    "prefix": "10.7.0.0/16",
    "next_hop": "ed25519:b",
    "source": "link-state",
    "admin_distance": 100,
    "metric": 20,
    "path": ["ed25519:a", "ed25519:b"],
    "transport": {"path": "direct", "rtt_ms": 12}
  },
  "candidates": [
    {"next_hop": "ed25519:c", "metric": 35, "eligible": false, "reason": "higher metric"},
    {"next_hop": "ed25519:d", "metric": 20, "eligible": true, "reason": "ecmp"}
  ],
  "matched_policies": ["policy-7"],
  "generation": 42
}
```

### 3.3 调节

```http
POST   /v1/routes
PATCH  /v1/routes/{id}
DELETE /v1/routes/{id}
POST   /v1/routes/{id}/pin
POST   /v1/routes/{id}/drain
POST   /v1/policy
POST   /v1/links/{peer}/cost
POST   /v1/paths/{peer}/preference
GET    /v1/routes/history
POST   /v1/routes/rollback
```

`POST /v1/routes`：

```json
{
  "prefix": "192.168.1.0/24",
  "via": "ed25519:b",
  "scope": "local",
  "admin_distance": 1,
  "metric": 10,
  "weight": 100,
  "pin": true,
  "expires_at": "2026-11-23T00:00:00Z",
  "reason": "maintenance window",
  "dry_run": true,
  "if_match_generation": 42,
  "idempotency_key": "req-123"
}
```

响应：

```json
{
  "tx_id": "tx-...",
  "generation": 43,
  "dry_run": true,
  "diff": {
    "added": [{"prefix": "192.168.1.0/24", "via": "ed25519:b"}],
    "removed": [],
    "affected_nodes": ["ed25519:a", "ed25519:b"]
  },
  "warnings": ["next hop is currently offline; route installed but inactive"]
}
```

`scope`：

- `local`：只改本节点；agent 默认。
- `network`：全网；必须走 controller；`none` 模式返回 400（v1）。
- controller 默认 `network`；agent 收到 `network` 时转发或拒绝，不本地偷偷生效。

### 3.4 事件（SSE）

```text
event: route
data: {"generation":43,"change":"added","prefix":"192.168.1.0/24"}

event: peer
data: {"peer":"ed25519:b","state":"up","path":"direct","rtt_ms":12}

event: controller
data: {"connected":true,"epoch":7,"generation":43}
```

---

## 4. CLI 映射

| CLI | API |
|---|---|
| `stellaris status` | `GET /v1/status` |
| `stellaris peer list` | `GET /v1/peers` |
| `stellaris route list` | `GET /v1/routes` |
| `stellaris route explain <dst>` | `GET /v1/routes/explain` |
| `stellaris route add ...` | `POST /v1/routes` |
| `stellaris route update <id>` | `PATCH /v1/routes/{id}` |
| `stellaris route delete <id>` | `DELETE /v1/routes/{id}` |
| `stellaris route pin ...` | `POST /v1/routes/{id}/pin` |
| `stellaris route drain ...` | `POST /v1/routes/{id}/drain` |
| `stellaris link cost ...` | `POST /v1/links/{peer}/cost` |
| `stellaris path prefer ...` | `POST /v1/paths/{peer}/preference` |
| `stellaris route history` | `GET /v1/routes/history` |
| `stellaris route rollback <gen>` | `POST /v1/routes/rollback` |

---

## 5. 版本与兼容

- `Envelope.version = 1`；ALPN 后缀 `/1`。
- 加字段：只加 optional/重复字段，旧端忽略；不改变语义。
- 删/改字段：升 `/2`，双栈过渡。
- `RouteEntry`/`Manifest` 的签名 payload 用 postcard；字段顺序/默认值变更视为 breaking。
- 能力协商：`Hello.caps` + manifest `caps`；不支持的功能拒绝，不静默降级。
- 错误码稳定；`detail` 仅诊断。

---

## 6. 安全约定

- 控制/数据都走 iroh TLS 1.3；**0-RTT 禁用**；keylog 生产禁用。
- `Hello` nonce/timestamp/epoch 防重放；controller 维护 nonce 缓存。
- 签名域分离：`stellaris-control-v1`、`stellaris-manifest-v1`、`stellaris-route-intent-v1`。
- 不签“未规范化”的 JSON；签名对象用 postcard 或明确的 canonical bytes。
- 控制面消息限长/限速；单连接 in-flight 请求上限（如 64）。
- 管理 API 不允许匿名公网访问；默认 localhost/Unix socket。
- 证书/密钥轮换：manifest 过渡期允许旧 key 验证；过期后拒绝。

---

## 7. 参考

- iroh API：https://docs.rs/iroh
- prost：https://docs.rs/prost
- postcard：https://docs.rs/postcard
- OpenAPI：由 `utoipa` 生成，构建时输出 `openapi.json`

---

## 8. MVP HTTP controller（当前实现）

> 这是过渡实现；正式控制协议见第 1 节（iroh + protobuf + 签名）。

```http
GET  /v1/status          # 网络/generation/route/ack 数
GET  /v1/policy          # {acl, qos}
PUT  /v1/policy          # replace ACL/QoS policy, persisted
GET  /v1/snapshot?node=<id>  # {network_id, epoch, generation, members[{node_id,zone,overlay_ip,addrs,prefixes,links,last_seq}], routes[], signature}
POST /v1/routes          # {prefix, via, metric}
POST /v1/lsa             # LSA {origin,seq,zone,links[],prefixes[]}
POST /v1/ack             # {node, generation, epoch}
```

鉴权：`x-stellaris-secret: <control.secret>`（管理端点用 `control.admin_secret`）。`snapshot.signature` 是 HMAC-SHA256（控制面 secret）对 `{network_id,epoch,generation,members,routes}` 的签名，`ed25519_signature` 是 controller key 的签名；member 校验后才应用并回 ACK；member manifest 的 `overlay_ip/addrs` 用于自动发现/连接其他 member。ACK 带 epoch，epoch 不匹配返回 409；ACK 写入 `state_dir/controller-acks.json`。`/v1/lsa` 是 controller-mediated link-state 的拓扑上报入口；SPF 结果按 `?node=` 的本地视角计算。

入网（2026-11-25 起唯一入口）：

```text
POST /v1/enroll
{ "node_id": "<hex>", "overlay_ip": "10.7.0.2", "zone": "az-a",
  "addrs": ["192.0.2.2:41002"],
  "signature": "<hex Ed25519 over stellaris-enroll-v1|network|node|overlay|zone>" }

200 { "credential": { "credential": {...}, "issuer": "<hex>", "signature": "<hex>" } }
202 { "pending": true, "node": "<hex>" }        # 已进入 Raft 待审队列
403                                            # revoked/denied/签名错误
```

`/v1/admissions`（admin）列出待审；`/v1/admissions/{node}/approve|deny` 决策；
`/v1/members/{node}/grants` 更新前缀/能力并递增 revision；
`/v1/revoke` 撤销成员并写入 tombstone。`/v1/join` 已删除。

Member 配置：

```toml
[control]
url = "http://127.0.0.1:7800"   # 单入口；后端可以是 Raft leader/负载均衡
secret = "change-me"
```

Member 每 2 秒拉 snapshot；generation 变化时把 `source=controller` 的路由整体替换；local/static 路由保留并优先。controller 路由不持久化到 agent 的 `routes.json`。

---

## 9. 分布式 LSA（当前实现）

复用 iroh data connection，在同一个 ALPN 上开一条 bi-directional stream：

- 每端 `open_bi()` 一次，先发送 LinkStateDb 全量 LSA 快照，然后订阅本地 LSA 广播增量；
- 每端 `accept_bi()` 循环读取对端 stream；
- 帧格式：`u32 big-endian length` + JSON `ControlFrame`（`lsa`/`ping`/`pong`，最大 1 MiB）；
- 收到新 LSA（seq 更高）→ 更新本地 LinkStateDb → 本地 SPF → 转发给其他 peer；
- `seq` 由 LSA origin 单调递增，重复/旧 LSA 丢弃；
- 每 2s Ping/Pong；7s 无 Pong 认为 peer down，撤回本节点 LSA 中到该 peer 的 link 并重算路由。LSA 30s 未刷新即过期，controller/agent 都会清理；SPF 等代价下一跳会生成多条 RouteEntry，由 FIB 做 ECMP。
- LSA link metric 由当前 RTT（`rtt_ms/10`，最小 1）加跨 zone penalty 得到，并每 5s 重新发布；LSA 可携带 `overlay_ip` 与 underlay `addrs`；收到未知 origin 的 LSA 后，节点自动加入 PeerRegistry 并建立 iroh 连接（seed 仍来自静态 `[[peers]]`）。

当前 links/prefixes 来自静态 `[[peers]]` / `dataplane.advertise`；还没有动态邻居发现和 link-down 事件。

---

## 10. iroh controller control protocol（当前实现）

ALPN：`stellaris/control/1`。

Controller 配置 `control.iroh_port` 开启；member 配置 `control.endpoint_id` + `control.addrs`。每个请求/响应使用一条 bi-directional stream：

```
u32 big-endian length + JSON Request
u32 big-endian length + JSON Response
```

Request：

```text
snapshot { node?, secret? }
lsa      { lsa, signature, secret? }
ack      { node, generation, epoch?, secret? }
enroll   { overlay_ip?, zone?, addrs?, secret? }   # 节点身份 = conn.remote_id()
```

Response：

```text
snapshot   { snapshot }
ok         { changed, generation, epoch }
error      { code, message }
credential { credential }      # SignedCredential
pending    { node }
denied     { node, reason }
```

snapshot 与 HTTP 版本相同（epoch/members/routes/HMAC 签名）。member 校验签名后应用并回 ACK；ACK epoch 不匹配返回 409。

### 10.1 成员凭据握手（数据面 ALPN `stellaris/data/1`）

连接建立后，双方在一条 bi-stream 上交换一帧 `SignedCredential`：

```json
{ "credential": {
    "network": "<uuid>", "node": "<hex node id>",
    "overlay_ip": "10.7.0.2", "prefixes": ["192.168.50.0/24"],
    "capabilities": ["member"], "revision": 3, "not_after": 1764000000
  },
  "issuer": "<controller node id>", "signature": "<hex ed25519>" }
```

签名内容：`b"stellaris-credential-v1" || issuer(32) || canonical_json(credential)`。

验证失败（无凭据、过期、跨网络、issuer 不受信、revision 回滚）关闭连接。
成功则把凭据转成 grant，用于 anti-spoof 和 LSA 前缀校验（见 §2.3）。
