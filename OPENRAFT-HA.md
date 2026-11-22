# Openraft Controller HA — 详细设计（未实现）

> 状态：H0 确定性模型 + H1 单节点持久化 + H2 3 节点 Raft/HTTP RPC/落盘 + controller API 写路径 + 3 controller 进程失败切换 + Raft TLS 已实现；mTLS、大 snapshot、真实多物理主机尚未完成。
> 当前实现：单 controller + 多 controller active-active fanout（pre-Raft）+ signed snapshot + epoch/manifest + 持久化 ACK。
> 目标：把 controller 从“内存状态 + fanout”升级为 **openraft 复制的确定性状态机**，提供 quorum、leader election、快照、成员变更和故障恢复。
> 关联：[ARCHITECTURE.md](ARCHITECTURE.md)、[PROTOCOL.md](PROTOCOL.md)、[PLAN.md](PLAN.md)、[PRIORITIES.md](PRIORITIES.md)。

---

## 0. 结论先行

Raft HA **不应直接套在现有 controller 上**。必须先做两件事：

1. **确定性状态机化**：把 routes/LSA/ACK/epoch 变成 `Command -> State` 的纯函数；
2. **身份与授权**：在 Raft 复制之前，先有一种可信的方式确认“谁可以提交命令”。

否则会得到“高可用地复制未授权写入”或“每次重放结果不同”的伪 HA。

建议顺序：

```text
Security/Hello + controller identity
      ↓
Deterministic ControllerModel + command log
      ↓
openraft single-node shadow
      ↓
3-controller cluster
      ↓
cutover from fanout
```

---

## 1. 目标与非目标

### 1.1 目标

- 3/5 controller 组成 Raft group。
- leader election、quorum write、线性化读。
- 持久化 log/vote/snapshot；重启恢复。
- controller 故障时，member 的 FIB 不被清空，写操作 fail-closed。
- manifest/epoch 在 Raft 内单调；旧 leader 被 fence。
- 成员/路由/ACK 状态可复制、可快照、可恢复。
- 提供迁移路径，保留现有 HTTP/iroh member API。

### 1.2 非目标（本阶段）

- 不做跨 region 多 Raft group / 多网络联邦。
- 不做 controller 与数据面同机故障域优化。
- 不做 Raft 之外的 Byzantine fault tolerance。
- 不做 controller 动态扩缩容的自动化（先支持手工 add/remove learner/voter）。
- 不把 member（agent）变成 Raft voter；只 controller 投票。

---

## 2. 当前 controller 状态与问题

当前 `ControllerState`：

```text
routes:      Vec<RouteEntry>        // 静态配置 + API
link_state:  LinkStateDb            // 由 LSA 汇总
acks:        HashMap<NodeId,u64>    // 持久化 JSON
generation:  AtomicU64
epoch:       u64
secret:      shared HMAC secret
```

Member 通过 HTTP/iroh 拉 snapshot，校验 HMAC，应用并 ACK。

问题：

1. **状态不是命令日志**：无法重放出确定的状态。
2. **LSA 含时间/连接状态**：RTT metric、TTL expiry 依赖本地 `Instant`/wall clock。
3. **RouteId 随机生成**：同一条命令在不同节点重放会产生不同 ID。
4. **fanout 无 quorum**：多 controller 各写各的，没有 split-brain 保护。
5. **安全边界不足**：shared secret + HMAC 能防篡改，但不能证明“某个 member 有权提交某条前缀”。
6. **ACK 与 snapshot 不是 Raft 状态**：当前 ACK 存在本地 JSON，无法保证多副本一致。

---

## 3. 目标架构

```text
                         ┌────────────────────────────┐
                         │ Controller Raft Group      │
                         │  c1 (leader)               │
                         │  c2 (follower)             │
                         │  c3 (follower)             │
                         └─────────────┬──────────────┘
                                       │ signed snapshot / ACK
              ┌────────────────────────┼────────────────────────┐
              │                        │                        │
        member a                  member b                  member c
        FIB/route query           FIB/route query           FIB/route query
```

- 一个 network 一个 Raft group；不同 network 不共享 log。
- controller 有独立身份（Ed25519）和稳定 `NodeId`。
- member 不参与投票，只提交 LSA/ACK/路由查询。
- controller 的 HTTP/iroh API 面向 member；Raft RPC 是内部接口，独立认证。

---

## 4. 确定性状态机

### 4.1 ControllerModel

```rust
struct ControllerModel {
    network: NetworkId,
    epoch: u64,                 // controller term/epoch，单调
    generation: u64,            // 状态版本
    routes: BTreeMap<Prefix, Vec<RouteIntent>>,
    lsas: BTreeMap<NodeId, LsaRecord>,
    acks: BTreeMap<NodeId, AckRecord>,
    members: BTreeMap<NodeId, MemberRecord>,
}
```

原则：

- 所有 key 用 `BTreeMap`/有序 Vec，保证 snapshot 可重复。
- 不把 `Instant`、`SystemTime`、随机 ID 放进状态。
- 时间相关行为通过 **leader 发出的命令** 表达。
- route 的 FIB 结果由纯函数 `compute(model, node)` 计算，不存派生 FIB。

### 4.2 命令

```rust
enum ControllerCommand {
    SetEpoch { epoch: u64 },
    UpsertRoute { id: RouteId, prefix: IpNet, via: NodeId, ... },
    DeleteRoute { id: RouteId },
    ApplyLsa { lsa: Lsa },
    ExpireLsa { origin: NodeId, up_to_seq: u64, now_ms: u64 },
    Ack { node: NodeId, generation: u64, epoch: u64 },
    SetPolicy { ... },           // 可选，后续
}
```

关键规则：

- `RouteId` 由 leader 在提交前生成；follower 只应用命令。
- `ExpireLsa` 是命令，不由每个副本本地时间自行判断。
- `ApplyLsa` 只接受 seq 更高；seq 相同是 no-op。
- `Ack` 幂等；generation 只能递增。
- `SetEpoch` 只能由 Raft leader 在当前 term 内提交。

### 4.3 时间与 TTL

不要在 `apply()` 里调用 `Instant::now()`。

方案 A（推荐）：

- LSA record 存 `last_seen_ms`/`expires_at_ms`；
- leader 周期性提交 `ExpireLsa { now_ms }`；
- follower 按命令中的 `now_ms` 删除；
- now_ms 来自 leader 时钟，命令进 log 后所有副本一致。

方案 B：

- 读时按 `last_seen + ttl` 过滤，但必须固定一个“读时钟”并写入 snapshot，否则不同副本结果不同。

MVP 选择 A。

---

## 5. openraft 0.10 集成

### 5.1 TypeConfig

```rust
openraft::declare_raft_types!(
    pub TypeConfig:
        D = ControllerCommand,
        R = CommandResult,
        Node = ControllerNode,   // id + raft addr + api addr
);
```

- `ControllerNode` 不能是 `()`：需要 Raft RPC 地址。
- `SnapshotData` 放 `Cursor<Vec<u8>>` 或 `Bytes`。
- `AsyncRuntime` 用 `TokioRuntime`。

### 5.2 存储

生产建议：

- log/vote：RocksDB、redb 或 SQLite（WAL + fsync）；
- state machine：同一事务域或独立 store；
- snapshot：本地文件 + 校验和 + generation；
- 必须实现 openraft storage conformance suite；
- 必须测试：`append` 返回前落盘、vote/log 顺序、truncate/purge 边界、snapshot 安装原子性。

原型可以用 `openraft-memstore`，但它**不是持久化存储**，不能直接作为生产实现。

### 5.3 网络

`RaftNetworkV2`：

```text
append_entries / vote / full_snapshot
```

实现选项：

- HTTP/2（axum + reqwest），独立 `/internal/raft/*`，mTLS 或 controller 间 Ed25519 签名；
- iroh control ALPN，独立于 member control ALPN；
- 必须校验 target 是预期 controller（防地址复用/重定向）；
- 实现 RPC timeout/backoff，`Unreachable` 语义；
- snapshot 分块 + 校验和 + 取消。

### 5.4 Bootstrap 与成员变更

```text
1. 三个 controller 启动，配置固定 node id/addr；
2. 选一个 pristine controller：initialize([c1,c2,c3])；
3. 其他节点作为 learner 加入（或 initialize 时直接三 voter）；
4. add_learner(blocking=true)；
5. change_membership(joint -> final)；
6. 新节点先同步 snapshot/log，再提升 voter。
```

生产要求：

- 禁止把已删除节点 ID 分配给新节点；
- 成员变更必须一次一个，观察 quorum；
- 保留旧成员信息用于审计；
- 提供 `controller status` 显示 leader/term/last_log/applied/snapshot。

### 5.5 读语义

- 写：只允许 leader；follower 返回 leader hint（HTTP 307/409 + `leader` 字段）。
- member snapshot 读：默认 **leader 线性化读**；
- 可选 follower read：显式 opt-in，接受 stale；
- `ensure_linearizable()` 后再构建 snapshot；
- snapshot 带 epoch/generation + controller 签名；member 校验。

---

## 6. 与现有 API 的兼容

### 6.1 写路径

```http
POST /v1/routes
Idempotency-Key: ...
If-Match: generation
```

- 非 leader：返回 `307` + `Location`/`leader`；
- leader：`client_write(ControllerCommand)`，等待 apply，返回结果；
- 超时：返回 503，不返回“可能已提交”的假成功；
- 重试必须幂等。

### 6.2 snapshot

```json
{
  "network_id": "...",
  "epoch": 7,
  "generation": 42,
  "leader": "...",
  "members": [],
  "routes": [],
  "signature": "..."
}
```

- 签名从共享 HMAC 迁移到 controller Ed25519（或双签名过渡）；
- member 校验 controller 公钥/manifest；
- epoch 不匹配 → 409/重新拉取；
- ACK 只接受当前 epoch 的 leader snapshot。

### 6.3 fanout 兼容

保留 `control.urls`：

- 迁移期 member 仍可 fanout；
- controller 检测到 Raft 已启用时，follower 不再本地提交，只转发 leader；
- 迁移完成后移除 fanout 写路径。

---

## 7. 故障模型与行为

| 故障 | 期望 |
|---|---|
| leader 宕机 | 新 leader 在 election timeout 内选出；member 保留旧 FIB；写暂停后恢复 |
| 少数派分区 | 少数派不能提交；读默认拒绝线性化；member 不应用新 snapshot |
| 旧 leader 恢复 | term 更高，旧 leader 降级；旧 epoch 写被 fence |
| follower 落后 | snapshot install + log catch-up；不提升为 voter 前完成 |
| controller 全部不可用 | member 保留最后 FIB，数据面继续；写 fail-closed |
| snapshot 损坏 | 校验和失败，拒绝安装，保留旧 snapshot |
| 时钟异常 | 只用 leader 命令时间；不依赖各副本本地时间做状态变更 |

### 7.1 写可用性

Raft quorum 丢失时：

- 路由/策略/ACK 写返回 503；
- 数据面继续用最后 FIB；
- member 不删除最后已知路由；
- UI 显示 `degraded`。

---

## 8. 安全前置条件

**必须在 Raft 之前完成**：

1. member `Hello`：
   - network_id、node_id、nonce、timestamp、epoch；
   - Ed25519 签名；
   - controller 维护 nonce 缓存。
2. controller 身份：
   - 固定 Ed25519 key；
   - member 配置 controller 公钥/指纹；
   - 禁止 TOFU 静默接受。
3. Raft RPC：
   - mTLS 或 controller 间签名；
   - 校验 target controller identity。
4. 授权：
   - 只有授权 member 能提交自己的 LSA/前缀；
   - gateway 前缀需要 `can_route` capability；
   - 路由写入需要 admin/controller 权限。
5. Secret/key 轮换：
   - 双 key 过渡；
   - 旧 key 过期拒绝。

没有这些，Raft 只是把未授权写入复制到多数派。

---

## 8.1 当前过渡：手动 leader fence

在 openraft 实现前，controller 支持：

```toml
[control]
leader_id = "<controller-node-id>"
```

- 只有签名身份等于 `leader_id` 的 controller 接受 LSA/join/revoke 写入
- 非 leader 返回 503
- 这不是自动 failover；leader 变更需要管理员更新配置/重启
- 成员侧仍使用 snapshot/manifest threshold

它用于在过渡期避免“多个 controller 同时接受写”的明显 split-brain，
最终仍需 openraft 的 term/leader/quorum。

## 8.2 H0：确定性状态模型（已实现）

新增：

```text
crates/stellaris-agent/src/controller_model.rs
```

- `ControllerModel`
- `ControllerCommand`
- 无墙钟时间
- LSA seq 幂等
- epoch 单调
- snapshot bytes 可复现
- revoke 清理 member/LSA

测试：

- 同一 command log 重放结果一致
- stale LSA/lower epoch 被忽略
- revoke 清理

它已经作为 **shadow model** 接入 HTTP controller：

- LSA/join/revoke/ack 会同步更新 model
- `GET /v1/model` 可查看 shadow 状态
- 命令以 JSONL 追加到 `state_dir/controller-commands.jsonl`
- 重启时按命令日志重放 model
- 尚未替换旧 controller 状态，也尚未接入 openraft

这是 Phase 0 的前置模型。

## 8.3 H1：单节点 openraft 原型（已实现）

新增：

```text
crates/stellaris-agent/src/controller_raft.rs
```

- `TypeConfig` 使用 `ControllerCommand` / `CommandResult`
- in-memory `RaftLogStorage`
- `RaftStateMachine` 直接 apply 到 `ControllerModel`
- snapshot 序列化 model
- single-voter `Raft::initialize`
- `client_write(ApplyLsa)` 测试通过

当前限制：

- log/vote/state 可落盘到 `raft-log.json` / `raft-state.json`（单节点测试通过）
- snapshot 数据仍主要从 state machine 重建；生产级 snapshot 文件/校验待做
- `RaftNetworkV2` 是 placeholder，只用于单节点
- 尚未接入 HTTP controller
- 尚未实现 3 controller bootstrap/membership

### H2：3 节点 Raft（已实现）

新增：

```rust
start_cluster(models)
```

- 3 个 `Raft` 实例
- in-process `RaftNetworkV2`
- 三 voter `initialize`
- leader 选举
- leader 写入并复制到所有副本
- leader shutdown 后重新选主并继续写入

测试：

```text
three_node_raft_commits_to_all_replicas
three_node_raft_survives_leader_failure
```

新增 HTTP RPC：

- `POST /raft/append`
- `POST /raft/vote`
- `HttpFactory` / `HttpNetwork`
- 3 节点通过真实 localhost HTTP 完成 leader 选举和复制

测试：

```text
three_node_raft_over_http
```

限制：

- HTTP RPC 支持共享 secret header（`x-stellaris-raft-secret`）
- 尚未使用 TLS/mTLS
- 3 节点可通过 `start_http_cluster_on_disk` 落盘并在整体重启后恢复
- 集群重启测试已验证（固定监听地址）
- snapshot 传输已实现（`POST /raft/snapshot` + `SnapshotRpc`）
- 已验证停掉的 follower 重启后通过 snapshot 追平（`restarting_follower_catches_up_via_snapshot`）
- snapshot RPC 带 SHA-256 checksum，服务端校验
- Raft HTTP body limit 64 MiB
- raft log/state 使用 fsync + atomic rename
- 大 snapshot 分块上传：`/raft/snapshot/begin` + `/chunk` + `/finish`（单块 2 MiB）
- 大包/断点恢复仍未测试
- controller 支持 `control.raft_dir` 启用单节点 Raft
- `/v1/lsa` 在 Raft 模式走 `client_write`
- `/v1/snapshot` / `/v1/model` 从 Raft state machine 生成
- join/revoke/ack 在 Raft 模式下也提交 `ControllerCommand`
- join token 消费集合已进入 `ControllerModel`
- Raft 模式下 LSA 前缀授权读取 model member grant

### H1 持久化验证

新增：

```rust
start_single_on_disk(model, dir)
```

测试：

```text
single_node_raft_recovers_from_disk
```

- 写入 LSA
- shutdown
- 同目录重启
- state machine 从磁盘恢复 LSA

## 8.4 3 controller 进程 E2E

脚本：

```bash
./scripts/test-controller-raft-3node.sh
```

验证：

- 3 个真实 `stellaris-controller` 进程
- Raft bootstrap
- leader election
- `/v1/join`
- `/v1/lsa`
- `/v1/snapshot`
- kill leader
- 新 leader 继续 LSA
- 新 leader snapshot 可见

结果：

```text
leader=1
snapshot ok
new leader=3
failover snapshot ok
crash recovery ok
OK: 3-controller raft join/LSA/snapshot/failover/crash-recovery works.
```

额外验证：`kill -9` leader 后重启原 leader，进程从落盘 Raft log/state 恢复，
识别新 leader、降为 follower，并通过 `/v1/model` 追平 seq=2。

## 8.5 真实 LAN 3 controller macvlan

脚本：

```bash
PARENT=enp1s0 SUBNET=10.0.10.0/23 GATEWAY=10.0.10.1 IP1=10.0.10.240 IP2=10.0.10.242 IP3=10.0.10.244 IP_CLIENT=10.0.10.245 BIN=./target/release/stellaris-controller ./scripts/test-docker-controller-raft-macvlan.sh
```

结果：

```text
leader=1
snapshot ok
new leader=3
failover snapshot ok
OK: 3 macvlan controller raft join/LSA/snapshot/failover/partition-recovery works.
```

3 个 controller 容器各自使用真实 LAN IP，通过 macvlan 运行独立进程，
并验证了旧 leader 断网后重新加入、降为 follower 并通过 `/v1/model` 追平 seq=2。
验证了非 loopback 地址上的 Raft、join、LSA、snapshot 和 leader 失败切换。

## 8.6 Raft TLS E2E

脚本：

```bash
cargo build -p stellaris-agent --bin stellaris-controller
./scripts/test-controller-raft-tls-3node.sh
# OK: 3-controller raft TLS join/LSA/snapshot works.
```

验证：

- 3 controller 进程
- HTTPS Raft `/raft/append` / `/raft/vote` / `/raft/snapshot`
- CA 校验
- mTLS client certificate
- shared secret
- join/LSA/snapshot

## 9. 迁移步骤

### Phase 0：确定性与影子状态机

- 引入 `ControllerModel` 和 `ControllerCommand`；
- 现有 controller 用同一命令更新内存状态；
- 增加 `compute_snapshot(model, node)`；
- 单测：同一命令序列在任意顺序/重复下结果一致。

### Phase 1：单节点 openraft shadow

- 启动 1 个 Raft controller；
- 写路径先 Raft，再更新旧 API；
- 对比 Raft state 与旧 state；
- 不切换 member 读写。

### Phase 2：3 controller cluster

- 3 节点 bootstrap；
- 故障注入、snapshot、重启；
- member 只连 leader（或 follower 转发）；
- 保留 fanout 读兼容。

### Phase 3：cutover

- 关闭 fanout 写；
- 切换签名到 controller key；
- 监控 drift/ACK；
- 保留回滚开关（回到 fanout 只读）。

### Phase 4：清理

- 移除 JSON ACK 持久化；
- 移除 fanout 写路径；
- 文档/运维手册。

---

## 10. 测试计划

### 10.1 单元

- 状态机 apply 幂等性；
- LSA seq/TTL 确定性；
- RouteId 由命令携带，不随机；
- snapshot encode/decode 稳定；
- epoch/generation 单调。

### 10.2 存储

- openraft storage conformance suite；
- vote/log 落盘顺序；
- truncate/purge；
- snapshot install 原子性；
- 重启恢复。

### 10.3 网络/集群

- 3 controller happy path；
- kill leader；
- kill follower；
- 少数派分区；
- 网络抖动/超时；
- snapshot install（新节点）；
- 节点重启；
- 成员变更 joint consensus；
- 旧 leader 恢复。

### 10.4 集成

- 3 controller + 3 member；
- member 路由/ACK；
- controller 全挂 → 数据面继续；
- 写 fail-closed；
- 迁移期 fanout + Raft 混跑。

### 10.5 混沌

- 随机 kill/restart；
- 时钟偏移；
- 磁盘满/慢；
- snapshot 损坏；
- 网络分区组合。

---

## 11. 运维

- `/metrics`：leader、term、last_log、applied、snapshot、replication lag、quorum。
- `/v1/controller/status`：leader、voters、learners、epoch、generation。
- 备份：snapshot + log；恢复演练。
- 升级：先滚动 follower，再 leader；检查 openraft 版本数据兼容。
- 节点替换：先 add learner，追平，再 change membership，最后移除旧节点。

---

## 12. 工作量与风险

粗估（1～2 名 Rust 工程师）：

| 工作 | 估算 |
|---|---:|
| 确定性模型/命令/快照 | 1～2 周 |
| openraft storage/network | 2～3 周 |
| 集群 bootstrap/成员变更 | 1 周 |
| 迁移/fanout 兼容 | 1 周 |
| 故障/混沌/性能测试 | 2 周 |
| 文档/运维 | 1 周 |

主要风险：

- 状态机不确定性导致副本 drift；
- snapshot 太大/太慢；
- Raft 网络与现有 iroh/HTTP 认证冲突；
- 迁移期双写不一致；
- 测试环境资源有限（aliyun 1.7G 内存）。

---

## 13. 待定问题

1. 一个 network 一个 Raft group，还是多 network 共享 controller group？
2. controller 与 relay 是否同进程/同失败域？
3. ACK 是否需要进入 Raft，还是只做可丢弃的观测数据？
4. LSA 是否全部进 Raft，还是只复制“成员/前缀意图”，路由由各 controller 本地计算？
5. snapshot 签名用 Ed25519 还是 controller quorum 多签？
6. 是否支持 follower read？默认关闭还是显式 opt-in？

---

## 14. 参考

- openraft getting started（RaftTypeConfig / RaftLogStorage / RaftStateMachine / RaftNetworkV2）
- openraft `raft-kv-memstore` 示例（仅原型，不是生产存储）
- 现有 `ARCHITECTURE.md` §6 controller/HA、§7 安全
- 现有 `PROTOCOL.md` §1 控制协议、§10 iroh controller
