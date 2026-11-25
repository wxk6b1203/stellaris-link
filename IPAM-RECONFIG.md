# IPAM 地址热重配（设计与实现说明）

> 状态：**2026-11-26 实现（MVP）**。适用于 controller 模式、`node.ipam = "auto"`
> 的成员；静态 `overlay_ip` 不参与热重配。Linux 已验证，macOS/Windows 暂不支持
> TUN 地址热切换。关联：[IPAM.md](IPAM.md)、[PROTOCOL.md](PROTOCOL.md)。

---

## 1. 问题

`ipam = "auto"` 的地址来自 controller 凭据。当前成员只在启动时把凭据地址写入 TUN；
运行中 controller 改了地址，agent 只告警，需要重启。运维希望不重启进程完成换址。

## 2. 可行性结论

可行，边界是“**进程内热切换**”，不是“零中断”：

- controller 端可以原子地释放旧租约、分配/指定新地址、更新 member overlay 并 bump revision；
- agent 端已经有 `local_overlay` 状态，TUN 是单地址；可以在进程内 `ip addr flush/add`
  并让 LSA 在下一个 5s 周期发布新地址；
- 对端从 controller snapshot 拿到新 grant，anti-spoof 以新地址为准；
- 旧地址立即 release 并进入 quarantine，避免被复用。

代价：

- 切换瞬间在途数据包/已有 TCP 连接会断（TCP 通过重传恢复，不是无缝）；
- 旧 LSA 在新 LSA 发布前可能仍被对端短暂使用，最长 ~5s；
- 只有 Linux 的 `ip` 路径已实现；macOS/Windows 需要各自的地址管理命令；
- 如果 agent 重配失败，controller 已经切到新地址，需要人工回滚/再次 reassign。

## 3. Controller 设计

### 3.1 Raft 命令

```rust
ReassignAddress {
    node: NodeId,
    ip: Option<IpAddr>,       // None = 从池里自动选
    pool: Option<String>,
    zone: Option<String>,
    now: u64,
}
```

apply 语义（确定性，所有副本一致）：

1. 成员必须存在；`ip` 显式给定时必须在某个池的 CIDR/range 内、未被其他成员/租约/
   reservation 占用、且不在 quarantine；
2. 新地址不能等于旧地址；
3. 释放旧租约（按旧池 `quarantine_secs` 隔离旧地址）；
4. 给新地址分配租约（`lease_secs`，`now=0` 时不过期）；
5. 更新 `member.overlay_ip`，`bump_revision(node)`。

自动选地址时排除旧地址，避免“释放后立刻又选中自己”。

### 3.2 API

```text
POST /v1/ipam/leases/{node}/reassign
{ "ip": "10.66.0.9", "pool": "overlay-v4", "zone": "az-a" }   # 字段都可选
```

admin secret；成功返回 `{node, old, new, pool, revision}`；错误：404 成员不存在、
409 地址不可用/池不匹配、400 参数错误。Raft 模式走 `client_write`。

## 4. Agent 设计

1. `control_client` 收到新凭据，verify 后比较 `verified.overlay_ip` 与 `state.local_overlay()`；
2. 不同则调用 `dataplane` 句柄的 `reconfigure(new_ip)`：
   - Linux：`ip addr flush dev <tun> scope global`（IPv6 用 `-6`），
     `ip addr add <new>/<prefix> dev <tun>`（IPv6 加 `nodad`），`ip link set up`，
     `ip route flush cache`；
   - 失败则尝试恢复旧地址并返回错误，保留旧 `local_overlay`；
3. 成功后更新 `local_overlay`，link_state 下一次 tick 以新地址构造 LSA（seq 增加）；
4. 凭据落盘；重启后直接用新地址，不回到旧地址。

`DataplaneHandle` 保存 `dev/tun_name/prefix_len/current`，由 `dataplane::start`
在 TUN 创建后写入 `AgentState`；`DataPlane` 未启动时（启动早期）只更新 overlay，
TUN 创建时自然使用新地址。

## 5. 兼容与限制

- 仅 `node.ipam = "auto"`；静态配置地址不受 controller 影响。
- Linux 的 `ip` 命令可用时支持；macOS/Windows 的 reconfig 返回不支持错误。
- 不做双地址 grace：旧地址立即从 TUN 删除并 quarantine，换取实现简单和地址不复用。
- 不做“controller 等待 agent ack 再释放旧地址”的两阶段切换；如需零中断需要
  双地址/双 grant，列入后续。
- 地址族切换（v4↔v6）不在 MVP 内。

## 6. 验证（2026-11-26 完成）

- 模型：显式/自动 reassign、旧地址 quarantine、池外/已占用/revocation 场景。
- controller：API 鉴权、409、revision bump、credential overlay 更新。
- 真实本机 netns（两个 agent + host controller）：
  - `.1/.2` 初始互通；
  - A 在线 `reassign .1 → .9 → .10`，TUN 立即切换，B 感知 revision 后更新 peer
    overlay 并用新凭据重连；
  - B→新地址 0% loss，旧地址 100% loss；重启 A 仍用新地址。
- 已知限制：切换瞬间在途 TCP 会断；旧 LSA 最多 ~5s 才被新 LSA 替换；仅 Linux。
