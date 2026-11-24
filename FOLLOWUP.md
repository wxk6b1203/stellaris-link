# 后续工作标记

> 更新时间：2026-11-23
> 关联：[TEST-RESULTS.md](TEST-RESULTS.md)、[GAPS.md](GAPS.md)

当前接受的能力边界：

- 单路径 failover 可用
- 真正 multipath **不在当前范围内**
- snapshot controller HTTP 重启/同一 transfer 续传已实现
- 整集群滚动重启的真实 openraft 进程测试仍需补

---

## 1. 真正 multipath（后续，需要传输层改动）

现状：

```text
双 direct: path_count=1
双 relay:  path_count=1
100ms 延迟：不切换
20% 丢包：不切换
硬阻断：切换
```

需要：

- 多 connection / 多 endpoint
- 路径度量（RTT、丢包、成本）
- 调度器/负载均衡/聚合
- 数据面发送与接收去重

涉及：

- `crates/stellaris-agent/src/transport.rs`
- `crates/stellaris-agent/src/dataplane.rs`
- `PeerState` / 路径指标

---

## 2. Snapshot 滚动重启续传

已实现：

- transfer 元数据/`data.bin` 落盘
- controller HTTP server 重启后加载
- begin 幂等：同 `total` + `checksum` 返回原 transfer 和 `received`
- 客户端从 `received` 的 chunk 边界继续
- 单测 `snapshot_transfer_survives_http_restart`

仍需补：

- 真实 3 controller 进程滚动重启测试
- leader 进程重启时 openraft 重新触发 `full_snapshot` 后的端到端验证
- 不同 snapshot meta/checksum 的冲突处理
- transfer TTL 与滚动重启窗口协调

---

## 3. 三地 rolling restart：已通过，选举超时已产品化

已用 Shenzhen/Shanghai/Chengdu 三地公网 + mTLS 跑通：

- follower 逐个重启
- leader 最后重启
- 新 leader 选出
- 旧 leader 重新加入

根因：默认 `election_timeout_min=150ms` 对跨地域 vote RPC 太短，出现 `timeout after 150ms when Vote`；当时用环境变量 `STELLARIS_RAFT_ELECTION_TIMEOUT_MS=1000` 后通过。

已完成产品化（2026-11-24）：

- 新增正式 TOML 配置 `control.raft_election_timeout_ms`，省略时使用跨地域默认值
  `1000ms`（max `2000ms`、heartbeat `250ms`），即上面验证通过的值。
- 越界值（`50..=60000` 之外）在配置加载阶段报错。
- `/v1/status.raft` 与启动日志给出生效值和来源（`config` / `default-cross-region` / 废弃的 `env`）。
- 环境变量降级为兼容回退：仅当 TOML 未配置时生效并打 warn。
- `scripts/test-controller-raft-3node.sh` 改用 TOML 并断言生效值；本机 3 进程实测通过。
- `scripts/test-real-rolling-restart-ha.sh` 也改为写 TOML（未复跑，当前无测试主机）。

2026-11-24 用新一批临时主机（成都/深圳/上海）补测：

- 三地滚动重启用 TOML 复跑通过（`status.raft.source=config`）。
- 20% 丢包 + 50ms 单向时延下，leader 故障后 3.6s 选出新 leader，写/LSA/snapshot 正常。
- 5.57 MiB 模型走 2MiB 分块 snapshot 传输；2mbit 限速中断后部分数据保留（2097152 字节，重启前后一致）；全速重跑安装成功（follower generation 追平 leader）。

仍需：

- 限速中断后的"续传到完成"没观察到（90s 窗口 + 后续复测被编排问题打断），需要单独实验；
- 60s transfer TTL 在 2mbit 级慢链路上是否够用，需要和上面一起验证；
- 丢包/抖动下的滚动重启与 >4MiB snapshot；
- 长时间 soak。

资源需求（本轮无测试主机，只记录待开）：

- 3 台 Linux（Ubuntu 22.04/24.04，x86_64，1 vCPU / 1-2 GB / 20 GB）分属 3 个地域，
  都有公网 IP，互相可达 TCP `5689-6000`（脚本用 5701 raft / 5801 HTTP）。
- root + SSH key（22）；`tc`/`iproute2` 可用来注入 RTT/丢包。
- 二进制可在本机交叉编译后 scp，不必在每台机装 Rust。
- 用途：`scripts/test-real-rolling-restart-ha.sh` 用 TOML 复跑；netem 注入 20% 丢包/100ms RTT
  观察选举；制造 >4MiB snapshot 观察跨 WAN 续传。

## 3.1 其他后续

- 应用层 fragment reassembly
- Docker 双容器 bridge/mDNS/TUN 全量回归
- 动态 Raft membership
- WAN 丢包/抖动、大 snapshot 跨 WAN
- 大规模/soak/性能
- macOS/Windows NAT
- CI、tracing、dashboard、打包

---

## 4. 当前优先级

1. 真实 3 controller 滚动重启 snapshot 续传测试
2. 传输层 multipath（需要新设计）
3. 应用层 fragment reassembly
4. Docker/CI 回归
