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

## 3. 三地 rolling restart 失败（高优先级）

环境：Shenzhen/Shanghai/Chengdu 各一个 controller，公网 5701/5801 + mTLS。

现象：

- follower 2/3 重启后仍可写
- follower 3 重启时 leader 从 1 切到 2
- kill leader 2 后，node1/node3 都 `leader:null`
- 80s 无新 leader

需要：

- 开 Raft debug/tracing
- 查 log/term/vote 状态
- 是否 follower 重启后 log 落后导致无法赢得选举
- 是否测试脚本在重启后错误地杀掉/未启动节点
- 是否 rolling restart 顺序/选举超时需要调整

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
