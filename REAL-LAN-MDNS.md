# 真实局域网 mDNS 验证记录

> 日期：2026-11-22
> 环境：macOS 10.0.10.231 + Linux (bee) 10.0.10.42，同一 /24
> 服务类型：`_stellaris._udp.local.`

## 配置

两端：

```toml
[transport]
mdns = true
# 默认 5353；测试自定义端口时可设 mdns_port
```

macOS 端：

```toml
listen_port = 46731
bind_ip = "10.0.10.231"
advertise = ["10.0.10.231:46731"]
```

bee 端：

```toml
listen_port = 46732
bind_ip = "10.0.10.42"
advertise = ["10.0.10.42:46732"]
```

两端使用相同 network 和 PSK。

## 结果

### Bee 发现 macOS

bee agent 日志：

```text
INFO stellaris_agent::discovery: discovered peer via mDNS peer=289bd50bc2e1
```

### macOS 系统 mDNS 看到 bee 服务

```text
$ dns-sd -B _stellaris._udp local.
Browsing for _stellaris._udp.local.
... Add ... local. _stellaris._udp. stellaris-8f8b93bbf154
```

说明：

- 服务注册成功
- 局域网 multicast 可达
- bee 能 browse 到 macOS 服务
- macOS 系统 resolver 能 browse 到 bee 服务

### 未完成

macOS 上的 agent 没有完成双向 browse/连接：

- macOS firewall 为开启状态
- 未修改系统 firewall / Local Network 权限
- 因此没有声称“agent 双向自动发现+连接”已通过

自定义 `mdns_port=5354` 的测试也没有发现；标准 5353 才成功。

OpenWrt x86_64（10.0.10.239）可选测试未完成：

- 静态 musl `hello` 可运行
- 静态 musl agent 启动即 SIGSEGV
- 说明 OpenWrt 侧二进制/CPU/兼容性仍需排查，不是 mDNS 协议问题

## 容器替代验证（成功）

没有第二台 Linux 主机时，使用同一 Docker bridge 上的两个 Linux 容器：

```bash
BIN=./target/release/stellaris-agent ./scripts/test-docker-mdns.sh
```

结果：

```text
OK: container mDNS discovery + PSK works.
```

两个容器都：

- mDNS 发现对方
- 建立 iroh transport 连接
- 通过 PSK handshake

这验证了 Linux 网络栈上的完整 mDNS 发现 + 认证流程，只是不是物理 LAN。

## 结论

真实局域网 mDNS 的 **服务注册与 browse** 已验证：

- bee → macOS：agent 日志发现
- macOS → bee：`dns-sd` 发现

完整 agent 双向连接受 macOS firewall/local-network 权限阻塞，未在物理 LAN 上验证通过；
但 Docker bridge 容器已完整通过。

## 下一步

1. 在 macOS 上允许 `stellaris-agent` 的本地网络/入站连接
2. 或使用两台 Linux 主机（相同 /24）做完整双向 agent 测试
3. OpenWrt 需要排查静态 agent SIGSEGV
