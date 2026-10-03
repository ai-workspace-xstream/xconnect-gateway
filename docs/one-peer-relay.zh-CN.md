# Gateway 的 One peer relay

Gateway 保持核心 relay 边界：接受 One 认证会话，依据 Zero 签名的网络成员和 `allowed_peers` 转发不透明 WireGuard 包。LAN 发现、探测、选择、故障切换由 One 路径管理器执行。设备注册、向 Zero 上报及未来 GPG / UUID / 用户 Auth 统一管理由 xconnect-edge-agent 承担。

新服务 `packaging/systemd/xconnect-gateway-relay.service` 执行 `xconnect-gateway relay --state-dir /var/lib/xconnect-gateway`，监听 loopback TCP 51821。既有 Xray VLESS / XHTTP / TLS 将该 TCP 目标路由到 relay，原 UDP WireGuard 转发保留。安装此新 unit 并执行 `systemctl daemon-reload`；Zero 签名配置启用 mesh 后，既有 up / sync 流程自动启动服务。关闭 mesh 时停止它。

relay 从 `<state-dir>/runtime/signed-config.json` 读取受保护的原始签名配置，校验签名、网络 / Gateway 绑定、generation 与 TTL，再读取既有 Gateway 私钥做 X25519 challenge 认证。运行期间每秒重载；TTL 更新保留会话，撤销成员或授权变更关闭受影响会话。无需给 Gateway 配置固定 One 名单或 LAN 地址。

数据面限制：每帧最大 8192 字节，每会话发送队列 64，最多 512 个待认证 / 活跃连接，认证超时 5 秒，空闲读超时 15 秒，并使用速率限制防止单会话阻塞其他设备。Gateway 不验证 peer 内层 HMAC，不持有 peer 间派生密钥；接收端 One 和 WireGuard 独立验证内层数据。

`<state-dir>/runtime/overlay-status.json` 提供非敏感服务状态，edge-agent 通过 `agent.overlayStatusPath` 只读采集并向 Zero 上报。

跨仓库验证：`tests/mesh/run.sh /path/to/XConnect-One /path/to/accounts`；需要 Go 1.26.4 和 PATH 内的 Xray。测试运行实际三 One WireGuard 和 Xray / XHTTP / TLS relay 链路，包含 LAN 切换、单设备对故障、TCP 延续和动态撤销。临时依赖 / 密钥在测试退出时清除。真实设备 UAT 尚需单独验证。
