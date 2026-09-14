# XConnect Gateway 自建安装与接入验证

XConnect Gateway 是独立 Linux relay/service。它与 XConnect One 使用相同的
Zero 网络协议，但角色不同：Gateway 提供 VLESS/TLS 入口并维护服务端
WireGuard peer；One 只维护自己的受控客户端运行时。

## 安装入口

`install.svc.plus` 应只托管经过审核的安装脚本。脚本从已批准的
GitHub Release 或内部镜像取得带 `SHA256SUMS` 的制品；它不会读取
Vault、Zero 邀请、TLS 私钥或 WireGuard 私钥。生产环境显式固定版本：

```sh
curl -fsSL https://install.svc.plus/xconnect-gateway | \
  XCONNECT_GATEWAY_VERSION=v0.1.5 bash
```

Gateway 仅支持 Linux `amd64` / `arm64`。私有 Release 使用受控镜像时，
由管理员设置 `XCONNECT_GATEWAY_RELEASE_BASE_URL`；镜像必须保持
`/<tag>/<asset>` 和 `/<tag>/SHA256SUMS` 结构。

## 主机准备

预先安装并固定受信任来源的：

- `xray`，支持 VLESS/TLS、XUDP 和 UDP `dokodemo-door`；
- `wireguard-tools`（`wg`、`wg-quick`）及 Linux WireGuard 内核支持；
- `systemd`、路由工具和用于服务端 TLS 的证书链。

TLS 证书和私钥从 Vault 注入到：

```text
/etc/xconnect-gateway/tls.crt
/etc/xconnect-gateway/tls.key
```

目录和私钥应由 root 拥有、权限为 `0700/0600`。GitOps 只保存公开的
环境、版本、实例规格和拓扑声明；不要把邀请、设备凭据、签名私钥或 TLS
私钥写入 Git。

## 加入与启动

以下值必须替换为当前用户在 Zero Portal 创建的 Gateway 资源。邀请只在
受保护终端中输入一次，不要写入 GitHub Actions 参数、shell history 或日志。

```sh
sudo /usr/local/bin/xconnect-gateway diagnose
sudo /usr/local/bin/xconnect-gateway init \
  --state-dir /var/lib/xconnect-gateway \
  --controller https://accounts-uat.example \
  --gateway-id gw-uat-1

# 在 Zero 中确认刚才显示的公钥，再创建该 Gateway 的短期邀请。
sudo /usr/local/bin/xconnect-gateway join \
  --state-dir /var/lib/xconnect-gateway \
  --gateway-id gw-uat-1 \
  'xconnect://join/REPLACE_WITH_SHORT_LIVED_INVITE?controller=https%3A%2F%2Faccounts-uat.example'

sudo /usr/local/bin/xconnect-gateway up \
  --state-dir /var/lib/xconnect-gateway \
  --tls-cert /etc/xconnect-gateway/tls.crt \
  --tls-key /etc/xconnect-gateway/tls.key
sudo /usr/local/bin/xconnect-gateway status --state-dir /var/lib/xconnect-gateway
```

`up` 会获取并验证签名 Gateway 配置，生成受保护的 Xray/WireGuard 文件，
启动外部运行时并发送应用 ACK。定时同步可使用仓库提供的 systemd
`xconnect-gateway-sync.service/.timer`；Xray 服务使用
`xconnect-gateway-xray.service`。安装这些 unit 后再执行：

```sh
sudo systemctl enable --now xconnect-gateway-xray.service
sudo systemctl enable --now xconnect-gateway-sync.timer
```

## WireGuard over VLESS 拓扑

Gateway 的公网入口只暴露 VLESS/TLS 端口（通常 TCP 443）：

```text
One WireGuard UDP
  → One 本地 Xray transport adapter
  → VLESS/TLS/XUDP
  → Gateway Xray VLESS inbound
  → Gateway 本地 UDP 127.0.0.1:51820
  → Gateway WireGuard
  → 授权私网资源
```

Gateway Xray 必须把专用 VLESS 入站路由到同机
`127.0.0.1:51820`，而不是开放公网 WireGuard UDP。One 的 peer
Endpoint 也必须是本机 transport adapter 的 loopback 地址。这样 NAT 后的
One 不需要入站端口，且 WireGuard 身份仍由双方独立密钥对提供。

## 精确验证

One 和 Gateway 都需要验证本次网络、本次设备和精确对端公钥；只看到 Zero
ACK 或 Portal 的“最近配置已确认”不等于数据面已连通。

```sh
# Gateway
sudo systemctl is-active xconnect-gateway-xray.service
sudo wg show xconnect0 latest-handshakes
sudo ss -lntp | grep ':443'

# One（在 One 节点）
sudo /usr/local/bin/xconnect status --state-dir /var/lib/xconnect-one
sudo wg show xconone0 latest-handshakes
ping -c 3 10.77.0.1
curl --fail --max-time 10 http://10.77.0.1:8080/uat/run
```

通过条件必须全部满足：Gateway/One 运行时为 active、handshake 命中精确
对端公钥且时间足够新、私网 ping 成功、私网 HTTP 返回本次验证标记。任何
一项失败都应先检查本机 Xray 配置测试、VLESS TLS/SNI、WireGuard peer、
AllowedIPs、转发和返回路由，再重试同步。

## 撤销

在 Zero Portal 撤销 Gateway 或 One 设备后，运行时应重新同步并删除已撤销
peer。Gateway 不应手工删除其他设备的 peer；本地停止操作为：

```sh
sudo /usr/local/bin/xconnect-gateway down --state-dir /var/lib/xconnect-gateway
```

正式 UAT 的资源生命周期、邀请和签名配置由 Zero/Accounts 管理。临时云端
验证资源按流水线租约自然到期；自建节点由管理员按同样的撤销和清理流程处理。
