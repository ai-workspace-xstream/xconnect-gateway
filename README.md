# XConnect Gateway

Independent Linux Server relay/service for XConnect Zero. Linux Server is the
only supported Gateway platform in the current release. It is deliberately
separate from the XConnect One controlled-client product and from XConnect App.

The runtime performs `join → session renewal → signed gateway config sync → WireGuard/Xray apply → ACK`. XConnect Zero `accounts` is the only configuration authority. The binary rejects unsigned, expired, cross-network, or cross-gateway configuration.

## Quick start: Linux Gateway

Gateway is a Linux Server role. The public entry point is a DNS-only hostname
with TCP `443`; WireGuard `51820/UDP` is not a public security-group rule.

### Step 1: prepare DNS

Create an A record for the Gateway public IPv4 address:

```text
tw-xconnect.svc.plus → Gateway public IPv4
```

Verify it before enrollment:

```sh
ping -c 1 tw-xconnect.svc.plus
```

### Step 2: install and initialize

On the Linux Gateway host:

```sh
curl -fsSL https://install.svc.plus/xconnect-gateway | \
  sudo env XCONNECT_GATEWAY_VERSION=v0.1.6 bash

curl -fsSL \
  https://raw.githubusercontent.com/ai-workspace-xstream/XConnect-One/main/scripts/one.sh \
  -o /tmp/xconnect-one.sh
chmod 0755 /tmp/xconnect-one.sh

sudo /tmp/xconnect-one.sh gateway-init \
  --controller https://accounts-uat.onwalk.net \
  --gateway-id gw-uat-tw-xconnect \
  --state-dir /var/lib/xconnect-gateway
```

`gateway-init` only creates the local protected identity and `state.json`. It
does not upload private keys or start the public service.

### Step 3: enroll and start the Gateway

Use Zero Portal to approve the Gateway public key and issue a short-lived
Gateway invitation. Then run the native Gateway lifecycle:

```sh
sudo xconnect-gateway join \
  --state-dir /var/lib/xconnect-gateway \
  --gateway-id gw-uat-tw-xconnect \
  'xconnect://join/SHORT_LIVED_INVITE'

sudo xconnect-gateway up \
  --state-dir /var/lib/xconnect-gateway \
  --tls-cert /etc/xconnect-gateway/tls.crt \
  --tls-key /etc/xconnect-gateway/tls.key
```

`join/up` verifies the signed Gateway configuration, renders external
Xray/WireGuard runtime files, starts the data plane and sends ACK. Never put
the invitation, TLS key, VLESS identity or WireGuard private key in GitHub
Actions inputs, GitOps or logs.

### Step 4: verify the data plane

```sh
sudo xconnect-gateway status --state-dir /var/lib/xconnect-gateway
sudo wg show xconnect0 latest-handshakes
sudo ss -lntp | grep ':443'
```

The expected path is:

```text
One WireGuard
  → One external Xray
  → VLESS/XHTTP TLS TCP 443
  → Gateway external Xray
  → Gateway local WireGuard
  → authorized private network
```

## Runtime boundary

- `xconnect-gateway`: owns enrollment, protected local state, signed configuration verification, generated runtime files, apply and ACK.
- external `WireGuard` and `Xray`: data plane processes. The generated Gateway
  Xray profile routes the dedicated VLESS inbound to `127.0.0.1:51820`; it is
  not a general-purpose internet proxy.
- GitOps: non-sensitive UAT topology and release selection.
- Vault: TLS key material and other environment secrets; expected UAT path is `kv/data/uat/xconnect-one`.
- `accounts`: per-user isolated networks, devices, invites, policy and signed configuration.
- `portal`: user-facing `/panel/xconnect-zero` BFF/UI. It never receives device credentials or private keys.

## Linux host

自建节点的安装脚本、Zero 加入和 WireGuard-over-VLESS 验证见
[docs/self-hosted-install-and-validation.md](docs/self-hosted-install-and-validation.md)。
其中的 `curl https://install.svc.plus/xconnect-gateway | bash` 只安装
Gateway 二进制；外部 Xray/WireGuard、TLS 文件和 Zero 邀请仍由节点管理员
按受保护流程配置。

Install `wireguard-tools`, `xray`, the systemd units under `packaging/systemd`, and the released binary at `/usr/local/bin/xconnect-gateway`. Provision the TLS certificate and key at `/etc/xconnect-gateway/tls.crt` and `/etc/xconnect-gateway/tls.key` from Vault without writing either value to Git.

The reviewed one-line installer only installs the CLI. It does not enroll the node,
consume an invitation, or start a network service:

```sh
curl -fsSL https://install.svc.plus/xconnect-gateway | \
  sudo env XCONNECT_GATEWAY_VERSION=v0.1.6 bash
```

Initialize the protected local identity explicitly, then use a short-lived Zero
invitation to join:

```sh
sudo xconnect-gateway diagnose
sudo xconnect-gateway init --controller https://accounts-uat.onwalk.net --gateway-id gw-uat-1
# Put the displayed public key into the owner-scoped Zero network, then create its one-time Gateway invite.
sudo xconnect-gateway join --gateway-id gw-uat-1 'xconnect://join/REDACTED?controller=https%3A%2F%2Faccounts-uat.onwalk.net'
sudo xconnect-gateway up
sudo systemctl enable --now xconnect-gateway-sync.timer
```

`up` is non-disruptive after the first activation: when `xconzero0` already
exists, peer changes are applied with `wg syncconf` instead of tearing down and
recreating the interface. This preserves live WireGuard sockets and handshake
timestamps during periodic reconciliation.

The invitation is one-time sensitive data. Do not pass it as a GitHub Actions input or print it in logs.
