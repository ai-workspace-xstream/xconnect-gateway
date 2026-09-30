#!/usr/bin/env bash
set -euo pipefail
umask 077
# Enable an already enrolled Linux Gateway. No enrollment or service secrets.
[[ $(uname -s) == Linux && $(id -u) == 0 ]] || { echo 'Run as root on Linux.' >&2; exit 1; }
repo_dir=$(cd "$(dirname "$0")/.." && pwd)
state_dir=${XCONNECT_GATEWAY_STATE_DIR:-/var/lib/xconnect-gateway}
frontend=${XCONNECT_GATEWAY_FRONTEND:-direct-tls}
socket=${XCONNECT_GATEWAY_LISTEN_SOCKET:-/run/xconnect-gateway/xray.sock}
cert=${XCONNECT_GATEWAY_TLS_CERT:-/etc/xconnect-gateway/tls.crt}
key=${XCONNECT_GATEWAY_TLS_KEY:-/etc/xconnect-gateway/tls.key}
# Restrict systemd substitutions to safe absolute paths (no expansion/specifiers).
for path in "$state_dir" "$socket" "$cert" "$key"; do
  [[ $path =~ ^/[a-zA-Z0-9_./-]+$ ]] || { echo 'Paths must be absolute without whitespace or systemd specifiers.' >&2; exit 1; }
done
[[ $frontend == direct-tls || $frontend == caddy-unix-h2c ]] || exit 1
[[ -f $state_dir/state.json ]] || { echo 'Enroll the Gateway before setup.' >&2; exit 1; }
for tool in /usr/local/bin/xconnect-gateway /usr/local/bin/xray; do
  [[ -x $tool ]] || { echo "Missing executable: $tool" >&2; exit 1; }
done
command -v wg >/dev/null
command -v wg-quick >/dev/null
if [[ $frontend == direct-tls ]]; then
  [[ -r $cert && -r $key ]] || { echo 'Configure TLS certificate/key first.' >&2; exit 1; }
else
  [[ $socket == /run/xconnect-gateway/* ]] || { echo 'Caddy socket must be in /run/xconnect-gateway.' >&2; exit 1; }
  getent group caddy >/dev/null
fi
backup=$(mktemp -d /var/tmp/xconnect-gateway-setup.XXXXXX)
for name in xconnect-gateway-sync.service xconnect-gateway-sync.timer xconnect-gateway-xray.service; do
  [[ ! -f /etc/systemd/system/$name ]] || cp -p "/etc/systemd/system/$name" "$backup/$name"
done
install -d -m 0755 /etc/sysctl.d /etc/systemd/system
[[ ! -f /etc/sysctl.d/90-xconnect-gateway.conf ]] || cp -p /etc/sysctl.d/90-xconnect-gateway.conf "$backup/sysctl.conf"
cat > /etc/sysctl.d/90-xconnect-gateway.conf <<EOF
net.ipv4.ip_forward=1
net.ipv4.conf.all.rp_filter=2
net.ipv4.conf.default.rp_filter=2
EOF
sysctl -p /etc/sysctl.d/90-xconnect-gateway.conf
install -m 0644 "$repo_dir/packaging/systemd/xconnect-gateway-sync.timer" /etc/systemd/system/
cat > /etc/systemd/system/xconnect-gateway-sync.service <<EOF
[Unit]
Description=Synchronize enrolled XConnect Gateway
After=network-online.target
Wants=network-online.target
[Service]
Type=oneshot
Environment=PATH=/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin
ExecStart=/usr/local/bin/xconnect-gateway up --state-dir $state_dir --frontend $frontend --listen-socket $socket --tls-cert $cert --tls-key $key
EOF
cat > /etc/systemd/system/xconnect-gateway-xray.service <<EOF
[Unit]
Description=XConnect Gateway Xray runtime
After=network-online.target
Wants=network-online.target
[Service]
User=root
RuntimeDirectory=xconnect-gateway
RuntimeDirectoryMode=0750
RuntimeDirectoryPreserve=yes
ExecStart=/usr/local/bin/xray run -config $state_dir/runtime/xray.json
Restart=on-failure
RestartSec=3
NoNewPrivileges=true
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
[Install]
WantedBy=multi-user.target
EOF
if [[ $frontend == caddy-unix-h2c ]]; then
  printf '\n[Service]\nGroup=caddy\nUMask=0007\n' >> /etc/systemd/system/xconnect-gateway-xray.service
fi
systemctl daemon-reload
# Sync creates the config and starts Xray only when changed or not active.
systemctl start xconnect-gateway-sync.service
systemctl enable xconnect-gateway-xray.service
systemctl enable --now xconnect-gateway-sync.timer
printf 'Gateway forwarding/autostart configured; backups: %s\n' "$backup"
