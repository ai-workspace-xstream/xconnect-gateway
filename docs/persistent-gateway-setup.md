# Persistent Linux Gateway setup

Install a Gateway binary built from this revision, Xray, WireGuard tools and systemd. Enroll with Zero first; setup does not create or replace enrollment, invitations, private keys, or Vault data.

Run `sudo bash scripts/setup-xconnect-gateway.sh` from this checkout. Default state is `/var/lib/xconnect-gateway`; direct TLS requires readable `/etc/xconnect-gateway/tls.crt` and `tls.key`. Override paths through `XCONNECT_GATEWAY_STATE_DIR`, `XCONNECT_GATEWAY_TLS_CERT`, and `XCONNECT_GATEWAY_TLS_KEY` passed explicitly to sudo.

For an existing Caddy frontend:

```sh
sudo env XCONNECT_GATEWAY_FRONTEND=caddy-unix-h2c \
  XCONNECT_GATEWAY_LISTEN_SOCKET=/run/xconnect-gateway/xray.sock \
  bash scripts/setup-xconnect-gateway.sh
```

Caddy and its frontend configuration/certificates must already exist. Setup enables persistent IPv4 forwarding and loose reverse-path filtering, a 60-second sync timer, and Xray recovery. Peer-only updates do not restart Xray; missing WireGuard interfaces are recreated even if the signed revision is unchanged. Existing custom systemd drop-ins remain in place: review them beforehand and remove obsolete unconditional restart hooks using your deployment tool. Setup never opens public SSH/firewall rules or installs application-specific Raft aliases.

Verify `sysctl net.ipv4.ip_forward`, `systemctl status xconnect-gateway-sync.timer xconnect-gateway-xray.service`, `wg show`, and actual remote TCP/SSH reachability. Repeat after a maintenance reboot. Unit/sysctl backups are reported under `/var/tmp/xconnect-gateway-setup.*`; restore those deliberately if needed. Installing a script does not update an older binary.
