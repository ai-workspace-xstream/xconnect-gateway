# Linux container deployment

The Compose example runs Gateway in its own network namespace with direct TLS.
It requires Docker Compose and a Linux host with kernel WireGuard support loaded
by the host administrator. The container needs NET_ADMIN for its WireGuard
interface and routes, and NET_BIND_SERVICE for TCP 443. Gateway manages the
interface with UID 0 inside the container. Use the dedicated container identity
and volume. The runtime does not need privileged mode or the Docker socket.

Set `GATEWAY_TLS_DIR` to the absolute path of a directory containing the
provisioned `tls.crt` and `tls.key` for the hostname configured in Zero. The
directory is mounted read-only. Set `GATEWAY_BIND_ADDRESS` to the approved host
address for a public direct-TLS deployment. The default publishes on loopback.
Only TCP 443 is published. The signed Gateway WireGuard listen port must be
51820 for the current Xray loopback handoff.

```sh
docker compose build
docker compose run --rm gateway init --controller https://zero.example.net --gateway-id gw-example
```

Run `init` once on a fresh volume. It prints the WireGuard public key needed by
Zero. Have Zero issue a one-use invitation for this Gateway and save it to a
protected local file through your secret delivery mechanism. Set
`GATEWAY_INVITE_FILE` to its absolute path and join through a one-off container.

```sh
docker compose run --rm \
  --volume "${GATEWAY_INVITE_FILE:?Set the protected invite file}:/run/gateway-invite:ro" \
  gateway join --gateway-id gw-example --invite-file /run/gateway-invite
docker compose up -d
docker compose exec gateway status
docker compose logs --tail 30 gateway
```

The service runs signed configuration reconciliation once a minute and
supervises Xray and the optional relay. Compose restarts the container if
reconciliation fails or either expected process exits. Verify a fresh
WireGuard handshake from an enrolled One and a request over the overlay to
confirm end-to-end connectivity. Keep the state volume across restarts. To
stop, use `docker compose stop`. To roll back, use the previous image with the
existing state volume.

This example is for standalone direct TLS. The SIT Traefik h2c ingress requires
its own deployment wiring, including a backend that shares the Gateway Unix
socket and forwards h2c.
