# Changelog

All notable changes to `XConnect-Gateway` are documented in this file.

## [v0.1.14] - 2026-11-22

### Added
- **Signed Policy Contract v2 (`internal/gateway`)**:
  - Added `PolicyArtifact` / `PolicyRule` to `gateway.Config` (`SchemaVersion: 2`) with Ed25519 signature verification and strict structural validation.
  - Added `Accept: application/vnd.xconnect.gateway-config.v2+json, application/json` content negotiation in `Client.Config` while preserving `SchemaVersion: 1` compatibility for older controllers/gateways.
- **Atomic Forwarding Policy Compiler & Enforcer (`internal/policy`)**:
  - Dynamically resolves `device_id` selectors from signed `Peers` (`WireGuardAddress`) with zero hardcoded overlay IPs.
  - Compiles deterministic `iptables-restore --noflush` / `ip6tables-restore --noflush` rulesets into an isolated `XCONNECT_ZERO_FWD` chain, mounted at `FORWARD` position 1 (`-i <iface> -o <iface> -j XCONNECT_ZERO_FWD`) without disturbing unrelated host chains.
  - Integrated policy compilation (`runtime/policy-compiled.rules`), live enforcement (`apply`/`sync`), clean teardown (`down`), state tracking (`AppliedPolicyRevision`, `AppliedPolicyDigest`), and telemetry fields (`GatewayTelemetry`).

## [v0.1.13] - 2026-11-18

### Changed
- Decoupled `XConnect-Gateway` into a pure data-plane runner (`apply`), added `connection_mode` support, and added local non-secret telemetry output (`gateway-telemetry.json`, `overlay-status.json`).
