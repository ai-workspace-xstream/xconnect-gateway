#!/usr/bin/env bash
set -euo pipefail
umask 022

# Release installer for the standalone XConnect Gateway Linux relay.
# The install.svc.plus endpoint may serve this file. It never receives or
# creates Zero invitations, Vault values, TLS keys, or WireGuard private keys.

readonly RELEASE_REPOSITORY="ai-workspace-xstream/XConnect-Gateway"
readonly DEFAULT_VERSION="v0.1.5"
version="${XCONNECT_GATEWAY_VERSION:-$DEFAULT_VERSION}"
install_dir="${XCONNECT_GATEWAY_INSTALL_DIR:-/usr/local/bin}"
release_base="${XCONNECT_GATEWAY_RELEASE_BASE_URL:-https://github.com/${RELEASE_REPOSITORY}/releases/download}"

die() {
  echo "xconnect-gateway-install: $*" >&2
  exit 1
}

[[ "$version" =~ ^v[0-9A-Za-z._-]+$ ]] || die "invalid release tag: $version"
[[ "$install_dir" = /* ]] || die 'XCONNECT_GATEWAY_INSTALL_DIR must be absolute'
command -v curl >/dev/null || die 'curl is required'

os="$(uname -s)"
arch="$(uname -m)"
[[ "$os" = Linux ]] || die "Linux is required (detected $os)"
case "$arch" in
  x86_64|amd64) asset='xconnect-gateway-linux-amd64' ;;
  aarch64|arm64) asset='xconnect-gateway-linux-arm64' ;;
  *) die "unsupported Linux architecture: $arch" ;;
esac

tmp_dir="$(mktemp -d "${TMPDIR:-/tmp}/xconnect-gateway-install.XXXXXX")"
trap 'rm -rf "$tmp_dir"' EXIT
archive_url="${release_base%/}/${version}/${asset}"
sums_url="${release_base%/}/${version}/SHA256SUMS"

curl --fail --silent --show-error --location --proto '=https' --tlsv1.2 \
  "$archive_url" -o "$tmp_dir/$asset"
curl --fail --silent --show-error --location --proto '=https' --tlsv1.2 \
  "$sums_url" -o "$tmp_dir/SHA256SUMS"

expected="$(awk -v asset="$asset" '$2 == asset || $2 == "dist/" asset { print $1; exit }' "$tmp_dir/SHA256SUMS")"
[[ "$expected" =~ ^[[:xdigit:]]{64}$ ]] || die "SHA256SUMS has no entry for $asset"
if command -v sha256sum >/dev/null; then
  printf '%s  %s\n' "$expected" "$tmp_dir/$asset" | sha256sum -c - >/dev/null
elif command -v shasum >/dev/null; then
  actual="$(shasum -a 256 "$tmp_dir/$asset" | awk '{print $1}')"
  [[ "$actual" = "$expected" ]] || die 'release checksum mismatch'
else
  die 'sha256sum or shasum is required'
fi

if [[ -w "$install_dir" || -e "$install_dir" && -w "$install_dir" ]]; then
  install -d -m 0755 "$install_dir"
  install -m 0755 "$tmp_dir/$asset" "$install_dir/xconnect-gateway"
else
  command -v sudo >/dev/null || die "write access to $install_dir or sudo is required"
  sudo install -d -m 0755 "$install_dir"
  sudo install -m 0755 "$tmp_dir/$asset" "$install_dir/xconnect-gateway"
fi

echo "installed XConnect Gateway $version ($asset) at $install_dir/xconnect-gateway"
