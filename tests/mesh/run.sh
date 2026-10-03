#!/usr/bin/env bash
set -euo pipefail
umask 077
# Run independent repositories without permanent local replaces or dependencies.
gateway_root="$(cd "$(dirname "$0")/../.." && pwd)"
one_root="${1:?usage: run.sh ONE_CHECKOUT ACCOUNTS_CHECKOUT}"
accounts_root="${2:?usage: run.sh ONE_CHECKOUT ACCOUNTS_CHECKOUT}"
one_root="$(cd "$one_root" && pwd)"
accounts_root="$(cd "$accounts_root" && pwd)"
mesh_tmp="$(mktemp -d "${TMPDIR:-/tmp}/xconnect-mesh.XXXXXX")"
trap 'rm -rf "$mesh_tmp"' EXIT
cmp "$one_root/overlay/pathwire/wire.go" "$gateway_root/internal/pathwire/wire.go"
(cd "$accounts_root" && XCONNECT_MESH_FIXTURE_DIR="$mesh_tmp" go test -count=1 ./internal/overlay -run TestMeshMultiDeviceSignedFixtures)
(cd "$one_root" && XCONNECT_MESH_FIXTURE_DIR="$mesh_tmp" go test -count=1 ./overlay/runtime -run TestExportMeshXrayProfiles)
cp "$gateway_root/tests/mesh/mesh_test.go.txt" "$mesh_tmp/mesh_test.go"
cat > "$mesh_tmp/go.mod" <<MOD
module github.com/ai-workspace-xstream/XConnect-Gateway/mesh-integration

go 1.26.4

require (
 github.com/ai-workspace-xstream/XConnect-One v0.0.0
 github.com/ai-workspace-xstream/XConnect-Gateway v0.0.0
)
replace github.com/ai-workspace-xstream/XConnect-One => "$one_root"
replace github.com/ai-workspace-xstream/XConnect-Gateway => "$gateway_root"
MOD
(cd "$mesh_tmp" && go get golang.zx2c4.com/wireguard@v0.0.0-20250521234502-f333402bd9cb && go mod tidy && go test -race -count="${XCONNECT_MESH_TEST_COUNT:-1}" -timeout=180s -run "${XCONNECT_MESH_TEST_PATTERN:-Test}" -v ./...)
