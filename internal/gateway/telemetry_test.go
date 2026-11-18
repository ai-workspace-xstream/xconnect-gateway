package gateway

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestParseWgDumpAndBuildTelemetry(t *testing.T) {
	dump := fmt.Sprintf(`privateKeyVal\tpublicInterfaceKey\t51820\toff
peerPub1\t(none)\t192.168.1.50:51820\t10.77.0.2/32\t%d\t102400\t204800\t25
peerPub2\t(none)\t(none)\t10.77.0.3/32\t0\t0\t0\toff`, time.Now().Unix()-10)

	// Replace literal \t with real tabs
	dump = stringsReplaceTabs(dump)

	peers := ParseWgDump(dump)
	if len(peers) != 2 {
		t.Fatalf("expected 2 peers, got %d", len(peers))
	}
	if peers[0].PublicKey != "peerPub1" || peers[0].RxBytes != 102400 || peers[0].TxBytes != 204800 {
		t.Fatalf("unexpected peer 0: %+v", peers[0])
	}
	if peers[1].PublicKey != "peerPub2" || peers[1].LatestHandshake != 0 {
		t.Fatalf("unexpected peer 1: %+v", peers[1])
	}

	cfg := Config{
		SchemaVersion:  1,
		Role:           Role,
		ConfigID:       "cfg-telemetry-1",
		NetworkID:      "net_uat",
		GatewayID:      "gw-uat-tw-xconnect",
		Generation:     5,
		ConnectionMode: ConnectionModeWGVLESSL3,
		Peers: []Peer{
			{DeviceID: "one-user1", WireGuardPublicKey: "peerPub1", WireGuardAddress: "10.77.0.2/32"},
			{DeviceID: "one-user2", WireGuardPublicKey: "peerPub2", WireGuardAddress: "10.77.0.3/32"},
		},
		Transport: Transport{ServerName: "tw-xconnect.svc.plus"},
	}

	now := time.Now().UTC()
	gt, osStatus := BuildTelemetry(cfg, peers, true, true, false, now)

	if gt.GatewayID != "gw-uat-tw-xconnect" || gt.NetworkID != "net_uat" {
		t.Fatalf("unexpected gateway id or net: %+v", gt)
	}
	if gt.Traffic.RxBytesTotal != 102400 || gt.Traffic.TxBytesTotal != 204800 {
		t.Fatalf("unexpected traffic total: %+v", gt.Traffic)
	}
	if len(gt.Peers) != 2 {
		t.Fatalf("expected 2 peers, got %d", len(gt.Peers))
	}
	if !gt.Peers[0].Connected || gt.Peers[1].Connected {
		t.Fatalf("peer 0 should be connected, peer 1 should be disconnected: %+v", gt.Peers)
	}
	if osStatus.Role != "gateway" || !osStatus.Healthy {
		t.Fatalf("expected healthy gateway overlay status, got %+v", osStatus)
	}

	tmpDir := t.TempDir()
	if err := WriteGatewayTelemetry(tmpDir, gt, osStatus); err != nil {
		t.Fatalf("failed to write telemetry: %v", err)
	}

	gtRaw, err := os.ReadFile(filepath.Join(tmpDir, "runtime", "gateway-telemetry.json"))
	if err != nil {
		t.Fatal(err)
	}
	var readGT GatewayTelemetry
	if err := json.Unmarshal(gtRaw, &readGT); err != nil || readGT.GatewayID != "gw-uat-tw-xconnect" {
		t.Fatalf("corrupt gateway telemetry: %s", gtRaw)
	}

	osRaw, err := os.ReadFile(filepath.Join(tmpDir, "runtime", "overlay-status.json"))
	if err != nil {
		t.Fatal(err)
	}
	var readOS OverlayStatus
	if err := json.Unmarshal(osRaw, &readOS); err != nil || readOS.DeviceID != "gw-uat-tw-xconnect" {
		t.Fatalf("corrupt overlay status: %s", osRaw)
	}
}

func stringsReplaceTabs(s string) string {
	res := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		if i+1 < len(s) && s[i] == '\\' && s[i+1] == 't' {
			res = append(res, '\t')
			i++
		} else {
			res = append(res, s[i])
		}
	}
	return string(res)
}
