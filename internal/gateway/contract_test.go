package gateway

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestSignedGatewayConfigAndRendering(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	cfg := Config{SchemaVersion: 1, Role: Role, ConfigID: "cfg-1", NetworkID: "net-1", GatewayID: "gw-1", Generation: 2, IssuedAt: now, ExpiresAt: now.Add(10 * time.Minute), InterfaceName: "xconzero0", Address: "10.77.0.1/32", ListenPort: 51820, MTU: 1280, Peers: []Peer{{DeviceID: "one-1", WireGuardPublicKey: base64.StdEncoding.EncodeToString(make([]byte, 32)), WireGuardAddress: "10.77.0.2/32", AllowedIPs: "10.77.0.2/32"}}, Transport: Transport{Kind: "vless-xhttp", ServerName: "gw.example.test", Port: 443, AuthID: "11111111-1111-1111-1111-111111111111", Path: "/xconnect", Mode: "auto", Host: "gw.example.test"}, Signature: Signature{Algorithm: "Ed25519", KeyID: "key-1"}}
	payload, err := cfg.signingBytes()
	if err != nil {
		t.Fatal(err)
	}
	cfg.Signature.Value = base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, payload))
	keys := []SigningKey{{KeyID: "key-1", Algorithm: "Ed25519", PublicKey: base64.StdEncoding.EncodeToString(publicKey), Status: "current", NotBefore: now.Add(-time.Minute)}}
	if err := cfg.Verify(keys, now); err != nil {
		t.Fatal(err)
	}
	wg := cfg.WireGuard("private")
	if !strings.Contains(wg, "ListenPort = 51820") || !strings.Contains(wg, "AllowedIPs = 10.77.0.2/32") {
		t.Fatalf("bad WireGuard config: %s", wg)
	}
	xray, err := cfg.Xray("/tls.crt", "/tls.key")
	if err != nil || strings.Contains(string(xray), "xtls-rprx-vision") || !strings.Contains(string(xray), `"id": "11111111-1111-1111-1111-111111111111"`) || !strings.Contains(string(xray), `"network": "xhttp"`) || !strings.Contains(string(xray), `"path": "/xconnect"`) {
		t.Fatalf("bad Xray config: %s err=%v", xray, err)
	}
	var profile struct {
		Routing struct {
			Rules []struct {
				InboundTag  []string `json:"inboundTag"`
				OutboundTag string   `json:"outboundTag"`
			} `json:"rules"`
		} `json:"routing"`
		Outbounds []struct {
			Tag      string `json:"tag"`
			Settings struct {
				Redirect string `json:"redirect"`
			} `json:"settings"`
		} `json:"outbounds"`
	}
	if err := json.Unmarshal(xray, &profile); err != nil {
		t.Fatalf("invalid Xray JSON: %v", err)
	}
	if len(profile.Routing.Rules) != 1 || profile.Routing.Rules[0].OutboundTag != "xconnect-wireguard" || len(profile.Routing.Rules[0].InboundTag) != 1 || profile.Routing.Rules[0].InboundTag[0] != "xconnect-vless-in" {
		t.Fatalf("Xray VLESS inbound is not routed to WireGuard: %s", xray)
	}
	foundRedirect := false
	for _, outbound := range profile.Outbounds {
		if outbound.Tag == "xconnect-wireguard" && outbound.Settings.Redirect == "127.0.0.1:51820" {
			foundRedirect = true
		}
	}
	if !foundRedirect {
		t.Fatalf("Xray gateway outbound does not redirect to local WireGuard: %s", xray)
	}
	cfg.Generation++
	if err := cfg.Verify(keys, now); err == nil {
		t.Fatal("tampered config verified")
	}
}
