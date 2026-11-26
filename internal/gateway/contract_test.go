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
				Redirect   string `json:"redirect"`
				FinalRules []struct {
					Action  string   `json:"action"`
					IP      []string `json:"ip"`
					Port    string   `json:"port"`
					Network string   `json:"network"`
				} `json:"finalRules"`
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
			if len(outbound.Settings.FinalRules) != 1 || outbound.Settings.FinalRules[0].Action != "allow" || outbound.Settings.FinalRules[0].Port != "51820" || len(outbound.Settings.FinalRules[0].IP) != 1 || outbound.Settings.FinalRules[0].IP[0] != "127.0.0.1/32" {
				t.Fatalf("Xray gateway outbound missing loopback WireGuard finalRules: %s", xray)
			}
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

func TestCaddyUnixFrontendDoesNotRequireTLSOrPublicListener(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	cfg := Config{
		SchemaVersion: 1, Role: Role, ConfigID: "cfg-caddy", NetworkID: "net-1", GatewayID: "gw-1",
		Generation: 1, IssuedAt: now, ExpiresAt: now.Add(time.Minute), InterfaceName: "xconzero0",
		Address: "10.77.0.1/32", ListenPort: 51820, MTU: 1420,
		Transport: Transport{Kind: "vless-xhttp", ServerName: "ph-xconnect.svc.plus", Port: 443,
			AuthID: "runtime-auth-id", Path: "/xconnect", Mode: "auto", Host: "ph-xconnect.svc.plus",
			Frontend: FrontendCaddyUnixH2C, ListenSocket: DefaultGatewaySocket},
	}
	raw, err := cfg.Xray("", "")
	if err != nil {
		t.Fatal(err)
	}
	var profile struct {
		Inbounds []struct {
			Listen any `json:"listen"`
			Port   int `json:"port"`
			Stream struct {
				Security string `json:"security"`
				Network  string `json:"network"`
				XHTTP    struct {
					Path string `json:"path"`
				} `json:"xhttpSettings"`
			} `json:"streamSettings"`
		} `json:"inbounds"`
	}
	if err := json.Unmarshal(raw, &profile); err != nil {
		t.Fatal(err)
	}
	if len(profile.Inbounds) != 1 || profile.Inbounds[0].Listen != DefaultGatewaySocket+",0660" || profile.Inbounds[0].Port != 0 || profile.Inbounds[0].Stream.Security != "" || profile.Inbounds[0].Stream.Network != "xhttp" || profile.Inbounds[0].Stream.XHTTP.Path != "/xconnect" {
		t.Fatalf("unexpected Caddy frontend Xray profile: %s", raw)
	}
}

func TestLegacyAccountsSignedConfigWithoutKindAndFrontend(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	// Transport from older Accounts has no Kind, no Frontend, no ListenSocket
	cfg := Config{
		SchemaVersion: 1, Role: Role, ConfigID: "cfg-legacy", NetworkID: "net_shared_vault", GatewayID: "vault-prod-0",
		Generation: 2, IssuedAt: now, ExpiresAt: now.Add(10 * time.Minute), InterfaceName: "xconzero0",
		Address: "10.79.0.1/32", ListenPort: 51820, MTU: 1420, Peers: []Peer{},
		Transport: Transport{ServerName: "vault-xconnect.svc.plus", Port: 443, AuthID: "fb830a6d-04b9-4ce4-a552-97464c99c2e8"},
		Signature: Signature{Algorithm: "Ed25519", KeyID: "key-1"},
	}
	payload, err := cfg.signingBytes()
	if err != nil {
		t.Fatal(err)
	}
	// Verify that payload JSON does NOT contain "kind":"" or "frontend":""
	if strings.Contains(string(payload), `"kind"`) || strings.Contains(string(payload), `"frontend"`) {
		t.Fatalf("payload should omit empty kind and frontend: %s", payload)
	}
	cfg.Signature.Value = base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, payload))
	keys := []SigningKey{{KeyID: "key-1", Algorithm: "Ed25519", PublicKey: base64.StdEncoding.EncodeToString(publicKey), Status: "current", NotBefore: now.Add(-time.Minute)}}
	if err := cfg.Verify(keys, now); err != nil {
		t.Fatalf("legacy signed config verification failed: %v", err)
	}

	// Environment variable fallback for frontend
	t.Setenv("XCONNECT_GATEWAY_FRONTEND", FrontendCaddyUnixH2C)
	t.Setenv("XCONNECT_GATEWAY_LISTEN_SOCKET", "/run/xconnect-gateway/xray.sock")
	raw, err := cfg.Xray("", "")
	if err != nil {
		t.Fatalf("Xray render failed: %v", err)
	}
	if !strings.Contains(string(raw), "/run/xconnect-gateway/xray.sock,0660") {
		t.Fatalf("expected Caddy unix socket in xray config: %s", raw)
	}
}

func TestSignedGatewayConfigV2WithPolicyAndValidation(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	keys := []SigningKey{{KeyID: "key-1", Algorithm: "Ed25519", PublicKey: base64.StdEncoding.EncodeToString(publicKey), Status: "current", NotBefore: now.Add(-time.Minute)}}

	base := Config{
		SchemaVersion:  2,
		Role:           Role,
		ConfigID:       "cfg-v2",
		NetworkID:      "net-1",
		GatewayID:      "gw-1",
		Generation:     42,
		IssuedAt:       now,
		ExpiresAt:      now.Add(10 * time.Minute),
		ConnectionMode: ConnectionModeWGVLESSL3,
		InterfaceName:  "xconzero0",
		Address:        "10.66.0.1/32",
		ListenPort:     51820,
		MTU:            1420,
		Peers: []Peer{
			{DeviceID: "mac", WireGuardPublicKey: base64.StdEncoding.EncodeToString(make([]byte, 32)), WireGuardAddress: "10.66.0.2/32", AllowedIPs: "10.66.0.2/32"},
			{DeviceID: "bot", WireGuardPublicKey: base64.StdEncoding.EncodeToString(make([]byte, 32)), WireGuardAddress: "10.66.0.4/32", AllowedIPs: "10.66.0.4/32"},
		},
		Transport: Transport{Kind: "vless-xhttp", ServerName: "gw.example.test", Port: 443, AuthID: "11111111-1111-1111-1111-111111111111", Path: "/xconnect", Mode: "auto", Host: "gw.example.test"},
		Policy: &PolicyArtifact{
			SchemaVersion:   1,
			CompilerVersion: "xconnect-policy-v1",
			NetworkID:       "net-1",
			Revision:        42,
			DefaultAction:   "deny",
			ProtectedFlows:  []string{"control:controller-session"},
			Rules: []PolicyRule{{
				ID:                 "allow-mac-bot",
				Action:             "allow",
				SourceDevices:      []string{"mac"},
				DestinationDevices: []string{"bot"},
				Protocols:          []string{"icmp", "tcp"},
				Ports:              []int{22, 8080},
			}},
		},
		Signature: Signature{Algorithm: "Ed25519", KeyID: "key-1"},
	}

	payload, err := base.SigningBytes()
	if err != nil {
		t.Fatal(err)
	}
	base.Signature.Value = base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, payload))
	if err := base.Verify(keys, now); err != nil {
		t.Fatalf("expected valid v2 policy config to verify: %v", err)
	}

	// Tampering with policy must invalidate Ed25519 signature.
	tampered := base
	tamperedPolicy := *base.Policy
	tamperedPolicy.DefaultAction = "allow"
	tampered.Policy = &tamperedPolicy
	if err := tampered.Verify(keys, now); err == nil {
		t.Fatal("expected tampered policy default_action to fail signature verification")
	}

	// SchemaVersion 1 with attached policy must fail structural validation.
	v1WithPolicy := base
	v1WithPolicy.SchemaVersion = 1
	if err := v1WithPolicy.ValidateStructure(now); err == nil {
		t.Fatal("expected v1 config with attached policy to fail validation")
	}

	// Invalid policy variants must be rejected.
	invalidCases := []struct {
		name   string
		mutate func(*PolicyArtifact)
	}{
		{name: "network mismatch", mutate: func(p *PolicyArtifact) { p.NetworkID = "other-net" }},
		{name: "bad default action", mutate: func(p *PolicyArtifact) { p.DefaultAction = "reject" }},
		{name: "bad rule action", mutate: func(p *PolicyArtifact) { p.Rules[0].Action = "drop" }},
		{name: "duplicate rule id", mutate: func(p *PolicyArtifact) { p.Rules = append(p.Rules, p.Rules[0]) }},
		{name: "icmp with ports", mutate: func(p *PolicyArtifact) { p.Rules[0].Protocols = []string{"icmp"}; p.Rules[0].Ports = []int{80} }},
		{name: "port out of range", mutate: func(p *PolicyArtifact) { p.Rules[0].Ports = []int{70000} }},
		{name: "bad protocol", mutate: func(p *PolicyArtifact) { p.Rules[0].Protocols = []string{"gre"} }},
		{name: "empty source", mutate: func(p *PolicyArtifact) { p.Rules[0].SourceDevices = nil }},
		{name: "too many rules", mutate: func(p *PolicyArtifact) {
			p.Rules = make([]PolicyRule, 201)
			for i := range p.Rules {
				p.Rules[i] = PolicyRule{ID: "r-" + strings.Repeat("x", 1) + string(rune('a'+i%26)) + string(rune('0'+i/26)), Action: "allow", SourceDevices: []string{"*"}, DestinationDevices: []string{"*"}}
			}
		}},
	}
	for _, tc := range invalidCases {
		cfg := base
		pCopy := *base.Policy
		pCopy.Rules = append([]PolicyRule(nil), base.Policy.Rules...)
		tc.mutate(&pCopy)
		cfg.Policy = &pCopy
		if err := cfg.ValidateStructure(now); err == nil {
			t.Fatalf("expected invalid policy case %q to fail ValidateStructure", tc.name)
		}
	}
}
