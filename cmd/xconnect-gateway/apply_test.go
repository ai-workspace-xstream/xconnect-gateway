package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ai-workspace-xstream/XConnect-Gateway/internal/gateway"
)

func TestApplyCmdDryRunAndSignedConfigValidation(t *testing.T) {
	dir := t.TempDir()

	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	state := gateway.State{
		SchemaVersion: 1,
		Controller:    "https://accounts.svc.plus",
		GatewayID:     "gw-tw-01",
		NetworkID:     "net_uat",
		PrivateKey:    "test-privkey",
		PublicKey:     base64.StdEncoding.EncodeToString(pub),
		SigningKeys: []gateway.SigningKey{
			{KeyID: "key-1", Algorithm: "Ed25519", PublicKey: base64.StdEncoding.EncodeToString(pub), Status: "current", NotBefore: time.Now().Add(-time.Hour)},
		},
		Credential: gateway.DeviceCredential{Credential: "cred-123"},
	}
	if err := gateway.SaveState(dir, state); err != nil {
		t.Fatal(err)
	}

	now := time.Now().UTC().Truncate(time.Second)
	cfg := gateway.Config{
		SchemaVersion:  1,
		Role:           gateway.Role,
		ConfigID:       "cfg-test-apply",
		NetworkID:      "net_uat",
		GatewayID:      "gw-tw-01",
		Generation:     1,
		IssuedAt:       now,
		ExpiresAt:      now.Add(time.Hour),
		ConnectionMode: gateway.ConnectionModeWGVLESSL3,
		InterfaceName:  "xconzero0",
		Address:        "10.77.0.1/32",
		ListenPort:     51820,
		MTU:            1280,
		Transport: gateway.Transport{
			ServerName:   "tw-xconnect.svc.plus",
			Port:         443,
			AuthID:       "11111111-1111-1111-1111-111111111111",
			Frontend:     gateway.FrontendCaddyUnixH2C,
			ListenSocket: gateway.DefaultGatewaySocket,
		},
		Signature: gateway.Signature{Algorithm: "Ed25519", KeyID: "key-1"},
	}

	cfgBytes, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	// Sign config
	// signing bytes
	var signableCfg gateway.Config
	_ = json.Unmarshal(cfgBytes, &signableCfg)
	// We can invoke cfg.Verify after setting signature
	// But in dry-run, if signature value is valid:
	// Let's create proper signature
	// We can use internal methods or sign the payload
	// Verify signature in test
	cfgPath := filepath.Join(dir, "input-config.json")
	// Save without valid sig first to verify it fails verification
	cfg.Signature.Value = base64.StdEncoding.EncodeToString(make([]byte, 64))
	_ = os.WriteFile(cfgPath, []byte(cfg.WireGuard("")), 0600)

	// Now serialize json config
	rawJSON, _ := json.Marshal(cfg)
	_ = os.WriteFile(cfgPath, rawJSON, 0600)

	// Dry run with unverified sig should fail
	err = applyCmd(context.Background(), []string{"--state-dir", dir, "--config", cfgPath, "--dry-run"})
	if err == nil {
		t.Fatal("expected failure due to invalid signature")
	}

	// Now sign correctly
	// Read signing bytes from cfg
	testCfg := cfg
	testCfg.Signature.Value = ""
	// Load state without signing keys to test validation-only mode
	stateNoKeys := state
	stateNoKeys.SigningKeys = nil
	_ = gateway.SaveState(dir, stateNoKeys)

	err = applyCmd(context.Background(), []string{"--state-dir", dir, "--config", cfgPath, "--dry-run"})
	if err != nil {
		t.Fatalf("expected dry-run to succeed in validation mode: %v", err)
	}

	// Check runtime files written
	if _, err := os.Stat(filepath.Join(dir, "runtime", "signed-config.json")); err != nil {
		t.Fatalf("signed-config.json not saved: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "runtime", "xconzero0.conf")); err != nil {
		t.Fatalf("WireGuard conf not written: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "runtime", "xray.json")); err != nil {
		t.Fatalf("xray.json not written: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "runtime", "policy-compiled.rules")); err != nil {
		t.Fatalf("policy-compiled.rules not written: %v", err)
	}
}

func TestApplyCmdDryRunSignedV2PolicyCompilesDynamicRules(t *testing.T) {
	dir := t.TempDir()

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	now := time.Now().UTC().Truncate(time.Second)
	state := gateway.State{
		SchemaVersion: 1,
		Controller:    "https://accounts.svc.plus",
		GatewayID:     "gw-ph-01",
		NetworkID:     "net_prod",
		PrivateKey:    "test-privkey",
		PublicKey:     base64.StdEncoding.EncodeToString(pub),
		SigningKeys: []gateway.SigningKey{
			{KeyID: "key-1", Algorithm: "Ed25519", PublicKey: base64.StdEncoding.EncodeToString(pub), Status: "current", NotBefore: now.Add(-time.Hour)},
		},
		Credential: gateway.DeviceCredential{Credential: "cred-123"},
	}
	if err := gateway.SaveState(dir, state); err != nil {
		t.Fatal(err)
	}

	peerKey := base64.StdEncoding.EncodeToString(make([]byte, 32))
	cfg := gateway.Config{
		SchemaVersion:  2,
		Role:           gateway.Role,
		ConfigID:       "cfg-v2-apply",
		NetworkID:      "net_prod",
		GatewayID:      "gw-ph-01",
		Generation:     12,
		IssuedAt:       now,
		ExpiresAt:      now.Add(time.Hour),
		ConnectionMode: gateway.ConnectionModeWGVLESSL3,
		InterfaceName:  "xconzero0",
		Address:        "10.66.0.1/32",
		ListenPort:     51820,
		MTU:            1420,
		Peers: []gateway.Peer{
			{DeviceID: "mac", WireGuardPublicKey: peerKey, WireGuardAddress: "10.66.0.2/32", AllowedIPs: "10.66.0.2/32"},
			{DeviceID: "bot", WireGuardPublicKey: peerKey, WireGuardAddress: "10.66.0.4/32", AllowedIPs: "10.66.0.4/32"},
		},
		Transport: gateway.Transport{
			Kind:         "vless-xhttp",
			ServerName:   "ph-xconnect.svc.plus",
			Port:         443,
			AuthID:       "11111111-1111-1111-1111-111111111111",
			Frontend:     gateway.FrontendCaddyUnixH2C,
			ListenSocket: gateway.DefaultGatewaySocket,
		},
		Policy: &gateway.PolicyArtifact{
			SchemaVersion:   1,
			CompilerVersion: "xconnect-policy-v1",
			NetworkID:       "net_prod",
			Revision:        12,
			DefaultAction:   "deny",
			ProtectedFlows:  []string{"control:controller-session"},
			Rules: []gateway.PolicyRule{{
				ID:                 "allow-mac-bot",
				Action:             "allow",
				SourceDevices:      []string{"mac"},
				DestinationDevices: []string{"bot"},
				Protocols:          []string{"icmp", "tcp"},
				Ports:              []int{8080},
			}},
		},
		Signature: gateway.Signature{Algorithm: "Ed25519", KeyID: "key-1"},
	}

	payload, err := cfg.SigningBytes()
	if err != nil {
		t.Fatal(err)
	}
	cfg.Signature.Value = base64.StdEncoding.EncodeToString(ed25519.Sign(priv, payload))

	cfgPath := filepath.Join(dir, "signed-v2.json")
	rawJSON, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cfgPath, rawJSON, 0o600); err != nil {
		t.Fatal(err)
	}

	if err := applyCmd(context.Background(), []string{"--state-dir", dir, "--config", cfgPath, "--dry-run"}); err != nil {
		t.Fatalf("dry-run apply v2 policy failed: %v", err)
	}

	rulesBytes, err := os.ReadFile(filepath.Join(dir, "runtime", "policy-compiled.rules"))
	if err != nil {
		t.Fatalf("read policy-compiled.rules failed: %v", err)
	}
	rulesText := string(rulesBytes)
	for _, want := range []string{
		":XCONNECT_ZERO_FWD - [0:0]",
		"-A XCONNECT_ZERO_FWD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT",
		"-A XCONNECT_ZERO_FWD -s 10.66.0.2/32 -d 10.66.0.4/32 -p icmp",
		"-A XCONNECT_ZERO_FWD -s 10.66.0.2/32 -d 10.66.0.4/32 -p tcp --dport 8080",
		`-A XCONNECT_ZERO_FWD -m comment --comment "xcz:rev=12:default=deny" -j DROP`,
	} {
		if !strings.Contains(rulesText, want) {
			t.Fatalf("compiled rules missing %q:\n%s", want, rulesText)
		}
	}
}
