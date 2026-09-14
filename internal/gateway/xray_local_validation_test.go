package gateway

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func TestGeneratedXrayConfigAcceptedByInstalledCore(t *testing.T) {
	xrayPath, err := exec.LookPath("xray")
	if err != nil {
		t.Skip("xray is not installed in this test environment")
	}
	certDir := t.TempDir()
	certPath := filepath.Join(certDir, "tls.crt")
	keyPath := filepath.Join(certDir, "tls.key")
	if err := exec.Command("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", keyPath, "-out", certPath, "-days", "1", "-subj", "/CN=gateway.example.test").Run(); err != nil {
		t.Skipf("openssl is not available for local Xray validation: %v", err)
	}
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	cfg := Config{SchemaVersion: 1, Role: Role, ConfigID: "cfg-local-xray", NetworkID: "net-local", GatewayID: "gw-local", Generation: 1, IssuedAt: now, ExpiresAt: now.Add(time.Hour), InterfaceName: "xconzero0", Address: "10.77.0.1/32", ListenPort: 51820, MTU: 1280, Peers: []Peer{{DeviceID: "one-local", WireGuardPublicKey: base64.StdEncoding.EncodeToString(make([]byte, 32)), WireGuardAddress: "10.77.0.2/32", AllowedIPs: "10.77.0.2/32"}}, Transport: Transport{ServerName: "gateway.example.test", Port: 443, AuthID: "11111111-1111-1111-1111-111111111111"}, Signature: Signature{Algorithm: "Ed25519", KeyID: "key-local"}}
	payload, err := cfg.signingBytes()
	if err != nil {
		t.Fatal(err)
	}
	cfg.Signature.Value = base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, payload))
	config, err := cfg.Xray(certPath, keyPath)
	if err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(certDir, "xray.json")
	if err := os.WriteFile(configPath, config, 0o600); err != nil {
		t.Fatal(err)
	}
	command := exec.Command(xrayPath, "run", "-test", "-config", configPath)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("generated Gateway Xray config rejected: %v\n%s", err, output)
	}
}
