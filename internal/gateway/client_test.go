package gateway

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestClientAcceptsFormalZeroExchangeAndAckResponses(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Header.Get("User-Agent") != httpUserAgent {
			http.Error(w, "stable user agent required", http.StatusForbidden)
			return
		}
		switch r.URL.Path {
		case "/api/overlay/v1/join-tokens/exchange":
			w.Header().Set("Cache-Control", "no-store")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"enrollment_token": "xenr_test", "token_type": "Bearer", "expires_at": now.Add(10 * time.Minute),
				"scope":             []string{"overlay:config:read", "overlay:config:ack", "overlay:device:revoke"},
				"device_credential": map[string]any{"credential_id": "credential-1", "credential": "xdc_test", "token_type": "Device", "issued_at": now, "expires_at": now.Add(24 * time.Hour), "scope": []string{"overlay:session:mint", "overlay:credential:rotate", "overlay:device:revoke"}},
				"device":            map[string]any{"id": "gw-test", "user_id": "11111111-2222-4333-8444-555555555555", "network_id": "net-test", "role": "gateway", "name": "gw-test", "platform": "linux", "hostname": "gateway", "wireguard_public_key": "public-key", "wireguard_address": "10.77.0.1/32", "created_at": now, "updated_at": now},
				"network":           map[string]any{"id": "net-test", "display_name": "Test", "cidr": "10.77.0.0/24", "gateway_id": "gw-test", "gateway_wireguard_public_key": "public-key", "gateway_endpoint_host": "gateway.example.test", "gateway_endpoint_port": 51820, "transport_server_name": "gateway.example.test", "transport_port": 443, "transport_auth_id": "11111111-1111-1111-1111-111111111111", "created_at": now, "updated_at": now},
				"signing_keys":      []any{},
			})
		case "/api/overlay/v1/enrollment/signed-config/2/ack":
			_ = json.NewEncoder(w).Encode(map[string]any{"acked": true, "duplicate": false, "ack": map[string]any{"device_id": "gw-test", "config_id": "cfg-test", "generation": 2, "applied_at": now, "received_at": now}})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	client, err := NewClient(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	client.http = server.Client()
	response, err := client.Exchange(context.Background(), "join-token", "gw-test", "gateway", "public-key")
	if err != nil || response.TokenType != "Bearer" || response.DeviceCredential.TokenType != "Device" {
		t.Fatalf("formal exchange response rejected: response=%#v err=%v", response, err)
	}
	if err := client.Ack(context.Background(), "enrollment-token", Config{ConfigID: "cfg-test", GatewayID: "gw-test", Generation: 2}); err != nil {
		t.Fatalf("formal ack response rejected: %v", err)
	}
}

func TestClientSessionUsesFormalDeviceAuthorizationAndRoundTripsNonce(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	const credential = "xdc_gateway-credential"
	const nonce = "gateway-session-nonce"
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/overlay/v1/device/session" {
			http.NotFound(w, r)
			return
		}
		if got := r.Header.Get("Authorization"); got != "Device "+credential {
			http.Error(w, "formal Device authorization required", http.StatusUnauthorized)
			return
		}
		if got := r.Header.Get("XConnect-Device"); got != "" {
			http.Error(w, "legacy device header must not be sent", http.StatusBadRequest)
			return
		}
		var request struct {
			ClientNonce string `json:"client_nonce"`
		}
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil || request.ClientNonce != nonce {
			http.Error(w, "client nonce mismatch", http.StatusBadRequest)
			return
		}
		w.Header().Set("Cache-Control", "private, no-store")
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(SessionResponse{
			ClientNonce:     request.ClientNonce,
			EnrollmentToken: "xenr_gateway",
			TokenType:       "Bearer",
			IssuedAt:        now,
			ExpiresAt:       now.Add(10 * time.Minute),
			Scope:           []string{"overlay:config:read", "overlay:config:ack"},
			DeviceID:        "gateway-1",
			NetworkID:       "network-1",
			SigningKeys:     []SigningKey{},
		})
	}))
	defer server.Close()

	client, err := NewClient(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	client.http = server.Client()
	response, err := client.Session(context.Background(), credential, nonce)
	if err != nil {
		t.Fatalf("formal session contract rejected: response=%#v err=%v", response, err)
	}
	if response.ClientNonce != nonce || response.DeviceID != "gateway-1" || response.NetworkID != "network-1" || response.EnrollmentToken == "" {
		t.Fatalf("invalid session response bindings: %#v", response)
	}
}

func TestClientRepeatedAckSameGeneration(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	var ackCount int
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/api/overlay/v1/enrollment/signed-config/2/ack" {
			ackCount++
			_ = json.NewEncoder(w).Encode(map[string]any{
				"acked":     true,
				"duplicate": ackCount > 1,
				"ack": map[string]any{
					"device_id":   "gw-test",
					"config_id":   "cfg-test",
					"generation":  2,
					"applied_at":  now,
					"received_at": now,
				},
			})
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()

	client, err := NewClient(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	client.http = server.Client()

	cfg := Config{ConfigID: "cfg-test", GatewayID: "gw-test", Generation: 2}

	// 1st ACK
	if err := client.Ack(context.Background(), "token", cfg); err != nil {
		t.Fatalf("first ack failed: %v", err)
	}

	// 2nd ACK on same generation (heartbeat sync)
	if err := client.Ack(context.Background(), "token", cfg); err != nil {
		t.Fatalf("second ack on same generation failed: %v", err)
	}

	if ackCount != 2 {
		t.Fatalf("expected server to receive 2 ACKs for same generation, got %d", ackCount)
	}
}

func TestClientAckFailureReturnsError(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "internal server error", http.StatusInternalServerError)
	}))
	defer server.Close()

	client, err := NewClient(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	client.http = server.Client()

	cfg := Config{ConfigID: "cfg-test", GatewayID: "gw-test", Generation: 2}
	err = client.Ack(context.Background(), "token", cfg)
	if err == nil {
		t.Fatal("expected error on server 500 for Ack, got nil")
	}
}

func TestClientConfigSendsV2AcceptHeaderAndDecodesV1AndV2(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	var acceptHeaders []string
	respondV2 := true

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/overlay/v1/gateway/signed-config" {
			http.NotFound(w, r)
			return
		}
		acceptHeaders = append(acceptHeaders, r.Header.Get("Accept"))
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "private, no-store")
		w.Header().Set("ETag", `"etag-1"`)
		if !respondV2 {
			_ = json.NewEncoder(w).Encode(Config{
				SchemaVersion: 1, Role: Role, ConfigID: "cfg-v1", NetworkID: "net-1", GatewayID: "gw-1",
				Generation: 1, IssuedAt: now, ExpiresAt: now.Add(time.Minute), InterfaceName: "xconzero0",
				Address: "10.66.0.1/32", ListenPort: 51820, MTU: 1420,
				Transport: Transport{ServerName: "gw.example.test", Port: 443, AuthID: "auth-1"},
				Signature: Signature{Algorithm: "Ed25519", KeyID: "key-1", Value: "sig"},
			})
			return
		}
		_ = json.NewEncoder(w).Encode(Config{
			SchemaVersion: 2, Role: Role, ConfigID: "cfg-v2", NetworkID: "net-1", GatewayID: "gw-1",
			Generation: 2, IssuedAt: now, ExpiresAt: now.Add(time.Minute), ConnectionMode: ConnectionModeWGVLESSL3,
			InterfaceName: "xconzero0", Address: "10.66.0.1/32", ListenPort: 51820, MTU: 1420,
			Transport: Transport{Kind: "vless-xhttp", ServerName: "gw.example.test", Port: 443, AuthID: "auth-1"},
			Policy: &PolicyArtifact{
				SchemaVersion:   1,
				CompilerVersion: "xconnect-policy-v1",
				NetworkID:       "net-1",
				Revision:        2,
				DefaultAction:   "deny",
				ProtectedFlows:  []string{"control:controller-session"},
				Rules:           []PolicyRule{{ID: "r1", Action: "allow", SourceDevices: []string{"*"}, DestinationDevices: []string{"*"}, Protocols: []string{"icmp"}}},
			},
			Signature: Signature{Algorithm: "Ed25519", KeyID: "key-1", Value: "sig"},
		})
	}))
	defer server.Close()

	client, err := NewClient(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	client.http = server.Client()

	v2Cfg, err := client.Config(context.Background(), "token")
	if err != nil {
		t.Fatalf("expected v2 config decode to succeed: %v", err)
	}
	if v2Cfg.SchemaVersion != 2 || v2Cfg.Policy == nil || len(v2Cfg.Policy.Rules) != 1 || v2Cfg.Policy.Rules[0].ID != "r1" {
		t.Fatalf("unexpected decoded v2 config: %+v", v2Cfg)
	}

	respondV2 = false
	v1Cfg, err := client.Config(context.Background(), "token")
	if err != nil {
		t.Fatalf("expected v1 fallback config decode to succeed: %v", err)
	}
	if v1Cfg.SchemaVersion != 1 || v1Cfg.Policy != nil {
		t.Fatalf("unexpected decoded v1 config: %+v", v1Cfg)
	}

	if len(acceptHeaders) != 2 || !strings.Contains(acceptHeaders[0], SignedConfigV2MediaType) || !strings.Contains(acceptHeaders[0], "application/json") {
		t.Fatalf("expected Accept header to negotiate %s, got %#v", SignedConfigV2MediaType, acceptHeaders)
	}
}
