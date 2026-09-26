package gateway

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"strings"
	"time"
)

const Role = "gateway"

const (
	FrontendDirectTLS    = "direct-tls"
	FrontendCaddyUnixH2C = "caddy-unix-h2c"
	DefaultGatewaySocket = "/run/xconnect-gateway/xray.sock"
)

type SigningKey struct {
	KeyID     string     `json:"key_id"`
	Algorithm string     `json:"algorithm"`
	PublicKey string     `json:"public_key"`
	Status    string     `json:"status"`
	NotBefore time.Time  `json:"not_before"`
	NotAfter  *time.Time `json:"not_after,omitempty"`
}

type Peer struct {
	DeviceID           string `json:"device_id"`
	WireGuardPublicKey string `json:"wireguard_public_key"`
	WireGuardAddress   string `json:"wireguard_address"`
	AllowedIPs         string `json:"allowed_ips"`
}

type Transport struct {
	Kind         string `json:"kind,omitempty"`
	ServerName   string `json:"server_name"`
	Port         int    `json:"port"`
	AuthID       string `json:"auth_id"`
	Path         string `json:"path,omitempty"`
	Mode         string `json:"mode,omitempty"`
	Host         string `json:"host,omitempty"`
	Frontend     string `json:"frontend,omitempty"`
	ListenSocket string `json:"listen_socket,omitempty"`
}

type Signature struct {
	Algorithm string `json:"algorithm"`
	KeyID     string `json:"key_id"`
	Value     string `json:"value"`
}

type Config struct {
	SchemaVersion int       `json:"schema_version"`
	Role          string    `json:"role"`
	ConfigID      string    `json:"config_id"`
	NetworkID     string    `json:"network_id"`
	GatewayID     string    `json:"gateway_id"`
	Generation    uint64    `json:"generation"`
	IssuedAt      time.Time `json:"issued_at"`
	ExpiresAt     time.Time `json:"expires_at"`
	InterfaceName string    `json:"interface_name"`
	Address       string    `json:"address"`
	ListenPort    int       `json:"listen_port"`
	MTU           int       `json:"mtu"`
	Peers         []Peer    `json:"peers"`
	Transport     Transport `json:"transport"`
	Signature     Signature `json:"signature"`
}

func (c Config) signingBytes() ([]byte, error) {
	return json.Marshal(struct {
		SchemaVersion int       `json:"schema_version"`
		Role          string    `json:"role"`
		ConfigID      string    `json:"config_id"`
		NetworkID     string    `json:"network_id"`
		GatewayID     string    `json:"gateway_id"`
		Generation    uint64    `json:"generation"`
		IssuedAt      time.Time `json:"issued_at"`
		ExpiresAt     time.Time `json:"expires_at"`
		InterfaceName string    `json:"interface_name"`
		Address       string    `json:"address"`
		ListenPort    int       `json:"listen_port"`
		MTU           int       `json:"mtu"`
		Peers         []Peer    `json:"peers"`
		Transport     Transport `json:"transport"`
	}{c.SchemaVersion, c.Role, c.ConfigID, c.NetworkID, c.GatewayID, c.Generation, c.IssuedAt, c.ExpiresAt, c.InterfaceName, c.Address, c.ListenPort, c.MTU, c.Peers, c.Transport})
}

func (c Config) Verify(keys []SigningKey, now time.Time) error {
	if c.SchemaVersion != 1 || c.Role != Role || c.ConfigID == "" || c.NetworkID == "" || c.GatewayID == "" || c.Generation == 0 || c.InterfaceName == "" || len(c.InterfaceName) > 15 || c.ListenPort < 1 || c.ListenPort > 65535 || c.MTU < 576 || (c.Transport.Kind != "" && c.Transport.Kind != "vless-xhttp") || c.Transport.Port != 443 || c.Transport.ServerName == "" || c.Transport.AuthID == "" || c.Signature.Algorithm != "Ed25519" || !c.ExpiresAt.After(now) || c.IssuedAt.After(now.Add(30*time.Second)) {
		return errors.New("invalid gateway signed config")
	}
	frontend := c.Transport.Frontend
	if frontend == "" {
		frontend = os.Getenv("XCONNECT_GATEWAY_FRONTEND")
	}
	if frontend == "" {
		frontend = FrontendDirectTLS
	}
	if frontend != FrontendDirectTLS && frontend != FrontendCaddyUnixH2C {
		return errors.New("invalid gateway XHTTP frontend")
	}
	if frontend == FrontendCaddyUnixH2C {
		socket := strings.TrimSpace(c.Transport.ListenSocket)
		if socket == "" {
			socket = os.Getenv("XCONNECT_GATEWAY_LISTEN_SOCKET")
		}
		if socket == "" {
			socket = DefaultGatewaySocket
		}
		if !strings.HasPrefix(socket, "/") || len(socket) > 4096 || strings.ContainsAny(socket, "\r\n") {
			return errors.New("invalid gateway XHTTP listen socket")
		}
	}
	if c.Transport.Path != "" && (!strings.HasPrefix(c.Transport.Path, "/") || len(c.Transport.Path) > 1024) {
		return errors.New("invalid gateway XHTTP path")
	}
	if c.Transport.Mode != "" && c.Transport.Mode != "auto" && c.Transport.Mode != "packet-up" && c.Transport.Mode != "stream-up" {
		return errors.New("invalid gateway XHTTP mode")
	}
	if c.Transport.Host != "" && strings.TrimSpace(c.Transport.Host) == "" {
		return errors.New("invalid gateway XHTTP host")
	}
	if prefix, err := netip.ParsePrefix(c.Address); err != nil || !prefix.Addr().Is4() || prefix.Bits() != 32 {
		return errors.New("invalid gateway address")
	}
	for _, peer := range c.Peers {
		if peer.DeviceID == "" || peer.WireGuardAddress == "" || peer.AllowedIPs == "" {
			return errors.New("invalid gateway peer")
		}
		key, err := base64.StdEncoding.DecodeString(peer.WireGuardPublicKey)
		if err != nil || len(key) != 32 {
			return errors.New("invalid peer public key")
		}
	}
	payload, err := c.signingBytes()
	if err != nil {
		return err
	}
	sig, err := base64.StdEncoding.DecodeString(c.Signature.Value)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return errors.New("invalid gateway signature")
	}
	for _, key := range keys {
		if key.KeyID != c.Signature.KeyID || key.Algorithm != "Ed25519" || key.Status != "current" && key.Status != "retiring" || key.NotBefore.After(c.IssuedAt) || key.NotAfter != nil && !c.ExpiresAt.Before(*key.NotAfter) {
			continue
		}
		publicKey, decodeErr := base64.StdEncoding.DecodeString(key.PublicKey)
		if decodeErr == nil && len(publicKey) == ed25519.PublicKeySize && ed25519.Verify(publicKey, payload, sig) {
			return nil
		}
	}
	return errors.New("gateway config signature is not trusted")
}

func (c Config) WireGuard(privateKey string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "[Interface]\nPrivateKey = %s\nAddress = %s\nListenPort = %d\nMTU = %d\n", strings.TrimSpace(privateKey), c.Address, c.ListenPort, c.MTU)
	for _, peer := range c.Peers {
		fmt.Fprintf(&b, "\n[Peer]\n# DeviceID = %s\nPublicKey = %s\nAllowedIPs = %s\n", peer.DeviceID, peer.WireGuardPublicKey, peer.AllowedIPs)
	}
	return b.String()
}

func (c Config) Xray(certPath, keyPath string) ([]byte, error) {
	frontend := c.Transport.Frontend
	if frontend == "" {
		frontend = os.Getenv("XCONNECT_GATEWAY_FRONTEND")
	}
	if frontend == "" {
		frontend = FrontendDirectTLS
	}
	if frontend == FrontendDirectTLS && (strings.TrimSpace(certPath) == "" || strings.TrimSpace(keyPath) == "") {
		return nil, errors.New("TLS certificate and key paths are required")
	}
	listenSocket := strings.TrimSpace(c.Transport.ListenSocket)
	if listenSocket == "" {
		listenSocket = os.Getenv("XCONNECT_GATEWAY_LISTEN_SOCKET")
	}
	if listenSocket == "" {
		listenSocket = DefaultGatewaySocket
	}
	if frontend == FrontendCaddyUnixH2C && listenSocket == "" {
		return nil, errors.New("Gateway Unix socket is required for Caddy frontend")
	}

	listen := any("0.0.0.0")
	stream := map[string]any{
		"network": "xhttp",
		"xhttpSettings": map[string]any{
			"path": c.Transport.XHTTPPath(),
			"mode": c.Transport.XHTTPMode(),
			"host": c.Transport.XHTTPHost(),
		},
	}
	if frontend == FrontendCaddyUnixH2C {
		listen = listenSocket + ",0660"
	} else {
		stream["security"] = "tls"
		stream["tlsSettings"] = map[string]any{
			"rejectUnknownSni": true,
			"minVersion":       "1.2",
			"certificates": []any{map[string]any{
				"certificateFile": certPath,
				"keyFile":         keyPath,
			}},
		}
	}
	inbound := map[string]any{
		"tag":            "xconnect-vless-in",
		"listen":         listen,
		"protocol":       "vless",
		"settings":       map[string]any{"clients": []any{map[string]any{"id": c.Transport.AuthID}}, "decryption": "none"},
		"streamSettings": stream,
	}
	if frontend == FrontendDirectTLS {
		inbound["port"] = c.Transport.Port
	}
	profile := map[string]any{
		"log": map[string]any{"loglevel": "warning"},
		"routing": map[string]any{
			"domainStrategy": "AsIs",
			"rules": []any{map[string]any{
				"type":        "field",
				"inboundTag":  []string{"xconnect-vless-in"},
				"outboundTag": "xconnect-wireguard",
			}},
		},
		"inbounds": []any{inbound},
		"outbounds": []any{
			map[string]any{"tag": "xconnect-wireguard", "protocol": "freedom", "settings": map[string]any{"redirect": "127.0.0.1:51820"}},
			map[string]any{"tag": "block", "protocol": "blackhole"},
		},
	}
	return json.MarshalIndent(profile, "", "  ")
}

func (t Transport) XHTTPPath() string {
	if strings.TrimSpace(t.Path) == "" {
		return "/xconnect"
	}
	return t.Path
}

func (t Transport) XHTTPMode() string {
	if strings.TrimSpace(t.Mode) == "" {
		return "auto"
	}
	return t.Mode
}

func (t Transport) XHTTPHost() string {
	if strings.TrimSpace(t.Host) == "" {
		return t.ServerName
	}
	return t.Host
}
