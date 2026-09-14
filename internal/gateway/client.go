package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type DeviceCredential struct {
	CredentialID string    `json:"credential_id"`
	Credential   string    `json:"credential"`
	TokenType    string    `json:"token_type"`
	IssuedAt     time.Time `json:"issued_at"`
	ExpiresAt    time.Time `json:"expires_at"`
	Scope        []string  `json:"scope"`
}
type Device struct {
	ID                 string     `json:"id"`
	UserID             string     `json:"user_id,omitempty"`
	NetworkID          string     `json:"network_id"`
	Role               string     `json:"role"`
	Name               string     `json:"name"`
	Platform           string     `json:"platform"`
	Hostname           string     `json:"hostname"`
	WireGuardPublicKey string     `json:"wireguard_public_key"`
	WireGuardAddress   string     `json:"wireguard_address"`
	CreatedAt          time.Time  `json:"created_at,omitempty"`
	UpdatedAt          time.Time  `json:"updated_at,omitempty"`
	LastSeenAt         *time.Time `json:"last_seen_at,omitempty"`
}
type Network struct {
	ID                  string    `json:"id"`
	DisplayName         string    `json:"display_name"`
	CIDR                string    `json:"cidr"`
	GatewayID           string    `json:"gateway_id"`
	GatewayWireGuardKey string    `json:"gateway_wireguard_public_key"`
	GatewayEndpointHost string    `json:"gateway_endpoint_host"`
	GatewayEndpointPort int       `json:"gateway_endpoint_port"`
	TransportServerName string    `json:"transport_server_name"`
	TransportPort       int       `json:"transport_port"`
	TransportAuthID     string    `json:"transport_auth_id"`
	TransportKind       string    `json:"transport_kind"`
	TransportPath       string    `json:"transport_path"`
	TransportMode       string    `json:"transport_mode"`
	TransportHost       string    `json:"transport_host"`
	CreatedAt           time.Time `json:"created_at"`
	UpdatedAt           time.Time `json:"updated_at"`
}
type ExchangeResponse struct {
	EnrollmentToken  string           `json:"enrollment_token"`
	TokenType        string           `json:"token_type"`
	ExpiresAt        time.Time        `json:"expires_at"`
	Scope            []string         `json:"scope"`
	DeviceCredential DeviceCredential `json:"device_credential"`
	Device           Device           `json:"device"`
	Network          Network          `json:"network"`
	SigningKeys      []SigningKey     `json:"signing_keys"`
}
type SessionResponse struct {
	ClientNonce     string       `json:"client_nonce"`
	EnrollmentToken string       `json:"enrollment_token"`
	TokenType       string       `json:"token_type"`
	IssuedAt        time.Time    `json:"issued_at"`
	ExpiresAt       time.Time    `json:"expires_at"`
	Scope           []string     `json:"scope"`
	DeviceID        string       `json:"device_id"`
	NetworkID       string       `json:"network_id"`
	SigningKeys     []SigningKey `json:"signing_keys"`
}

type Client struct {
	base *url.URL
	http *http.Client
}

func NewClient(controller string) (*Client, error) {
	u, err := url.Parse(strings.TrimRight(strings.TrimSpace(controller), "/"))
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return nil, errors.New("controller must be an HTTPS origin")
	}
	return &Client{base: u, http: &http.Client{Timeout: 20 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("redirect rejected") }}}, nil
}

func (c *Client) request(ctx context.Context, method, path, authorization string, input, output any) (http.Header, error) {
	endpoint := *c.base
	endpoint.Path = strings.TrimRight(endpoint.Path, "/") + path
	var body io.Reader
	if input != nil {
		raw, err := json.Marshal(input)
		if err != nil {
			return nil, err
		}
		body = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, endpoint.String(), body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	if input != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if authorization != "" {
		req.Header.Set("Authorization", authorization)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 65536))
		return nil, fmt.Errorf("Zero API returned HTTP %d", resp.StatusCode)
	}
	decoder := json.NewDecoder(io.LimitReader(resp.Body, 2<<20))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(output); err != nil {
		return nil, err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return nil, errors.New("response has trailing data")
	}
	return resp.Header.Clone(), nil
}

func (c *Client) Exchange(ctx context.Context, token, gatewayID, hostname, publicKey string) (ExchangeResponse, error) {
	var out ExchangeResponse
	head, err := c.request(ctx, http.MethodPost, "/api/overlay/v1/join-tokens/exchange", "", map[string]any{"join_token": token, "device_id": gatewayID, "name": gatewayID, "platform": "linux", "hostname": hostname, "role": Role, "wireguard_public_key": publicKey}, &out)
	if err != nil {
		return out, err
	}
	if head.Get("Cache-Control") != "no-store" || out.Device.ID != gatewayID || out.Device.Role != Role || out.Device.WireGuardPublicKey != publicKey || out.Network.ID != out.Device.NetworkID {
		return out, errors.New("invalid gateway enrollment response")
	}
	return out, nil
}

func (c *Client) Session(ctx context.Context, credential, nonce string) (SessionResponse, error) {
	var out SessionResponse
	head, err := c.request(ctx, http.MethodPost, "/api/overlay/v1/device/session", "XConnect-Device "+credential, map[string]string{"client_nonce": nonce}, &out)
	if err != nil {
		return out, err
	}
	if !strings.Contains(head.Get("Cache-Control"), "no-store") {
		return out, errors.New("unsafe session cache policy")
	}
	return out, nil
}
func (c *Client) Config(ctx context.Context, token string) (Config, error) {
	var out Config
	head, err := c.request(ctx, http.MethodGet, "/api/overlay/v1/gateway/signed-config", "Bearer "+token, nil, &out)
	if err != nil {
		return out, err
	}
	if head.Get("Cache-Control") != "private, no-store" || head.Get("ETag") == "" {
		return out, errors.New("unsafe gateway config response")
	}
	return out, nil
}
func (c *Client) Ack(ctx context.Context, token string, cfg Config) error {
	var out struct {
		Acked     bool `json:"acked"`
		Duplicate bool `json:"duplicate"`
		Ack       struct {
			DeviceID   string    `json:"device_id"`
			ConfigID   string    `json:"config_id"`
			Generation uint64    `json:"generation"`
			AppliedAt  time.Time `json:"applied_at"`
			ReceivedAt time.Time `json:"received_at"`
		} `json:"ack"`
	}
	_, err := c.request(ctx, http.MethodPost, fmt.Sprintf("/api/overlay/v1/enrollment/signed-config/%d/ack", cfg.Generation), "Bearer "+token, map[string]string{"config_id": cfg.ConfigID, "device_id": cfg.GatewayID, "applied_at": time.Now().UTC().Truncate(time.Second).Format(time.RFC3339)}, &out)
	if err == nil && !out.Acked {
		return errors.New("Zero rejected gateway config acknowledgement")
	}
	return err
}
