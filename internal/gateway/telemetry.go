package gateway

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

type OverlayStatus struct {
	NetworkID    string        `json:"network_id"`
	DeviceID     string        `json:"device_id"`
	Role         string        `json:"role"`
	Capabilities []string      `json:"capabilities"`
	Healthy      bool          `json:"healthy"`
	UpdatedAt    time.Time     `json:"updated_at"`
	ExpiresAt    time.Time     `json:"expires_at"`
	Paths        []OverlayPath `json:"paths,omitempty"`
}

type OverlayPath struct {
	SentPackets     uint64 `json:"sent_packets"`
	ReceivedPackets uint64 `json:"received_packets"`
	DeviceID        string `json:"device_id"`
	Path            string `json:"path"`
	Endpoint        string `json:"endpoint,omitempty"`
	RTTMillis       int64  `json:"rtt_ms,omitempty"`
	Reason          string `json:"reason"`
}

type GatewayTelemetry struct {
	SchemaVersion       int                    `json:"schema_version"`
	NetworkID           string                 `json:"network_id"`
	GatewayID           string                 `json:"gateway_id"`
	EndpointHost        string                 `json:"endpoint_host,omitempty"`
	ConnectionMode      string                 `json:"connection_mode,omitempty"`
	AppliedConfigID     string                 `json:"applied_config_id,omitempty"`
	AppliedGeneration   uint64                 `json:"applied_generation,omitempty"`
	WireGuardRunning    bool                   `json:"wireguard_running"`
	XrayRunning         bool                   `json:"xray_running"`
	RelayRunning        bool                   `json:"relay_running"`
	RelayActiveSessions int                    `json:"relay_active_sessions,omitempty"`
	SampledAt           time.Time              `json:"sampled_at"`
	ExpiresAt           time.Time              `json:"expires_at"`
	Traffic             GatewayTrafficSummary  `json:"traffic"`
	Peers               []GatewayPeerTelemetry `json:"peers,omitempty"`
	TopApps             []GatewayAppTraffic    `json:"top_apps,omitempty"`
}

type GatewayTrafficSummary struct {
	RxBytesTotal    uint64 `json:"rx_bytes_total"`
	TxBytesTotal    uint64 `json:"tx_bytes_total"`
	InternetRxBytes uint64 `json:"internet_rx_bytes"`
	InternetTxBytes uint64 `json:"internet_tx_bytes"`
	PrivateRxBytes  uint64 `json:"private_rx_bytes"`
	PrivateTxBytes  uint64 `json:"private_tx_bytes"`
}

type GatewayPeerTelemetry struct {
	DeviceID          string     `json:"device_id"`
	WireGuardAddress  string     `json:"wireguard_address,omitempty"`
	Connected         bool       `json:"connected"`
	Path              string     `json:"path,omitempty"`
	Endpoint          string     `json:"endpoint,omitempty"`
	LatestHandshakeAt *time.Time `json:"latest_handshake_at,omitempty"`
	RxBytes           uint64     `json:"rx_bytes"`
	TxBytes           uint64     `json:"tx_bytes"`
	RTTMillis         int64      `json:"rtt_ms,omitempty"`
}

type GatewayAppTraffic struct {
	App         string `json:"app"`
	RxBytes     uint64 `json:"rx_bytes"`
	TxBytes     uint64 `json:"tx_bytes"`
	Connections int    `json:"connections"`
}

type WgDumpPeer struct {
	PublicKey       string
	PresharedKey    string
	Endpoint        string
	AllowedIPs      string
	LatestHandshake int64
	RxBytes         uint64
	TxBytes         uint64
	PersistentKA    string
}

func ParseWgDump(raw string) []WgDumpPeer {
	lines := strings.Split(strings.TrimSpace(raw), "\n")
	if len(lines) <= 1 {
		return nil
	}
	// First line is interface info: privateKey, publicKey, listenPort, fwmark
	var peers []WgDumpPeer
	for _, line := range lines[1:] {
		fields := strings.Split(line, "\t")
		if len(fields) < 8 {
			continue
		}
		handshake, _ := strconv.ParseInt(fields[4], 10, 64)
		rx, _ := strconv.ParseUint(fields[5], 10, 64)
		tx, _ := strconv.ParseUint(fields[6], 10, 64)
		peers = append(peers, WgDumpPeer{
			PublicKey:       fields[0],
			PresharedKey:    fields[1],
			Endpoint:        fields[2],
			AllowedIPs:      fields[3],
			LatestHandshake: handshake,
			RxBytes:         rx,
			TxBytes:         tx,
			PersistentKA:    fields[7],
		})
	}
	return peers
}

func BuildTelemetry(cfg Config, dumpPeers []WgDumpPeer, wgRunning, xrayRunning, relayRunning bool, now time.Time) (GatewayTelemetry, OverlayStatus) {
	now = now.UTC().Truncate(time.Second)
	mode := cfg.EffectiveConnectionMode()
	defaultPath := "vless-xhttp"
	if mode == ConnectionModeWGUDPL3 {
		defaultPath = "wg-udp"
	}

	peerMap := make(map[string]WgDumpPeer)
	for _, dp := range dumpPeers {
		peerMap[dp.PublicKey] = dp
	}

	var totalRx, totalTx uint64
	var telemetryPeers []GatewayPeerTelemetry
	var overlayPaths []OverlayPath

	for _, p := range cfg.Peers {
		dp, hasDump := peerMap[p.WireGuardPublicKey]
		var rx, tx uint64
		var connected bool
		var handshakeTime *time.Time
		var endpoint string

		if hasDump {
			rx = dp.RxBytes
			tx = dp.TxBytes
			totalRx += rx
			totalTx += tx
			endpoint = dp.Endpoint
			if dp.LatestHandshake > 0 {
				t := time.Unix(dp.LatestHandshake, 0).UTC()
				handshakeTime = &t
				if now.Sub(t) <= 3*time.Minute {
					connected = true
				}
			}
		}

		telemetryPeers = append(telemetryPeers, GatewayPeerTelemetry{
			DeviceID:          p.DeviceID,
			WireGuardAddress:  p.WireGuardAddress,
			Connected:         connected,
			Path:              defaultPath,
			Endpoint:          endpoint,
			LatestHandshakeAt: handshakeTime,
			RxBytes:           rx,
			TxBytes:           tx,
			RTTMillis:         0,
		})

		overlayPaths = append(overlayPaths, OverlayPath{
			DeviceID:        p.DeviceID,
			Path:            defaultPath,
			Endpoint:        endpoint,
			SentPackets:     tx / 1280,
			ReceivedPackets: rx / 1280,
			Reason:          "ok",
		})
	}

	healthy := wgRunning
	if mode == ConnectionModeWGVLESSL3 || mode == "" {
		healthy = healthy && xrayRunning
	}

	gt := GatewayTelemetry{
		SchemaVersion:       1,
		NetworkID:           cfg.NetworkID,
		GatewayID:           cfg.GatewayID,
		EndpointHost:        cfg.Transport.ServerName,
		ConnectionMode:      mode,
		AppliedConfigID:     cfg.ConfigID,
		AppliedGeneration:   cfg.Generation,
		WireGuardRunning:    wgRunning,
		XrayRunning:         xrayRunning,
		RelayRunning:        relayRunning,
		RelayActiveSessions: 0,
		SampledAt:           now,
		ExpiresAt:           now.Add(30 * time.Second),
		Traffic: GatewayTrafficSummary{
			RxBytesTotal:    totalRx,
			TxBytesTotal:    totalTx,
			PrivateRxBytes:  totalRx,
			PrivateTxBytes:  totalTx,
			InternetRxBytes: 0,
			InternetTxBytes: 0,
		},
		Peers:   telemetryPeers,
		TopApps: []GatewayAppTraffic{},
	}

	caps := []string{"gateway", "wireguard"}
	if relayRunning || cfg.Mesh != nil {
		caps = append(caps, "relay")
	}
	caps = append(caps, mode)

	osStatus := OverlayStatus{
		NetworkID:    cfg.NetworkID,
		DeviceID:     cfg.GatewayID,
		Role:         Role,
		Capabilities: caps,
		Healthy:      healthy,
		UpdatedAt:    now,
		ExpiresAt:    now.Add(30 * time.Second),
		Paths:        overlayPaths,
	}

	return gt, osStatus
}

func CollectAndWriteTelemetry(ctx context.Context, dir string, cfg Config, wgRunning, xrayRunning, relayRunning bool) error {
	var dumpPeers []WgDumpPeer
	if wgRunning && cfg.InterfaceName != "" {
		if raw, err := exec.CommandContext(ctx, "wg", "show", cfg.InterfaceName, "dump").Output(); err == nil {
			dumpPeers = ParseWgDump(string(raw))
		}
	}
	gt, osStatus := BuildTelemetry(cfg, dumpPeers, wgRunning, xrayRunning, relayRunning, time.Now())
	return WriteGatewayTelemetry(dir, gt, osStatus)
}

func WriteGatewayTelemetry(dir string, telemetry GatewayTelemetry, status OverlayStatus) error {
	runtimeDir := filepath.Join(dir, "runtime")
	if err := os.MkdirAll(runtimeDir, 0755); err != nil {
		return err
	}

	gtBytes, err := json.MarshalIndent(telemetry, "", "  ")
	if err != nil {
		return err
	}
	tmpGT := filepath.Join(runtimeDir, ".gateway-telemetry.json.tmp")
	if err := os.WriteFile(tmpGT, gtBytes, 0644); err != nil {
		return err
	}
	if err := os.Rename(tmpGT, filepath.Join(runtimeDir, "gateway-telemetry.json")); err != nil {
		return err
	}

	osBytes, err := json.MarshalIndent(status, "", "  ")
	if err != nil {
		return err
	}
	tmpOS := filepath.Join(runtimeDir, ".overlay-status.json.tmp")
	if err := os.WriteFile(tmpOS, osBytes, 0644); err != nil {
		return err
	}
	return os.Rename(tmpOS, filepath.Join(runtimeDir, "overlay-status.json"))
}
