package gateway

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"time"
)

type State struct {
	SchemaVersion       int              `json:"schema_version"`
	Controller          string           `json:"controller"`
	GatewayID           string           `json:"gateway_id"`
	NetworkID           string           `json:"network_id"`
	PrivateKey          string           `json:"wireguard_private_key"`
	PublicKey           string           `json:"wireguard_public_key"`
	Credential          DeviceCredential `json:"device_credential"`
	SigningKeys         []SigningKey     `json:"signing_keys"`
	EnrollmentToken     string           `json:"enrollment_token,omitempty"`
	EnrollmentExpiresAt time.Time        `json:"enrollment_expires_at,omitempty"`
	AppliedConfigID     string           `json:"applied_config_id,omitempty"`
	AppliedGeneration   uint64           `json:"applied_generation,omitempty"`
}

func LoadPendingState(dir string) (State, error) {
	var state State
	raw, err := os.ReadFile(filepath.Join(dir, "state.json"))
	if err != nil {
		return state, err
	}
	if err = json.Unmarshal(raw, &state); err != nil {
		return state, err
	}
	if state.SchemaVersion != 1 || state.Controller == "" || state.GatewayID == "" || state.PrivateKey == "" || state.PublicKey == "" {
		return state, errors.New("invalid gateway state")
	}
	return state, nil
}
func LoadState(dir string) (State, error) {
	state, err := LoadPendingState(dir)
	if err != nil {
		return state, err
	}
	if state.Credential.Credential == "" {
		return state, errors.New("gateway enrollment is incomplete")
	}
	return state, nil
}
func SaveState(dir string, state State) error {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	tmp := filepath.Join(dir, ".state.json.tmp")
	if err := os.WriteFile(tmp, raw, 0600); err != nil {
		return err
	}
	if err := os.Chmod(tmp, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Join(dir, "state.json"))
}
func WriteRuntime(dir string, cfg Config, privateKey, cert, key string) error {
	runtimeDir := filepath.Join(dir, "runtime")
	if err := os.MkdirAll(runtimeDir, 0700); err != nil {
		return err
	}
	xray, err := cfg.Xray(cert, key)
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(runtimeDir, cfg.InterfaceName+".conf"), []byte(cfg.WireGuard(privateKey)), 0600); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(runtimeDir, "xray.json"), xray, 0600)
}

func SaveSignedConfig(dir string, cfg Config) error {
	runtimeDir := filepath.Join(dir, "runtime")
	if e := os.MkdirAll(runtimeDir, 0700); e != nil {
		return e
	}
	raw, e := json.Marshal(cfg)
	if e != nil {
		return e
	}
	tmp := filepath.Join(runtimeDir, ".signed-config.json.tmp")
	if e = os.WriteFile(tmp, raw, 0600); e != nil {
		return e
	}
	return os.Rename(tmp, filepath.Join(runtimeDir, "signed-config.json"))
}
