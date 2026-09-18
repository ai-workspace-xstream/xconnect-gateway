package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/ai-workspace-xstream/XConnect-Gateway/internal/gateway"
)

func main() {
	if err := run(context.Background(), os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "xconnect-gateway:", err)
		os.Exit(1)
	}
}
func run(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return errors.New("usage: xconnect-gateway <init|join|sync|up|down|status|diagnose>")
	}
	switch args[0] {
	case "init":
		return initState(ctx, args[1:])
	case "join":
		return join(ctx, args[1:])
	case "sync":
		return syncConfig(ctx, args[1:], false)
	case "up":
		return syncConfig(ctx, args[1:], true)
	case "down":
		return down(args[1:])
	case "status":
		return status(args[1:])
	case "diagnose":
		return diagnose()
	default:
		return fmt.Errorf("unknown command %q", args[0])
	}
}
func initState(ctx context.Context, args []string) error {
	f, dir := common("init", args)
	gatewayID := f.String("gateway-id", "", "Gateway ID matching the Zero network")
	controller := f.String("controller", "", "XConnect Zero accounts HTTPS origin")
	if err := f.Parse(args); err != nil {
		return err
	}
	if *gatewayID == "" {
		return errors.New("init requires --gateway-id")
	}
	client, err := gateway.NewClient(*controller)
	if err != nil {
		return err
	}
	_ = client
	privateKey, publicKey, err := wireGuardKeys(ctx)
	if err != nil {
		return err
	}
	state := gateway.State{SchemaVersion: 1, Controller: strings.TrimRight(*controller, "/"), GatewayID: *gatewayID, PrivateKey: privateKey, PublicKey: publicKey}
	if err := gateway.SaveState(*dir, state); err != nil {
		return err
	}
	fmt.Printf("wireguard_public_key=%s\n", publicKey)
	return nil
}
func common(name string, args []string) (*flag.FlagSet, *string) {
	f := flag.NewFlagSet(name, flag.ContinueOnError)
	dir := f.String("state-dir", "/var/lib/xconnect-gateway", "protected gateway state directory")
	return f, dir
}
func join(ctx context.Context, args []string) error {
	f, dir := common("join", args)
	gatewayID := f.String("gateway-id", "", "Gateway ID matching the Zero network")
	if err := f.Parse(args); err != nil {
		return err
	}
	if f.NArg() != 1 || *gatewayID == "" {
		return errors.New("join requires --gateway-id and one xconnect:// invite URI")
	}
	controller, token, err := parseInvite(f.Arg(0))
	if err != nil {
		return err
	}
	privateKey, publicKey := "", ""
	if pending, pendingErr := gateway.LoadPendingState(*dir); pendingErr == nil {
		if pending.GatewayID != *gatewayID || pending.Controller != strings.TrimRight(controller, "/") || pending.Credential.Credential != "" {
			return errors.New("existing gateway state does not match this enrollment")
		}
		privateKey, publicKey = pending.PrivateKey, pending.PublicKey
	} else {
		privateKey, publicKey, err = wireGuardKeys(ctx)
		if err != nil {
			return err
		}
	}
	hostname, _ := os.Hostname()
	client, err := gateway.NewClient(controller)
	if err != nil {
		return err
	}
	response, err := client.Exchange(ctx, token, *gatewayID, hostname, publicKey)
	if err != nil {
		return err
	}
	state := gateway.State{SchemaVersion: 1, Controller: controller, GatewayID: *gatewayID, NetworkID: response.Network.ID, PrivateKey: privateKey, PublicKey: publicKey, Credential: response.DeviceCredential, SigningKeys: response.SigningKeys, EnrollmentToken: response.EnrollmentToken, EnrollmentExpiresAt: response.ExpiresAt}
	if err := gateway.SaveState(*dir, state); err != nil {
		return err
	}
	fmt.Printf("Gateway %s enrolled in network %s\n", state.GatewayID, state.NetworkID)
	return nil
}
func syncConfig(ctx context.Context, args []string, apply bool) error {
	f, dir := common("sync", args)
	cert := f.String("tls-cert", "/etc/xconnect-gateway/tls.crt", "VLESS TLS certificate")
	key := f.String("tls-key", "/etc/xconnect-gateway/tls.key", "VLESS TLS private key")
	if err := f.Parse(args); err != nil {
		return err
	}
	state, err := gateway.LoadState(*dir)
	if err != nil {
		return err
	}
	client, err := gateway.NewClient(state.Controller)
	if err != nil {
		return err
	}
	token := state.EnrollmentToken
	if token == "" || !state.EnrollmentExpiresAt.After(time.Now().Add(time.Minute)) {
		session, sessionErr := client.Session(ctx, state.Credential.Credential, nonce())
		if sessionErr != nil {
			return sessionErr
		}
		if session.DeviceID != state.GatewayID || session.NetworkID != state.NetworkID {
			return errors.New("device session binding mismatch")
		}
		token = session.EnrollmentToken
		state.EnrollmentToken = token
		state.EnrollmentExpiresAt = session.ExpiresAt
		state.SigningKeys = session.SigningKeys
	}
	cfg, err := client.Config(ctx, token)
	if err != nil {
		return err
	}
	if cfg.GatewayID != state.GatewayID || cfg.NetworkID != state.NetworkID {
		return errors.New("signed config binding mismatch")
	}
	if err := cfg.Verify(state.SigningKeys, time.Now().UTC()); err != nil {
		return err
	}
	if err := gateway.WriteRuntime(*dir, cfg, state.PrivateKey, *cert, *key); err != nil {
		return err
	}
	if apply {
		if os.Geteuid() != 0 {
			return errors.New("up must run as root")
		}
		if state.AppliedConfigID != cfg.ConfigID || state.AppliedGeneration != cfg.Generation {
			if err := applyRuntime(ctx, *dir, cfg); err != nil {
				return err
			}
		}
		if err := client.Ack(ctx, token, cfg); err != nil {
			return err
		}
		state.AppliedConfigID = cfg.ConfigID
		state.AppliedGeneration = cfg.Generation
	}
	if err := gateway.SaveState(*dir, state); err != nil {
		return err
	}
	fmt.Printf("Gateway config %s generation %d %s\n", cfg.ConfigID, cfg.Generation, map[bool]string{true: "applied", false: "synced"}[apply])
	return nil
}
func applyRuntime(ctx context.Context, dir string, cfg gateway.Config) error {
	xrayPath := filepath.Join(dir, "runtime", "xray.json")
	wgPath := filepath.Join(dir, "runtime", cfg.InterfaceName+".conf")
	if err := command(ctx, "xray", "run", "-test", "-config", xrayPath); err != nil {
		return err
	}
	if wireGuardApplyMode(interfaceExists(ctx, cfg.InterfaceName)) == "syncconf" {
		// Keep the interface and its sockets alive while applying peer changes.
		// Tearing it down here resets WireGuard handshake timestamps and causes
		// a periodic sync to look like a connectivity failure.
		stripped, err := exec.CommandContext(ctx, "wg-quick", "strip", wgPath).Output()
		if err != nil {
			return fmt.Errorf("wg-quick strip failed: %w", err)
		}
		sync := exec.CommandContext(ctx, "wg", "syncconf", cfg.InterfaceName, "/dev/stdin")
		sync.Stdin = bytes.NewReader(stripped)
		sync.Stdout = os.Stdout
		sync.Stderr = os.Stderr
		if err := sync.Run(); err != nil {
			return fmt.Errorf("wg syncconf failed: %w", err)
		}
		// wg syncconf intentionally does not manage the routes that wg-quick
		// created when the interface was first brought up. Reconcile the
		// peer routes explicitly or a newly enrolled peer can handshake while
		// packets still follow the host's default route.
		if err := reconcileWireGuardRoutes(ctx, cfg.InterfaceName); err != nil {
			return err
		}
	} else if err := command(ctx, "wg-quick", "up", wgPath); err != nil {
		return err
	}
	return command(ctx, "systemctl", "restart", "xconnect-gateway-xray.service")
}

func reconcileWireGuardRoutes(ctx context.Context, interfaceName string) error {
	raw, err := exec.CommandContext(ctx, "wg", "show", interfaceName, "allowed-ips").Output()
	if err != nil {
		return fmt.Errorf("wg allowed-ips inspection failed: %w", err)
	}
	for _, route := range wireGuardRouteCIDRs(string(raw)) {
		family := "-4"
		if strings.Contains(route, ":") {
			family = "-6"
		}
		if err := command(ctx, "ip", family, "route", "replace", route, "dev", interfaceName); err != nil {
			return fmt.Errorf("reconcile WireGuard route %s failed: %w", route, err)
		}
	}
	return nil
}

func wireGuardRouteCIDRs(raw string) []string {
	seen := make(map[string]struct{})
	var routes []string
	for _, line := range strings.Split(raw, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		for _, candidate := range fields[1:] {
			_, network, err := net.ParseCIDR(candidate)
			if err != nil || network == nil || network.String() == "0.0.0.0/0" || network.String() == "::/0" {
				continue
			}
			route := network.String()
			if _, ok := seen[route]; ok {
				continue
			}
			seen[route] = struct{}{}
			routes = append(routes, route)
		}
	}
	return routes
}

func wireGuardApplyMode(interfacePresent bool) string {
	if interfacePresent {
		return "syncconf"
	}
	return "up"
}

func interfaceExists(ctx context.Context, name string) bool {
	return exec.CommandContext(ctx, "ip", "link", "show", "dev", name).Run() == nil
}
func down(args []string) error {
	f, dir := common("down", args)
	if err := f.Parse(args); err != nil {
		return err
	}
	_, err := gateway.LoadState(*dir)
	if err != nil {
		return err
	}
	_ = exec.Command("systemctl", "stop", "xconnect-gateway-xray.service").Run()
	matches, _ := filepath.Glob(filepath.Join(*dir, "runtime", "*.conf"))
	if len(matches) != 1 {
		return errors.New("owned WireGuard config not found")
	}
	return command(context.Background(), "wg-quick", "down", matches[0])
}
func status(args []string) error {
	f, dir := common("status", args)
	if err := f.Parse(args); err != nil {
		return err
	}
	state, err := gateway.LoadState(*dir)
	if err != nil {
		return err
	}
	fmt.Printf("gateway=%s network=%s applied_generation=%d config=%s\n", state.GatewayID, state.NetworkID, state.AppliedGeneration, state.AppliedConfigID)
	return nil
}
func diagnose() error {
	for _, name := range []string{"wg", "wg-quick", "xray", "systemctl"} {
		path, err := exec.LookPath(name)
		if err != nil {
			return fmt.Errorf("required runtime %s unavailable", name)
		}
		fmt.Printf("%s=%s\n", name, path)
	}
	return nil
}
func command(ctx context.Context, name string, args ...string) error {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%s failed: %w", name, err)
	}
	return nil
}
func wireGuardKeys(ctx context.Context) (string, string, error) {
	privateRaw, err := exec.CommandContext(ctx, "wg", "genkey").Output()
	if err != nil {
		return "", "", err
	}
	privateKey := strings.TrimSpace(string(privateRaw))
	cmd := exec.CommandContext(ctx, "wg", "pubkey")
	cmd.Stdin = strings.NewReader(privateKey + "\n")
	publicRaw, err := cmd.Output()
	return privateKey, strings.TrimSpace(string(publicRaw)), err
}
func nonce() string {
	raw := make([]byte, 16)
	_, _ = rand.Read(raw)
	raw[6] = (raw[6] & 0x0f) | 0x40
	raw[8] = (raw[8] & 0x3f) | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x", raw[0:4], raw[4:6], raw[6:8], raw[8:10], raw[10:16])
}
func parseInvite(raw string) (string, string, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Scheme != "xconnect" || u.Host != "join" {
		return "", "", errors.New("invalid XConnect invite URI")
	}
	token := strings.TrimPrefix(u.Path, "/")
	controller := u.Query().Get("controller")
	decoded, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(token, "xjt_"))
	if err != nil || len(decoded) != 32 {
		return "", "", errors.New("invalid join token")
	}
	client, err := gateway.NewClient(controller)
	if err != nil {
		return "", "", err
	}
	_ = client
	return strings.TrimRight(controller, "/"), token, nil
}
