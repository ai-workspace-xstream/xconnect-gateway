package main

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/ai-workspace-xstream/XConnect-Gateway/internal/gateway"
	"github.com/ai-workspace-xstream/XConnect-Gateway/internal/relay"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"
)

func serveRelay(parent context.Context, args []string) error {
	f, dir := common("relay", args)
	if e := f.Parse(args); e != nil {
		return e
	}
	ctx, cancel := signal.NotifyContext(parent, os.Interrupt, syscall.SIGTERM)
	defer cancel()
	load := func() (gateway.Config, relay.Config, error) {
		state, e := gateway.LoadState(*dir)
		if e != nil {
			return gateway.Config{}, relay.Config{}, e
		}
		raw, e := os.ReadFile(filepath.Join(*dir, "runtime", "signed-config.json"))
		if e != nil {
			return gateway.Config{}, relay.Config{}, e
		}
		var cfg gateway.Config
		if e = json.Unmarshal(raw, &cfg); e != nil {
			return cfg, relay.Config{}, e
		}
		if cfg.NetworkID != state.NetworkID || cfg.GatewayID != state.GatewayID {
			return cfg, relay.Config{}, errors.New("relay binding mismatch")
		}
		if e = cfg.Verify(state.SigningKeys, time.Now()); e != nil {
			return cfg, relay.Config{}, e
		}
		if cfg.Mesh == nil {
			return cfg, relay.Config{}, errors.New("relay is disabled by signed config")
		}
		return cfg, relay.Config{NetworkID: cfg.NetworkID, PrivateKey: state.PrivateKey, ExpiresAt: cfg.ExpiresAt, Peers: cfg.Mesh.Peers}, nil
	}
	cfg, rc, e := load()
	if e != nil {
		return e
	}
	server, e := relay.New(rc)
	if e != nil {
		return e
	}
	listener, e := net.Listen("tcp4", "127.0.0.1:51821")
	if e != nil {
		return e
	}
	go func() {
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				next, config, e := load()
				if e != nil {
					if !cfg.ExpiresAt.After(time.Now()) {
						cancel()
					}
					continue
				}
				if next.Generation < cfg.Generation {
					cancel()
					return
				}
				if e = server.Update(config); e != nil {
					cancel()
					return
				}
				cfg = next
				report := struct {
					NetworkID    string    `json:"network_id"`
					DeviceID     string    `json:"device_id"`
					Role         string    `json:"role"`
					Capabilities []string  `json:"capabilities"`
					Healthy      bool      `json:"healthy"`
					UpdatedAt    time.Time `json:"updated_at"`
					ExpiresAt    time.Time `json:"expires_at"`
				}{cfg.NetworkID, cfg.GatewayID, "gateway", []string{"gateway-relay-v1"}, true, time.Now().UTC(), cfg.ExpiresAt}
				if raw, e := json.Marshal(report); e == nil {
					path := filepath.Join(*dir, "runtime", "overlay-status.json")
					if os.WriteFile(path+".tmp", raw, 0600) == nil {
						_ = os.Rename(path+".tmp", path)
					}
				}
			}
		}
	}()
	return server.Serve(ctx, listener)
}
