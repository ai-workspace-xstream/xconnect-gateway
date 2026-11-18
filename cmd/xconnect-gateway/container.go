package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/ai-workspace-xstream/XConnect-Gateway/internal/gateway"
)

type runtimeKey struct{}

type serviceRuntimeState struct {
	xray, relay childProcess
}

func serviceRuntime(ctx context.Context) *serviceRuntimeState {
	runtime, _ := ctx.Value(runtimeKey{}).(*serviceRuntimeState)
	return runtime
}

func (r *serviceRuntimeState) reconcileRelay(ctx context.Context, dir string, enabled bool) error {
	if r == nil {
		if enabled {
			return command(ctx, "systemctl", "start", "xconnect-gateway-relay.service")
		}
		_ = command(ctx, "systemctl", "stop", "xconnect-gateway-relay.service")
		return nil
	}
	if !enabled {
		r.relay.stop()
		return nil
	}
	if r.relay.active() {
		return nil
	}
	binary, err := os.Executable()
	if err != nil {
		return err
	}
	return r.relay.start(ctx, binary, "relay", "--state-dir", dir)
}

func (r *serviceRuntimeState) xrayActive(ctx context.Context) bool {
	if r == nil {
		return exec.CommandContext(ctx, "systemctl", "is-active", "--quiet", "xconnect-gateway-xray.service").Run() == nil
	}
	return r.xray.active()
}

func (r *serviceRuntimeState) restartXray(ctx context.Context, path string) error {
	if r == nil {
		return command(ctx, "systemctl", "restart", "xconnect-gateway-xray.service")
	}
	r.xray.stop()
	return r.xray.start(ctx, "xray", "run", "-config", path)
}

type childProcess struct {
	cmd  *exec.Cmd
	done chan struct{}
}

func (p *childProcess) active() bool {
	if p.cmd == nil {
		return false
	}
	select {
	case <-p.done:
		return false
	default:
		return true
	}
}

func (p *childProcess) start(ctx context.Context, binary string, args ...string) error {
	p.stop()
	cmd := exec.CommandContext(ctx, binary, args...)
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	if err := cmd.Start(); err != nil {
		return err
	}
	done := make(chan struct{})
	p.cmd, p.done = cmd, done
	go func() {
		_ = cmd.Wait()
		close(done)
	}()
	select {
	case <-done:
		return fmt.Errorf("%s exited during startup", binary)
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(250 * time.Millisecond):
		return nil
	}
}

func (p *childProcess) stop() {
	if p.cmd == nil {
		return
	}
	_ = p.cmd.Process.Kill()
	<-p.done
	p.cmd, p.done = nil, nil
}

func serveContainer(parent context.Context, args []string) error {
	ctx, cancel := signal.NotifyContext(parent, os.Interrupt, syscall.SIGTERM)
	defer cancel()
	runtime := &serviceRuntimeState{}
	defer runtime.xray.stop()
	defer runtime.relay.stop()
	ctx = context.WithValue(ctx, runtimeKey{}, runtime)

	_ = applyCmd(ctx, args)

	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-runtime.xray.done:
			return errors.New("Xray exited")
		case <-runtime.relay.done:
			return errors.New("Gateway relay exited")
		case <-ticker.C:
			f, dir := common("serve", args)
			_ = f.Parse(args)
			cfgRaw, err := os.ReadFile(filepath.Join(*dir, "runtime", "signed-config.json"))
			if err == nil {
				var cfg gateway.Config
				if err := json.Unmarshal(cfgRaw, &cfg); err == nil {
					wgRunning := interfaceExists(ctx, cfg.InterfaceName)
					xrayRunning := runtime.xrayActive(ctx)
					relayRunning := cfg.Mesh != nil
					_ = gateway.CollectAndWriteTelemetry(ctx, *dir, cfg, wgRunning, xrayRunning, relayRunning)
				}
			}
		}
	}
}
