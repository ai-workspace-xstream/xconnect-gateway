//go:build linux

package policy

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

type execRunner struct{}

func (execRunner) ReadFile(path string) ([]byte, error) {
	return os.ReadFile(path)
}

func (execRunner) WriteFile(path string, data []byte, perm os.FileMode) error {
	return os.WriteFile(path, data, perm)
}

func (execRunner) Run(ctx context.Context, stdin string, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			msg = strings.TrimSpace(stdout.String())
		}
		if msg != "" {
			return stdout.Bytes(), fmt.Errorf("%w: %s", err, msg)
		}
		return stdout.Bytes(), err
	}
	return stdout.Bytes(), nil
}

// Apply enables forwarding and atomically reconciles XCONNECT_ZERO_FWD on Linux.
func Apply(ctx context.Context, ruleset CompiledRuleset) error {
	return ApplyWithRunner(ctx, execRunner{}, ruleset)
}

// Teardown removes XCONNECT_ZERO_FWD jump rules and deletes the chain on Linux.
func Teardown(ctx context.Context, iface string) error {
	return TeardownWithRunner(ctx, execRunner{}, iface)
}
