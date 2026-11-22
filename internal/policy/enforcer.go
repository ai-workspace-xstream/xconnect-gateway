package policy

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
)

const (
	ipv4ForwardProcPath = "/proc/sys/net/ipv4/ip_forward"
	ipv6ForwardProcPath = "/proc/sys/net/ipv6/conf/all/forwarding"
)

// Runner abstracts OS sysctl reads/writes and firewall CLI invocations so
// reconciliation logic can be verified deterministically on any OS.
type Runner interface {
	ReadFile(path string) ([]byte, error)
	WriteFile(path string, data []byte, perm os.FileMode) error
	Run(ctx context.Context, stdin string, name string, args ...string) ([]byte, error)
}

// ApplyWithRunner enables kernel IP forwarding as required and atomically
// reconciles XCONNECT_ZERO_FWD plus its head-of-FORWARD jump rule without
// disturbing unrelated host firewall chains.
func ApplyWithRunner(ctx context.Context, runner Runner, ruleset CompiledRuleset) error {
	if !validInterfaceName(ruleset.InterfaceName) {
		return errors.New("invalid WireGuard interface name")
	}
	if strings.TrimSpace(ruleset.IPv4RestoreScript) == "" {
		return errors.New("compiled IPv4 ruleset is empty")
	}
	if err := ensureSysctlOne(runner, ipv4ForwardProcPath, true); err != nil {
		return fmt.Errorf("enable IPv4 forwarding: %w", err)
	}
	if err := reconcileFamily(ctx, runner, "iptables", "iptables-restore", ruleset.InterfaceName, ruleset.IPv4RestoreScript); err != nil {
		return err
	}
	if strings.TrimSpace(ruleset.IPv6RestoreScript) != "" {
		if err := ensureSysctlOne(runner, ipv6ForwardProcPath, false); err != nil {
			return fmt.Errorf("enable IPv6 forwarding: %w", err)
		}
		if err := reconcileFamily(ctx, runner, "ip6tables", "ip6tables-restore", ruleset.InterfaceName, ruleset.IPv6RestoreScript); err != nil {
			return err
		}
	}
	return nil
}

// TeardownWithRunner removes XConnect-Gateway's FORWARD jump rules and deletes
// XCONNECT_ZERO_FWD cleanly without touching unrelated host rules.
func TeardownWithRunner(ctx context.Context, runner Runner, iface string) error {
	iface = strings.TrimSpace(iface)
	if !validInterfaceName(iface) {
		return errors.New("invalid WireGuard interface name")
	}
	var errs []error
	if err := teardownFamily(ctx, runner, "iptables", iface, false); err != nil {
		errs = append(errs, err)
	}
	_ = teardownFamily(ctx, runner, "ip6tables", iface, true)
	return errors.Join(errs...)
}

func ensureSysctlOne(runner Runner, path string, required bool) error {
	raw, err := runner.ReadFile(path)
	if err == nil && strings.TrimSpace(string(raw)) == "1" {
		return nil
	}
	if err != nil && !required && errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if writeErr := runner.WriteFile(path, []byte("1\n"), 0o644); writeErr != nil {
		if !required && errors.Is(writeErr, os.ErrNotExist) {
			return nil
		}
		return writeErr
	}
	return nil
}

func reconcileFamily(ctx context.Context, runner Runner, iptBin, restoreBin, iface, restoreScript string) error {
	if _, err := runner.Run(ctx, restoreScript, restoreBin, "--noflush"); err != nil {
		return fmt.Errorf("%s --noflush failed: %w", restoreBin, err)
	}
	out, err := runner.Run(ctx, "", iptBin, "-S", "FORWARD")
	if err != nil {
		return fmt.Errorf("%s -S FORWARD failed: %w", iptBin, err)
	}
	firstIsOurs, matchCount := inspectForwardChain(string(out), iface)
	if firstIsOurs && matchCount == 1 {
		return nil
	}
	for i := 0; i < matchCount; i++ {
		if _, err := runner.Run(ctx, "", iptBin, "-D", "FORWARD", "-i", iface, "-o", iface, "-j", ChainName); err != nil {
			return fmt.Errorf("%s remove stale jump rule failed: %w", iptBin, err)
		}
	}
	if _, err := runner.Run(ctx, "", iptBin, "-I", "FORWARD", "1", "-i", iface, "-o", iface, "-j", ChainName); err != nil {
		return fmt.Errorf("%s insert jump rule failed: %w", iptBin, err)
	}
	return nil
}

func teardownFamily(ctx context.Context, runner Runner, iptBin, iface string, optional bool) error {
	out, err := runner.Run(ctx, "", iptBin, "-S", "FORWARD")
	if err != nil {
		if optional {
			return nil
		}
		return fmt.Errorf("%s -S FORWARD failed: %w", iptBin, err)
	}
	_, matchCount := inspectForwardChain(string(out), iface)
	for i := 0; i < matchCount; i++ {
		if _, err := runner.Run(ctx, "", iptBin, "-D", "FORWARD", "-i", iface, "-o", iface, "-j", ChainName); err != nil {
			return fmt.Errorf("%s remove jump rule failed: %w", iptBin, err)
		}
	}
	if _, err := runner.Run(ctx, "", iptBin, "-S", ChainName); err != nil {
		// Chain already absent; nothing left to flush or delete.
		return nil
	}
	if _, err := runner.Run(ctx, "", iptBin, "-F", ChainName); err != nil {
		return fmt.Errorf("%s flush chain failed: %w", iptBin, err)
	}
	if _, err := runner.Run(ctx, "", iptBin, "-X", ChainName); err != nil {
		return fmt.Errorf("%s delete chain failed: %w", iptBin, err)
	}
	return nil
}

func inspectForwardChain(output, iface string) (firstRuleIsOurs bool, matchCount int) {
	appendIndex := 0
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 || fields[0] != "-A" || fields[1] != "FORWARD" {
			continue
		}
		if hasForwardJumpTokens(fields[2:], iface) {
			if appendIndex == 0 {
				firstRuleIsOurs = true
			}
			matchCount++
		}
		appendIndex++
	}
	return firstRuleIsOurs, matchCount
}

func hasForwardJumpTokens(tokens []string, iface string) bool {
	var hasIn, hasOut, hasJump bool
	for i := 0; i+1 < len(tokens); i++ {
		switch tokens[i] {
		case "-i":
			if tokens[i+1] == iface {
				hasIn = true
			}
			i++
		case "-o":
			if tokens[i+1] == iface {
				hasOut = true
			}
			i++
		case "-j":
			if tokens[i+1] == ChainName {
				hasJump = true
			}
			i++
		}
	}
	return hasIn && hasOut && hasJump
}
