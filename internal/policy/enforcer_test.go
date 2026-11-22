package policy

import (
	"context"
	"errors"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/ai-workspace-xstream/XConnect-Gateway/internal/gateway"
)

type recordedCall struct {
	name  string
	args  []string
	stdin string
}

type fakeRunner struct {
	files      map[string][]byte
	forwardOut map[string]string
	chainOut   map[string]string
	calls      []recordedCall
	writes     map[string]string
}

func (f *fakeRunner) ReadFile(path string) ([]byte, error) {
	if raw, ok := f.files[path]; ok {
		return raw, nil
	}
	return nil, os.ErrNotExist
}

func (f *fakeRunner) WriteFile(path string, data []byte, _ os.FileMode) error {
	if f.writes == nil {
		f.writes = make(map[string]string)
	}
	if f.files == nil {
		f.files = make(map[string][]byte)
	}
	f.files[path] = data
	f.writes[path] = string(data)
	return nil
}

func (f *fakeRunner) Run(_ context.Context, stdin string, name string, args ...string) ([]byte, error) {
	f.calls = append(f.calls, recordedCall{name: name, args: slices.Clone(args), stdin: stdin})
	if (name == "iptables" || name == "ip6tables") && len(args) == 2 && args[0] == "-S" {
		if args[1] == "FORWARD" {
			if out, ok := f.forwardOut[name]; ok {
				return []byte(out), nil
			}
			return nil, errors.New("chain missing")
		}
		if args[1] == ChainName {
			if out, ok := f.chainOut[name]; ok {
				return []byte(out), nil
			}
			return nil, errors.New("No chain/target/match by that name")
		}
	}
	return nil, nil
}

func TestApplyWithRunnerReconcilesForwardingAndPromotesJumpAheadOfManualRule(t *testing.T) {
	ruleset, err := Compile("xconzero0", []gateway.Peer{
		{DeviceID: "mac", WireGuardAddress: "10.66.0.2/32"},
		{DeviceID: "bot", WireGuardAddress: "10.66.0.4/32"},
	}, &gateway.PolicyArtifact{
		SchemaVersion: 1,
		NetworkID:     "net-1",
		Revision:      10,
		DefaultAction: "deny",
	})
	if err != nil {
		t.Fatal(err)
	}

	runner := &fakeRunner{
		files: map[string][]byte{
			ipv4ForwardProcPath: []byte("0\n"),
		},
		forwardOut: map[string]string{
			"iptables": strings.Join([]string{
				"-P FORWARD ACCEPT",
				"-A FORWARD -i xconzero0 -o xconzero0 -j ACCEPT",
				"-A FORWARD -i xconzero0 -o xconzero0 -j XCONNECT_ZERO_FWD",
			}, "\n"),
		},
	}

	if err := ApplyWithRunner(context.Background(), runner, ruleset); err != nil {
		t.Fatalf("ApplyWithRunner failed: %v", err)
	}
	if runner.writes[ipv4ForwardProcPath] != "1\n" {
		t.Fatalf("expected ip_forward enabled, writes=%#v", runner.writes)
	}
	if len(runner.calls) != 4 {
		t.Fatalf("expected 4 calls (restore, -S, -D, -I), got %d: %#v", len(runner.calls), runner.calls)
	}
	if runner.calls[0].name != "iptables-restore" || !slices.Equal(runner.calls[0].args, []string{"--noflush"}) || runner.calls[0].stdin != ruleset.IPv4RestoreScript {
		t.Fatalf("unexpected restore call: %#v", runner.calls[0])
	}
	if runner.calls[2].name != "iptables" || !slices.Equal(runner.calls[2].args, []string{"-D", "FORWARD", "-i", "xconzero0", "-o", "xconzero0", "-j", ChainName}) {
		t.Fatalf("expected stale jump deletion, got %#v", runner.calls[2])
	}
	if runner.calls[3].name != "iptables" || !slices.Equal(runner.calls[3].args, []string{"-I", "FORWARD", "1", "-i", "xconzero0", "-o", "xconzero0", "-j", ChainName}) {
		t.Fatalf("expected jump inserted at position 1, got %#v", runner.calls[3])
	}

	// Idempotent pass when already positioned at FORWARD #1.
	runner.calls = nil
	runner.writes = nil
	runner.forwardOut["iptables"] = "-P FORWARD ACCEPT\n-A FORWARD -i xconzero0 -o xconzero0 -j XCONNECT_ZERO_FWD\n-A FORWARD -j f2b-sshd\n"
	if err := ApplyWithRunner(context.Background(), runner, ruleset); err != nil {
		t.Fatalf("idempotent ApplyWithRunner failed: %v", err)
	}
	if _, wrote := runner.writes[ipv4ForwardProcPath]; wrote || len(runner.calls) != 2 {
		t.Fatalf("expected only restore + -S check without sysctl write when jump is already #1, got calls=%#v wrote=%v", runner.calls, wrote)
	}
}

func TestTeardownWithRunnerRemovesOnlyOwnedJumpAndChain(t *testing.T) {
	runner := &fakeRunner{
		forwardOut: map[string]string{
			"iptables": strings.Join([]string{
				"-P FORWARD ACCEPT",
				"-A FORWARD -i xconzero0 -o xconzero0 -j XCONNECT_ZERO_FWD",
				"-A FORWARD -j f2b-sshd",
			}, "\n"),
		},
		chainOut: map[string]string{
			"iptables": "-N XCONNECT_ZERO_FWD\n-A XCONNECT_ZERO_FWD -j DROP\n",
		},
	}

	if err := TeardownWithRunner(context.Background(), runner, "xconzero0"); err != nil {
		t.Fatalf("TeardownWithRunner failed: %v", err)
	}

	wantCalls := [][]string{
		{"-S", "FORWARD"},
		{"-D", "FORWARD", "-i", "xconzero0", "-o", "xconzero0", "-j", ChainName},
		{"-S", ChainName},
		{"-F", ChainName},
		{"-X", ChainName},
		{"-S", "FORWARD"}, // optional ip6tables check
	}
	if len(runner.calls) != len(wantCalls) {
		t.Fatalf("got %d calls %#v, want %d", len(runner.calls), runner.calls, len(wantCalls))
	}
	for i, want := range wantCalls {
		if !slices.Equal(runner.calls[i].args, want) {
			t.Fatalf("call[%d] = %s %v, want args %v", i, runner.calls[i].name, runner.calls[i].args, want)
		}
	}
}
