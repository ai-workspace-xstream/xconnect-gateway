package policy

import (
	"strings"
	"testing"

	"github.com/ai-workspace-xstream/XConnect-Gateway/internal/gateway"
)

func TestCompileNilPolicyFailsClosedDeny(t *testing.T) {
	peers := []gateway.Peer{
		{DeviceID: "mac", WireGuardAddress: "10.66.0.2/32"},
		{DeviceID: "bot", WireGuardAddress: "10.66.0.4/32"},
	}
	ruleset, err := Compile("xconzero0", peers, nil)
	if err != nil {
		t.Fatalf("Compile(nil policy) error: %v", err)
	}
	if ruleset.DefaultAction != "deny" || ruleset.Revision != 0 || ruleset.RuleCount != 0 {
		t.Fatalf("unexpected ruleset metadata: %+v", ruleset)
	}
	wantSubstrings := []string{
		"*filter",
		":XCONNECT_ZERO_FWD - [0:0]",
		"-F XCONNECT_ZERO_FWD",
		"-A XCONNECT_ZERO_FWD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT",
		"-A XCONNECT_ZERO_FWD -m conntrack --ctstate INVALID -j DROP",
		`-A XCONNECT_ZERO_FWD -m comment --comment "xcz:rev=0:default=deny" -j DROP`,
		"COMMIT",
	}
	for _, want := range wantSubstrings {
		if !strings.Contains(ruleset.IPv4RestoreScript, want) {
			t.Fatalf("missing %q in script:\n%s", want, ruleset.IPv4RestoreScript)
		}
	}
	if ruleset.IPv6RestoreScript != "" {
		t.Fatalf("expected empty IPv6 script for IPv4-only peers, got:\n%s", ruleset.IPv6RestoreScript)
	}
}

func TestCompileDynamicPeerResolutionOrderingAndWarnings(t *testing.T) {
	peers := []gateway.Peer{
		{DeviceID: "macbook", WireGuardAddress: "10.66.0.2/24"},
		{DeviceID: "grok-bot", WireGuardAddress: "10.66.0.4/32"},
	}
	artifact := &gateway.PolicyArtifact{
		SchemaVersion: 1,
		NetworkID:     "net_prod",
		Revision:      17,
		DefaultAction: "deny",
		Rules: []gateway.PolicyRule{
			{
				ID:                 "allow-mac-grok-web",
				Action:             "allow",
				SourceDevices:      []string{"macbook", "offline-laptop"},
				DestinationDevices: []string{"grok-bot"},
				Protocols:          []string{"icmp", "tcp"},
				Ports:              []int{8080, 22, 8080},
			},
			{
				ID:                 "deny-offline-only",
				Action:             "deny",
				SourceDevices:      []string{"missing-node"},
				DestinationDevices: []string{"*"},
				Protocols:          []string{"all"},
			},
		},
	}

	r1, err := Compile("xconzero0", peers, artifact)
	if err != nil {
		t.Fatalf("Compile error: %v", err)
	}
	r2, err := Compile("xconzero0", peers, artifact)
	if err != nil {
		t.Fatalf("Compile repeat error: %v", err)
	}
	if r1.Digest != r2.Digest {
		t.Fatalf("expected deterministic digest, got %s vs %s", r1.Digest, r2.Digest)
	}
	if len(r1.Warnings) != 2 {
		t.Fatalf("expected 2 unresolved-device warnings, got %#v", r1.Warnings)
	}
	// Host prefix must normalize 10.66.0.2/24 -> 10.66.0.2/32, never 10.66.0.0/24 or *.
	wantICMP := `-A XCONNECT_ZERO_FWD -s 10.66.0.2/32 -d 10.66.0.4/32 -p icmp -m comment --comment "xcz:rev=17:rule=allow-mac-grok-web" -j ACCEPT`
	wantTCP := `-A XCONNECT_ZERO_FWD -s 10.66.0.2/32 -d 10.66.0.4/32 -p tcp -m multiport --dports 22,8080 -m comment --comment "xcz:rev=17:rule=allow-mac-grok-web" -j ACCEPT`
	if !strings.Contains(r1.IPv4RestoreScript, wantICMP) {
		t.Fatalf("missing ICMP rule %q in:\n%s", wantICMP, r1.IPv4RestoreScript)
	}
	if !strings.Contains(r1.IPv4RestoreScript, wantTCP) {
		t.Fatalf("missing TCP multiport rule %q in:\n%s", wantTCP, r1.IPv4RestoreScript)
	}
	// Unresolved device must never widen to a wildcard rule.
	if strings.Contains(r1.IPv4RestoreScript, "rule=deny-offline-only") {
		t.Fatalf("unresolved device rule should emit nothing rather than wildcard:\n%s", r1.IPv4RestoreScript)
	}
}

func TestCompileMultiportChunkingAllWithPortsAndAllowDefault(t *testing.T) {
	peers := []gateway.Peer{
		{DeviceID: "a", WireGuardAddress: "10.66.0.2/32"},
		{DeviceID: "b", WireGuardAddress: "10.66.0.3/32"},
	}
	ports := make([]int, 0, 17)
	for p := 8000; p < 8017; p++ {
		ports = append(ports, p)
	}
	artifact := &gateway.PolicyArtifact{
		SchemaVersion: 1,
		NetworkID:     "net_1",
		Revision:      3,
		DefaultAction: "allow",
		Rules: []gateway.PolicyRule{{
			ID:                 "allow-many-ports",
			Action:             "allow",
			SourceDevices:      []string{"*"},
			DestinationDevices: []string{"b"},
			Protocols:          []string{"all"},
			Ports:              ports,
		}},
	}
	ruleset, err := Compile("xconzero0", peers, artifact)
	if err != nil {
		t.Fatalf("Compile error: %v", err)
	}
	if !strings.Contains(ruleset.IPv4RestoreScript, "-d 10.66.0.3/32 -p tcp -m multiport --dports 8000,8001,8002,8003,8004,8005,8006,8007,8008,8009,8010,8011,8012,8013,8014") {
		t.Fatalf("missing first 15-port tcp chunk:\n%s", ruleset.IPv4RestoreScript)
	}
	if !strings.Contains(ruleset.IPv4RestoreScript, "-d 10.66.0.3/32 -p tcp -m multiport --dports 8015,8016") {
		t.Fatalf("missing remainder 2-port tcp chunk:\n%s", ruleset.IPv4RestoreScript)
	}
	if !strings.Contains(ruleset.IPv4RestoreScript, "-d 10.66.0.3/32 -p udp -m multiport --dports 8015,8016") {
		t.Fatalf("missing udp expansion for protocol=all with ports:\n%s", ruleset.IPv4RestoreScript)
	}
	if !strings.Contains(ruleset.IPv4RestoreScript, `-m comment --comment "xcz:rev=3:default=allow" -j ACCEPT`) {
		t.Fatalf("expected default ACCEPT tail rule:\n%s", ruleset.IPv4RestoreScript)
	}
}

func TestCompileDualStackSeparatesIPv4AndIPv6(t *testing.T) {
	peers := []gateway.Peer{
		{DeviceID: "node1", WireGuardAddress: "10.66.0.2/32, fd66::2/128"},
		{DeviceID: "node2", WireGuardAddress: "10.66.0.4/32, fd66::4/128"},
	}
	artifact := &gateway.PolicyArtifact{
		SchemaVersion: 1,
		NetworkID:     "net_dual",
		Revision:      9,
		DefaultAction: "deny",
		Rules: []gateway.PolicyRule{{
			ID:                 "allow-dual",
			Action:             "allow",
			SourceDevices:      []string{"node1"},
			DestinationDevices: []string{"node2"},
			Protocols:          []string{"icmp", "tcp"},
			Ports:              []int{443},
		}},
	}
	ruleset, err := Compile("xconzero0", peers, artifact)
	if err != nil {
		t.Fatalf("Compile dual-stack error: %v", err)
	}
	if !strings.Contains(ruleset.IPv4RestoreScript, "-s 10.66.0.2/32 -d 10.66.0.4/32 -p icmp") {
		t.Fatalf("missing IPv4 ICMP rule:\n%s", ruleset.IPv4RestoreScript)
	}
	if strings.Contains(ruleset.IPv4RestoreScript, "fd66::") {
		t.Fatalf("IPv4 script must not contain IPv6 addresses:\n%s", ruleset.IPv4RestoreScript)
	}
	if !strings.Contains(ruleset.IPv6RestoreScript, "-s fd66::2/128 -d fd66::4/128 -p ipv6-icmp") || !strings.Contains(ruleset.IPv6RestoreScript, "-s fd66::2/128 -d fd66::4/128 -p tcp --dport 443") {
		t.Fatalf("missing IPv6 rules:\n%s", ruleset.IPv6RestoreScript)
	}
	if strings.Contains(ruleset.IPv6RestoreScript, "10.66.0.") {
		t.Fatalf("IPv6 script must not contain IPv4 addresses:\n%s", ruleset.IPv6RestoreScript)
	}
}
