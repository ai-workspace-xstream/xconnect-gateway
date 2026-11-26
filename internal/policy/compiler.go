package policy

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"strings"

	"github.com/ai-workspace-xstream/XConnect-Gateway/internal/gateway"
)

const (
	// ChainName is the isolated filter chain owned exclusively by XConnect-Gateway.
	ChainName = "XCONNECT_ZERO_FWD"
	// MaxMultiportEntries matches Linux xt_multiport's 15-port ceiling per rule.
	MaxMultiportEntries = 15
)

// CompiledRuleset holds deterministic iptables-restore / ip6tables-restore scripts
// compiled from a signed Gateway Config's peers and optional policy artifact.
type CompiledRuleset struct {
	InterfaceName     string
	Revision          uint64
	DefaultAction     string
	RuleCount         int
	IPv4Rules         []string
	IPv6Rules         []string
	IPv4RestoreScript string
	IPv6RestoreScript string
	Digest            string
	Warnings          []string
}

type peerAddresses struct {
	v4 []netip.Prefix
	v6 []netip.Prefix
}

// Compile translates a Gateway PolicyArtifact and the currently signed Peers
// list into deterministic, atomic iptables-restore scripts. Device IDs are
// resolved dynamically from peers' WireGuardAddress values; no overlay IPs are
// hardcoded. If policy is nil, compilation fails closed with default DROP.
func Compile(iface string, peers []gateway.Peer, policy *gateway.PolicyArtifact) (CompiledRuleset, error) {
	iface = strings.TrimSpace(iface)
	if !validInterfaceName(iface) {
		return CompiledRuleset{}, errors.New("invalid WireGuard interface name")
	}

	var warnings []string
	peerMap, hasIPv4Peers, hasIPv6Peers := buildPeerAddressMap(peers, &warnings)

	defaultAction := "deny"
	revision := uint64(0)
	ruleCount := 0
	var rules []gateway.PolicyRule
	if policy != nil {
		if policy.DefaultAction != "deny" && policy.DefaultAction != "allow" {
			return CompiledRuleset{}, errors.New("invalid policy default action")
		}
		defaultAction = policy.DefaultAction
		revision = policy.Revision
		ruleCount = len(policy.Rules)
		rules = policy.Rules
	}

	v4Rules := []string{
		fmt.Sprintf("-A %s -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT", ChainName),
		fmt.Sprintf("-A %s -m conntrack --ctstate INVALID -j DROP", ChainName),
	}
	var v6UserRules []string

	for _, rule := range rules {
		v4Compiled, v6Compiled, err := compileRule(revision, rule, peerMap, hasIPv4Peers, hasIPv6Peers, &warnings)
		if err != nil {
			return CompiledRuleset{}, err
		}
		v4Rules = append(v4Rules, v4Compiled...)
		v6UserRules = append(v6UserRules, v6Compiled...)
	}

	tailTarget := "DROP"
	if defaultAction == "allow" {
		tailTarget = "ACCEPT"
	} else {
		icmpDefaultComment := quoteComment(fmt.Sprintf("xcz:rev=%d:default=icmp-allow", revision))
		v4Rules = append(v4Rules, fmt.Sprintf("-A %s -p icmp -m comment --comment %s -j ACCEPT", ChainName, icmpDefaultComment))
	}
	tailComment := quoteComment(fmt.Sprintf("xcz:rev=%d:default=%s", revision, defaultAction))
	v4Rules = append(v4Rules, fmt.Sprintf("-A %s -m comment --comment %s -j %s", ChainName, tailComment, tailTarget))

	v4Script := formatRestoreScript(v4Rules)

	var v6Rules []string
	var v6Script string
	if hasIPv6Peers || len(v6UserRules) > 0 {
		v6Rules = append(v6Rules,
			fmt.Sprintf("-A %s -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT", ChainName),
			fmt.Sprintf("-A %s -m conntrack --ctstate INVALID -j DROP", ChainName),
		)
		v6Rules = append(v6Rules, v6UserRules...)
		if defaultAction == "deny" {
			icmpDefaultComment := quoteComment(fmt.Sprintf("xcz:rev=%d:default=icmp-allow", revision))
			v6Rules = append(v6Rules, fmt.Sprintf("-A %s -p ipv6-icmp -m comment --comment %s -j ACCEPT", ChainName, icmpDefaultComment))
		}
		v6Rules = append(v6Rules, fmt.Sprintf("-A %s -m comment --comment %s -j %s", ChainName, tailComment, tailTarget))
		v6Script = formatRestoreScript(v6Rules)
	}

	sum := sha256.Sum256([]byte(v4Script + "\x00" + v6Script))
	return CompiledRuleset{
		InterfaceName:     iface,
		Revision:          revision,
		DefaultAction:     defaultAction,
		RuleCount:         ruleCount,
		IPv4Rules:         v4Rules,
		IPv6Rules:         v6Rules,
		IPv4RestoreScript: v4Script,
		IPv6RestoreScript: v6Script,
		Digest:            hex.EncodeToString(sum[:]),
		Warnings:          warnings,
	}, nil
}

// RenderCombinedArtifact produces a human-readable snapshot suitable for
// runtime/policy-compiled.rules inspection and dry-run verification.
func RenderCombinedArtifact(r CompiledRuleset) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# XConnect Zero Gateway Forwarding Policy\n")
	fmt.Fprintf(&b, "# interface=%s revision=%d default=%s rules=%d digest=%s\n", r.InterfaceName, r.Revision, r.DefaultAction, r.RuleCount, r.Digest)
	for _, w := range r.Warnings {
		fmt.Fprintf(&b, "# warning: %s\n", w)
	}
	b.WriteString(r.IPv4RestoreScript)
	if r.IPv6RestoreScript != "" {
		b.WriteString("\n# IPv6\n")
		b.WriteString(r.IPv6RestoreScript)
	}
	return b.String()
}

func compileRule(revision uint64, rule gateway.PolicyRule, peerMap map[string]peerAddresses, hasIPv4Peers, hasIPv6Peers bool, warnings *[]string) ([]string, []string, error) {
	var target string
	switch rule.Action {
	case "allow":
		target = "ACCEPT"
	case "deny":
		target = "DROP"
	default:
		return nil, nil, fmt.Errorf("invalid action %q in rule %q", rule.Action, rule.ID)
	}

	srcWildcard, srcAddrs := resolveDeviceRefs(rule.ID, rule.SourceDevices, peerMap, warnings)
	dstWildcard, dstAddrs := resolveDeviceRefs(rule.ID, rule.DestinationDevices, peerMap, warnings)

	v4Pairs := pairAddressFamilies(srcWildcard, srcAddrs.v4, dstWildcard, dstAddrs.v4, true)
	v6Pairs := pairAddressFamilies(srcWildcard, srcAddrs.v6, dstWildcard, dstAddrs.v6, hasIPv6Peers || len(srcAddrs.v6) > 0 || len(dstAddrs.v6) > 0)

	// Avoid empty IPv4 wildcard rules only when there are neither IPv4 peers nor wildcard matches.
	if !hasIPv4Peers && srcWildcard && dstWildcard && hasIPv6Peers {
		v4Pairs = nil
	}

	v4Matches, v6Matches, err := expandProtocolMatches(rule.ID, rule.Protocols, rule.Ports)
	if err != nil {
		return nil, nil, err
	}

	comment := quoteComment(fmt.Sprintf("xcz:rev=%d:rule=%s", revision, sanitizeRuleID(rule.ID)))

	var v4Out, v6Out []string
	for _, pair := range v4Pairs {
		for _, protoMatch := range v4Matches {
			v4Out = append(v4Out, formatRuleLine(pair.src, pair.dst, protoMatch, comment, target))
		}
	}
	for _, pair := range v6Pairs {
		for _, protoMatch := range v6Matches {
			v6Out = append(v6Out, formatRuleLine(pair.src, pair.dst, protoMatch, comment, target))
		}
	}
	return v4Out, v6Out, nil
}

type addressPair struct {
	src string
	dst string
}

func pairAddressFamilies(srcWildcard bool, src []netip.Prefix, dstWildcard bool, dst []netip.Prefix, emitWildcardBoth bool) []addressPair {
	switch {
	case srcWildcard && dstWildcard:
		if !emitWildcardBoth {
			return nil
		}
		return []addressPair{{}}
	case srcWildcard:
		out := make([]addressPair, 0, len(dst))
		for _, d := range dst {
			out = append(out, addressPair{dst: d.String()})
		}
		return out
	case dstWildcard:
		out := make([]addressPair, 0, len(src))
		for _, s := range src {
			out = append(out, addressPair{src: s.String()})
		}
		return out
	default:
		out := make([]addressPair, 0, len(src)*len(dst))
		for _, s := range src {
			for _, d := range dst {
				out = append(out, addressPair{src: s.String(), dst: d.String()})
			}
		}
		return out
	}
}

func expandProtocolMatches(ruleID string, rawProtos []string, rawPorts []int) ([]string, []string, error) {
	ports, err := normalizePorts(ruleID, rawPorts)
	if err != nil {
		return nil, nil, err
	}
	protos, err := normalizeProtocols(ruleID, rawProtos, len(ports) > 0)
	if err != nil {
		return nil, nil, err
	}

	var v4Matches []string
	var v6Matches []string
	for _, proto := range protos {
		switch proto {
		case "all":
			v4Matches = append(v4Matches, "")
			v6Matches = append(v6Matches, "")
		case "icmp":
			v4Matches = append(v4Matches, "-p icmp")
			v6Matches = append(v6Matches, "-p ipv6-icmp")
		case "tcp", "udp":
			matches := formatPortMatches(proto, ports)
			v4Matches = append(v4Matches, matches...)
			v6Matches = append(v6Matches, matches...)
		}
	}
	return v4Matches, v6Matches, nil
}

func normalizeProtocols(ruleID string, raw []string, hasPorts bool) ([]string, error) {
	if len(raw) == 0 {
		if hasPorts {
			return []string{"tcp", "udp"}, nil
		}
		return []string{"all"}, nil
	}

	seen := make(map[string]struct{}, len(raw))
	var ordered []string
	add := func(p string) {
		if _, ok := seen[p]; !ok {
			seen[p] = struct{}{}
			ordered = append(ordered, p)
		}
	}

	hasAll := false
	hasNonICMP := false
	for _, entry := range raw {
		p := strings.ToLower(strings.TrimSpace(entry))
		switch p {
		case "all":
			hasAll = true
			hasNonICMP = true
		case "tcp", "udp":
			hasNonICMP = true
			add(p)
		case "icmp":
			add(p)
		default:
			return nil, fmt.Errorf("invalid protocol %q in rule %q", entry, ruleID)
		}
	}

	if hasPorts && !hasNonICMP {
		return nil, fmt.Errorf("icmp rule %q cannot specify ports", ruleID)
	}
	if hasAll {
		if hasPorts {
			// iptables requires -p tcp or -p udp before --dport / multiport.
			ordered = ordered[:0]
			seen = map[string]struct{}{}
			add("tcp")
			add("udp")
			return ordered, nil
		}
		return []string{"all"}, nil
	}
	return ordered, nil
}

func normalizePorts(ruleID string, raw []int) ([]int, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	seen := make(map[int]struct{}, len(raw))
	ports := make([]int, 0, len(raw))
	for _, port := range raw {
		if port < 1 || port > 65535 {
			return nil, fmt.Errorf("invalid port %d in rule %q", port, ruleID)
		}
		if _, ok := seen[port]; ok {
			continue
		}
		seen[port] = struct{}{}
		ports = append(ports, port)
	}
	slices.Sort(ports)
	return ports, nil
}

func formatPortMatches(proto string, ports []int) []string {
	if len(ports) == 0 {
		return []string{"-p " + proto}
	}
	if len(ports) == 1 {
		return []string{fmt.Sprintf("-p %s --dport %d", proto, ports[0])}
	}
	var out []string
	for start := 0; start < len(ports); start += MaxMultiportEntries {
		end := min(start+MaxMultiportEntries, len(ports))
		chunk := ports[start:end]
		if len(chunk) == 1 {
			out = append(out, fmt.Sprintf("-p %s --dport %d", proto, chunk[0]))
			continue
		}
		parts := make([]string, 0, len(chunk))
		for _, p := range chunk {
			parts = append(parts, strconv.Itoa(p))
		}
		out = append(out, fmt.Sprintf("-p %s -m multiport --dports %s", proto, strings.Join(parts, ",")))
	}
	return out
}

func formatRuleLine(src, dst, protoMatch, comment, target string) string {
	parts := []string{"-A", ChainName}
	if src != "" {
		parts = append(parts, "-s", src)
	}
	if dst != "" {
		parts = append(parts, "-d", dst)
	}
	if protoMatch != "" {
		parts = append(parts, protoMatch)
	}
	parts = append(parts, "-m", "comment", "--comment", comment, "-j", target)
	return strings.Join(parts, " ")
}

func formatRestoreScript(rules []string) string {
	var b strings.Builder
	b.WriteString("*filter\n")
	fmt.Fprintf(&b, ":%s - [0:0]\n", ChainName)
	fmt.Fprintf(&b, "-F %s\n", ChainName)
	for _, r := range rules {
		b.WriteString(r)
		b.WriteByte('\n')
	}
	b.WriteString("COMMIT\n")
	return b.String()
}

func buildPeerAddressMap(peers []gateway.Peer, warnings *[]string) (map[string]peerAddresses, bool, bool) {
	peerMap := make(map[string]peerAddresses, len(peers))
	var hasV4, hasV6 bool
	for _, peer := range peers {
		id := strings.TrimSpace(peer.DeviceID)
		if id == "" {
			continue
		}
		entry := peerMap[id]
		for _, rawAddr := range strings.Split(peer.WireGuardAddress, ",") {
			addrText := strings.TrimSpace(rawAddr)
			if addrText == "" {
				continue
			}
			prefix, err := netip.ParsePrefix(addrText)
			if err != nil || !prefix.Addr().IsValid() {
				*warnings = append(*warnings, fmt.Sprintf("peer %q has invalid wireguard_address %q; ignored", id, addrText))
				continue
			}
			hostPrefix := netip.PrefixFrom(prefix.Addr(), prefix.Addr().BitLen())
			if hostPrefix.Addr().Is4() {
				hasV4 = true
				entry.v4 = appendUniquePrefix(entry.v4, hostPrefix)
			} else if hostPrefix.Addr().Is6() {
				hasV6 = true
				entry.v6 = appendUniquePrefix(entry.v6, hostPrefix)
			}
		}
		peerMap[id] = entry
	}
	return peerMap, hasV4, hasV6
}

func resolveDeviceRefs(ruleID string, refs []string, peerMap map[string]peerAddresses, warnings *[]string) (bool, peerAddresses) {
	var out peerAddresses
	seenRefs := make(map[string]struct{}, len(refs))
	for _, rawRef := range refs {
		ref := strings.TrimSpace(rawRef)
		if ref == "" {
			continue
		}
		if ref == "*" {
			return true, peerAddresses{}
		}
		if _, seen := seenRefs[ref]; seen {
			continue
		}
		seenRefs[ref] = struct{}{}
		entry, ok := peerMap[ref]
		if !ok || (len(entry.v4) == 0 && len(entry.v6) == 0) {
			*warnings = append(*warnings, fmt.Sprintf("rule %q: device %q is not present in signed peers; skipped", ruleID, ref))
			continue
		}
		for _, p := range entry.v4 {
			out.v4 = appendUniquePrefix(out.v4, p)
		}
		for _, p := range entry.v6 {
			out.v6 = appendUniquePrefix(out.v6, p)
		}
	}
	slices.SortFunc(out.v4, comparePrefix)
	slices.SortFunc(out.v6, comparePrefix)
	return false, out
}

func appendUniquePrefix(slice []netip.Prefix, candidate netip.Prefix) []netip.Prefix {
	if slices.Contains(slice, candidate) {
		return slice
	}
	return append(slice, candidate)
}

func comparePrefix(a, b netip.Prefix) int {
	return strings.Compare(a.String(), b.String())
}

func validInterfaceName(iface string) bool {
	if iface == "" || len(iface) > 15 {
		return false
	}
	for i := 0; i < len(iface); i++ {
		ch := iface[i]
		if !((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') || ch == '_' || ch == '-' || ch == '.') {
			return false
		}
	}
	return true
}

func sanitizeRuleID(id string) string {
	var b strings.Builder
	for i := 0; i < len(id) && b.Len() < 180; i++ {
		ch := id[i]
		if (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') || ch == '.' || ch == '_' || ch == ':' || ch == '-' {
			b.WriteByte(ch)
		} else {
			b.WriteByte('_')
		}
	}
	if b.Len() == 0 {
		return "rule"
	}
	return b.String()
}

func quoteComment(comment string) string {
	if len(comment) > 250 {
		comment = comment[:250]
	}
	return `"` + comment + `"`
}
