// Package tunnel compiles and renders the return path: where a scrubbing node
// sends traffic once it is clean.
//
// This is the half of a scrubbing service BGP cannot do. Announcing a
// customer's prefix pulls their traffic to the fabric, and it then cannot be
// routed back the ordinary way — as far as the internet is concerned the
// scrubbers *are* that prefix now, so a normal route toward it comes straight
// back. The clean traffic is encapsulated to the customer's own edge instead.
//
// Like the bgp package, nothing here touches an interface. It renders the
// configuration and the node agent serves it to whatever provisions tunnels
// on that box, so the fabric's intent can be read, diffed and tested rather
// than inferred from the state of a machine.
package tunnel

import (
	"fmt"
	"net/netip"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/Jacksondude1223-bit/scrubline-cloud-scrub/internal/model"
)

const (
	// pathMTU is the path the default tunnel MTU is derived from. Ethernet,
	// because that is what the overhead has to fit inside.
	pathMTU = 1500

	// ipv4Header is the outer header every encapsulation here adds.
	ipv4Header = 20
	// greHeader is GRE's own base header, plus four more when a key is set.
	greHeader = 4
	greKeyLen = 4
	// tcpIPHeaders is the inner IPv4 and TCP headers the MSS sits under.
	tcpIPHeaders = 40

	// minMTU is the floor the protocol itself requires of an IPv4 link.
	// Below it, the tunnel cannot carry a legal packet.
	minMTU = 576

	// ifPrefix namespaces the links this fabric creates, so a tunnel it
	// compiled is distinguishable from one that was already on the box.
	ifPrefix = "scr-"
	// ifNameMax is the kernel's limit on an interface name: IFNAMSIZ is 16
	// including the terminator. A name over it is silently truncated, and
	// two tunnels truncating to the same name is one tunnel.
	ifNameMax = 15
	// idMax is what that leaves for a tunnel ID.
	idMax = ifNameMax - len(ifPrefix)
)

// idPattern is what a tunnel ID may contain. It becomes an interface name, so
// it is held to what a link name can be rather than to what JSON can hold.
var idPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]*$`)

// Overhead is what one encapsulation costs per packet.
func Overhead(t model.Tunnel) int {
	switch t.Type {
	case model.TunnelIPIP:
		return ipv4Header
	default:
		overhead := ipv4Header + greHeader
		if t.Key != 0 {
			overhead += greKeyLen
		}
		return overhead
	}
}

// DefaultMTU is the largest packet that still fits inside the encapsulation
// on an ordinary Ethernet path.
func DefaultMTU(t model.Tunnel) int {
	return pathMTU - Overhead(t)
}

// MSSFor is the TCP maximum segment size that fits in an MTU.
//
// Clamping matters more than it looks. A tunnel with a correct MTU still
// hangs for any customer whose path drops the ICMP that path-MTU discovery
// depends on: the handshake completes, the first full-size segment does not,
// and the connection sits there. Clamping the advertised MSS on the way in
// means the far end never sends a segment that cannot fit.
func MSSFor(mtu int) int {
	mss := mtu - tcpIPHeaders
	if mss < 0 {
		return 0
	}
	return mss
}

// InterfaceName is the link name a tunnel compiles to.
func InterfaceName(id string) (string, error) {
	if err := ValidateID(id); err != nil {
		return "", err
	}
	return ifPrefix + id, nil
}

// ValidateID checks a tunnel ID against what an interface name may be.
func ValidateID(id string) error {
	if id == "" {
		return fmt.Errorf("tunnel id must not be empty")
	}
	if len(id) > idMax {
		return fmt.Errorf("tunnel id %q is %d characters; the kernel's interface-name limit leaves room for %d", id, len(id), idMax)
	}
	if !idPattern.MatchString(id) {
		return fmt.Errorf("tunnel id %q must be lowercase letters, digits and dashes, starting with a letter or digit", id)
	}
	return nil
}

// Validate checks one tunnel as written in a policy. protected is the set of
// prefixes the policy covers; a tunnel for anything else is a typo that would
// otherwise sit in the policy delivering nothing.
func Validate(t model.Tunnel, protected map[string]bool) error {
	if err := ValidateID(t.ID); err != nil {
		return err
	}
	switch t.Type {
	case "", model.TunnelGRE:
	case model.TunnelIPIP:
		if t.Key != 0 {
			return fmt.Errorf("tunnel %s: ipip carries no key; use gre to demultiplex several tunnels between the same addresses", t.ID)
		}
	default:
		return fmt.Errorf("tunnel %s: unknown type %q, expected %q or %q", t.ID, t.Type, model.TunnelGRE, model.TunnelIPIP)
	}

	remote, err := netip.ParseAddr(t.Remote)
	if err != nil {
		return fmt.Errorf("tunnel %s: remote %q is not an IP address: %v", t.ID, t.Remote, err)
	}
	if !remote.Is4() {
		// The overheads and the MSS arithmetic here are IPv4's. Accepting a
		// v6 endpoint would compile a tunnel whose MTU is wrong by twenty
		// bytes, which is the subtlest possible way to break a customer.
		return fmt.Errorf("tunnel %s: remote %q is not IPv4; only IPv4 endpoints are supported", t.ID, t.Remote)
	}
	if !remote.IsValid() || remote.IsUnspecified() || remote.IsMulticast() || remote.IsLoopback() {
		return fmt.Errorf("tunnel %s: remote %q is not a usable endpoint", t.ID, t.Remote)
	}

	if len(t.Prefixes) == 0 {
		return fmt.Errorf("tunnel %s: needs at least one prefix, or it delivers nothing", t.ID)
	}
	seen := map[string]bool{}
	for i, prefix := range t.Prefixes {
		if _, err := netip.ParsePrefix(prefix); err != nil {
			return fmt.Errorf("tunnel %s: prefixes[%d] %q: %v", t.ID, i, prefix, err)
		}
		if seen[prefix] {
			return fmt.Errorf("tunnel %s: prefixes[%d]: duplicate prefix %q", t.ID, i, prefix)
		}
		seen[prefix] = true
		if protected != nil && !protected[prefix] {
			return fmt.Errorf("tunnel %s: prefixes[%d]: %q is not in this policy's protected list", t.ID, i, prefix)
		}
	}

	overhead := Overhead(t)
	if t.MTU != 0 {
		if t.MTU < minMTU {
			return fmt.Errorf("tunnel %s: mtu %d is below the %d-byte IPv4 minimum", t.ID, t.MTU, minMTU)
		}
		if t.MTU > pathMTU-overhead {
			return fmt.Errorf("tunnel %s: mtu %d does not fit a %d-byte path with %d bytes of %s overhead; %d is the largest that does",
				t.ID, t.MTU, pathMTU, overhead, encapName(t), pathMTU-overhead)
		}
	}
	if t.MSSClamp != 0 {
		mtu := t.MTU
		if mtu == 0 {
			mtu = DefaultMTU(t)
		}
		if t.MSSClamp > MSSFor(mtu) {
			return fmt.Errorf("tunnel %s: mss_clamp %d is larger than the %d that fits an MTU of %d; it would clamp to a size that still cannot pass",
				t.ID, t.MSSClamp, MSSFor(mtu), mtu)
		}
		if t.MSSClamp < 536 {
			return fmt.Errorf("tunnel %s: mss_clamp %d is below the 536-byte floor every IPv4 host must accept", t.ID, t.MSSClamp)
		}
	}
	return nil
}

func encapName(t model.Tunnel) string {
	if t.Type == model.TunnelIPIP {
		return "ipip"
	}
	return "gre"
}

// ForNode resolves a policy tunnel into the instance one node builds: the
// local end filled in, the derived MTU and clamp resolved, and the interface
// named. The fabric is anycast, so every node carrying these prefixes builds
// its own tunnel to the same customer endpoint.
func ForNode(t model.Tunnel, node model.Node, prefixes []string) (model.NodeTunnel, error) {
	if node.TunnelSrc == "" {
		return model.NodeTunnel{}, fmt.Errorf("node %s has no tunnel_src, so it cannot build a return path", node.ID)
	}
	local, err := netip.ParseAddr(node.TunnelSrc)
	if err != nil || !local.Is4() {
		return model.NodeTunnel{}, fmt.Errorf("node %s: tunnel_src %q is not an IPv4 address", node.ID, node.TunnelSrc)
	}
	name, err := InterfaceName(t.ID)
	if err != nil {
		return model.NodeTunnel{}, err
	}
	mtu := t.MTU
	if mtu == 0 {
		mtu = DefaultMTU(t)
	}
	clamp := t.MSSClamp
	if clamp == 0 {
		clamp = MSSFor(mtu)
	}
	kind := t.Type
	if kind == "" {
		kind = model.TunnelGRE
	}
	out := model.NodeTunnel{
		ID: t.ID, Type: kind,
		Local: local.String(), Remote: t.Remote,
		Prefixes: append([]string(nil), prefixes...),
		MTU:      mtu, MSSClamp: clamp, Key: t.Key,
		Required: t.Required, Interface: name, Comment: t.Comment,
	}
	sort.Strings(out.Prefixes)
	return out, nil
}

// Commands renders a node's tunnels as iproute2 and nftables configuration,
// sorted so an unchanged set renders byte for byte the same and the agent can
// tell when nothing moved.
//
// Nothing here is executed. It is what the box should look like, for whatever
// is responsible for making it look that way.
func Commands(tunnels []model.NodeTunnel) ([]string, error) {
	rows := make([]model.NodeTunnel, len(tunnels))
	copy(rows, tunnels)
	sort.SliceStable(rows, func(i, j int) bool { return rows[i].ID < rows[j].ID })

	out := []string{}
	for _, t := range rows {
		lines, err := commandsFor(t)
		if err != nil {
			return nil, err
		}
		out = append(out, lines...)
	}
	return out, nil
}

func commandsFor(t model.NodeTunnel) ([]string, error) {
	// Everything below lands in a command line on a scrubbing node. The
	// values come from a policy over an API, so each one is parsed rather
	// than quoted: the bgp package learned the same lesson about communities
	// going into a routing daemon's pipe.
	if err := ValidateID(t.ID); err != nil {
		return nil, err
	}
	name, err := InterfaceName(t.ID)
	if err != nil {
		return nil, err
	}
	if t.Interface != "" && t.Interface != name {
		return nil, fmt.Errorf("tunnel %s: interface %q does not match the name its id compiles to (%q)", t.ID, t.Interface, name)
	}
	local, err := netip.ParseAddr(t.Local)
	if err != nil || !local.Is4() {
		return nil, fmt.Errorf("tunnel %s: local %q is not an IPv4 address", t.ID, t.Local)
	}
	remote, err := netip.ParseAddr(t.Remote)
	if err != nil || !remote.Is4() {
		return nil, fmt.Errorf("tunnel %s: remote %q is not an IPv4 address", t.ID, t.Remote)
	}
	if local == remote {
		return nil, fmt.Errorf("tunnel %s: local and remote are both %s", t.ID, local)
	}
	var kind string
	switch t.Type {
	case model.TunnelGRE:
		kind = "gre"
	case model.TunnelIPIP:
		kind = "ipip"
		if t.Key != 0 {
			return nil, fmt.Errorf("tunnel %s: ipip carries no key", t.ID)
		}
	default:
		return nil, fmt.Errorf("tunnel %s: unknown type %q", t.ID, t.Type)
	}
	if t.MTU < minMTU {
		return nil, fmt.Errorf("tunnel %s: mtu %d is below the %d-byte IPv4 minimum", t.ID, t.MTU, minMTU)
	}

	lines := []string{}
	if c := comment(t.Comment); c != "" {
		lines = append(lines, "# "+c)
	}

	add := &strings.Builder{}
	fmt.Fprintf(add, "ip link add %s type %s local %s remote %s", name, kind, local, remote)
	if t.Key != 0 {
		fmt.Fprintf(add, " key %d", t.Key)
	}
	lines = append(lines, add.String())
	lines = append(lines, fmt.Sprintf("ip link set %s mtu %d up", name, t.MTU))

	prefixes := append([]string(nil), t.Prefixes...)
	sort.Strings(prefixes)
	for _, prefix := range prefixes {
		p, err := netip.ParsePrefix(prefix)
		if err != nil {
			return nil, fmt.Errorf("tunnel %s: prefix %q: %v", t.ID, prefix, err)
		}
		// Masked, so a prefix written with host bits set routes as what it
		// reads rather than as what the kernel makes of it.
		lines = append(lines, fmt.Sprintf("ip route replace %s dev %s", p.Masked(), name))
	}

	if t.MSSClamp > 0 {
		lines = append(lines, fmt.Sprintf(
			"nft add rule inet scrubline forward oifname %q tcp flags syn tcp option maxseg size set %d",
			name, t.MSSClamp))
	}
	return lines, nil
}

// comment reduces operator free text to something that cannot escape a
// generated config line. Anything outside printable ASCII goes, and the rest
// is capped: a comment is a convenience, not a channel.
func comment(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r < 0x20 || r > 0x7e {
			continue
		}
		b.WriteRune(r)
		if b.Len() >= 120 {
			break
		}
	}
	return strings.TrimSpace(b.String())
}

// StateOf reads a node's reported tunnel states into a lookup, defaulting
// anything unreported to unknown.
func StateOf(reports []model.TunnelStatus) map[string]string {
	out := make(map[string]string, len(reports))
	for _, r := range reports {
		switch r.State {
		case model.TunnelUp, model.TunnelDown:
			out[r.TunnelID] = r.State
		default:
			out[r.TunnelID] = model.TunnelUnknown
		}
	}
	return out
}

// Deliverable reports whether a node can be trusted to deliver this tunnel's
// traffic, and why not when it cannot.
//
// A node announcing a prefix whose return path is down is worse than a node
// that never announced it: it attracts the customer's traffic and drops it on
// the floor. So a tunnel reported down takes its prefixes off that node.
//
// An unreported tunnel is not treated as down. Absence of a report usually
// means nothing is reporting, and inferring failure from silence would blank
// the fabric of any operator who has not wired a provisioner up yet. Setting
// Required on the tunnel is how that judgement is reversed.
func Deliverable(t model.NodeTunnel, state string) (bool, string) {
	switch state {
	case model.TunnelDown:
		return false, fmt.Sprintf("return tunnel %s is down", t.ID)
	case model.TunnelUp:
		return true, ""
	default:
		if t.Required {
			return false, fmt.Sprintf("return tunnel %s is required and has not reported up", t.ID)
		}
		return true, ""
	}
}

// ValidateStatus checks a state string reported by a node.
func ValidateStatus(state string) error {
	switch state {
	case model.TunnelUp, model.TunnelDown, model.TunnelUnknown:
		return nil
	}
	return fmt.Errorf("unknown tunnel state %q, expected %s, %s or %s",
		state, model.TunnelUp, model.TunnelDown, model.TunnelUnknown)
}

// ParseKey reads a GRE key written as text, for the places a key arrives as a
// string rather than a number.
func ParseKey(s string) (uint32, error) {
	if s == "" {
		return 0, nil
	}
	v, err := strconv.ParseUint(s, 10, 32)
	if err != nil {
		return 0, fmt.Errorf("gre key %q is not a 32-bit number", s)
	}
	return uint32(v), nil
}
