package bgp

import (
	"fmt"
	"net/netip"
	"regexp"
	"sort"
	"strings"

	"github.com/Jacksondude1223-bit/scrubline-cloud-scrub/internal/model"
)

// Customer peering is rendered as BIRD rather than as the ExaBGP commands the
// announcement plan uses, and the split is deliberate.
//
// Announcing is an imperative act — announce this, withdraw that, now — which
// is exactly what ExaBGP's command pipe is for. Peering with a customer is a
// standing configuration with an import filter and a prefix limit on it, and
// that is what BIRD's config language says well and ExaBGP's does not say at
// all. The session is served as JSON too, for anyone driving a third speaker.

const (
	// asMax is the largest 32-bit AS number.
	asMax = 4294967295
	// prefixLimitFactor is how much headroom the derived import limit leaves
	// over the number of prefixes a session accepts. De-aggregating under
	// attack is normal and expected, so an exact count would tear the
	// session down at the worst possible moment; the limit is a backstop
	// against a leak, not an inventory.
	prefixLimitFactor = 4
	// prefixLimitFloor keeps the derived limit usable for a session carrying
	// one or two prefixes.
	prefixLimitFloor = 8
	// maxMultihop is the largest sensible TTL for a peer that is not
	// directly attached.
	maxMultihop = 255
)

// sessionIDPattern is what a session id may contain.
//
// It is checked on the id as written, not on the name it compiles to: the
// "cust_" prefix would launder anything into something BIRD accepts, so
// validating the derived name proves nothing about the input.
var sessionIDPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]*$`)

// sessionIDMax keeps a protocol name to something a daemon and a human can
// both handle.
const sessionIDMax = 48

// ValidateSession checks one customer peering as written in a policy.
//
// Every field here ends up in a routing daemon's configuration file, so this
// holds the same line ValidateCommunity does: a value that cannot be vouched
// for is refused rather than quoted.
func ValidateSession(s model.Session, protected map[string]bool) error {
	if s.ID == "" {
		return fmt.Errorf("session id must not be empty")
	}
	if len(s.ID) > sessionIDMax {
		return fmt.Errorf("session %q: id is %d characters, over the %d-character limit", s.ID, len(s.ID), sessionIDMax)
	}
	if !sessionIDPattern.MatchString(s.ID) {
		return fmt.Errorf("session %q: id must be lowercase letters, digits, dashes and underscores, starting with a letter or digit", s.ID)
	}
	if _, err := netip.ParseAddr(s.PeerIP); err != nil {
		return fmt.Errorf("session %s: peer_ip %q is not an IP address: %v", s.ID, s.PeerIP, err)
	}
	if s.PeerAS <= 0 || s.PeerAS > asMax {
		return fmt.Errorf("session %s: peer_as %d is not a usable AS number", s.ID, s.PeerAS)
	}
	if s.LocalAS < 0 || s.LocalAS > asMax {
		return fmt.Errorf("session %s: local_as %d is not a usable AS number", s.ID, s.LocalAS)
	}
	if s.Multihop < 0 || s.Multihop > maxMultihop {
		return fmt.Errorf("session %s: multihop %d is outside 0..%d", s.ID, s.Multihop, maxMultihop)
	}
	if s.MaxPrefixes < 0 {
		return fmt.Errorf("session %s: max_prefixes must not be negative", s.ID)
	}
	if len(s.Prefixes) == 0 {
		return fmt.Errorf("session %s: needs at least one prefix, or it accepts nothing and the peering does nothing", s.ID)
	}
	seen := map[string]bool{}
	for i, prefix := range s.Prefixes {
		p, err := netip.ParsePrefix(prefix)
		if err != nil {
			return fmt.Errorf("session %s: prefixes[%d] %q: %v", s.ID, i, prefix, err)
		}
		if p.Masked() != p {
			return fmt.Errorf("session %s: prefixes[%d] %q has host bits set; write it as %s", s.ID, i, prefix, p.Masked())
		}
		if seen[prefix] {
			return fmt.Errorf("session %s: prefixes[%d]: duplicate prefix %q", s.ID, i, prefix)
		}
		seen[prefix] = true
		// A session that could accept a prefix the policy does not protect
		// would have the fabric announcing address space nobody asked it to
		// defend, on the say-so of the peer.
		if protected != nil && !protected[prefix] {
			return fmt.Errorf("session %s: prefixes[%d]: %q is not in this policy's protected list", s.ID, i, prefix)
		}
	}
	if err := validateSecret(s.Password); err != nil {
		return fmt.Errorf("session %s: password: %v", s.ID, err)
	}
	for i, region := range s.Regions {
		if strings.TrimSpace(region) == "" {
			return fmt.Errorf("session %s: regions[%d] must not be empty", s.ID, i)
		}
	}
	for i, node := range s.Nodes {
		if strings.TrimSpace(node) == "" {
			return fmt.Errorf("session %s: nodes[%d] must not be empty", s.ID, i)
		}
	}
	return nil
}

// validateSecret refuses a password that could close the quoted string it is
// written into and continue as configuration.
func validateSecret(p string) error {
	if p == "" {
		return nil
	}
	if len(p) > 80 {
		return fmt.Errorf("is longer than the 80 characters TCP-MD5 allows for")
	}
	for _, r := range p {
		if r < 0x21 || r > 0x7e || r == '"' || r == '\\' {
			return fmt.Errorf("must be printable ASCII without spaces, quotes or backslashes")
		}
	}
	return nil
}

// TerminatesOn reports whether a session is configured on a given node.
// Empty scoping means every node, which is rarely what anyone wants: a
// customer peers where they have a path, not with the whole fabric.
func TerminatesOn(s model.Session, n model.Node) bool {
	if len(s.Nodes) == 0 && len(s.Regions) == 0 {
		return true
	}
	for _, id := range s.Nodes {
		if id == n.ID || id == n.Name {
			return true
		}
	}
	for _, region := range s.Regions {
		if region == n.Region {
			return true
		}
	}
	return false
}

// ImportLimit is the number of accepted routes a session tolerates before it
// is torn down.
func ImportLimit(s model.Session) int {
	if s.MaxPrefixes > 0 {
		return s.MaxPrefixes
	}
	limit := len(s.Prefixes) * prefixLimitFactor
	if limit < prefixLimitFloor {
		limit = prefixLimitFloor
	}
	return limit
}

// protocolName is the BIRD protocol name a session id compiles to. The id is
// validated before it gets here; the dash is the one legal character BIRD
// will not take in a name.
func protocolName(id string) string {
	return "cust_" + strings.ReplaceAll(id, "-", "_")
}

// SessionConfig renders the customer peerings one node terminates as BIRD
// configuration, sorted so an unchanged set renders byte for byte the same.
//
// localAS is the fabric's own AS, used for any session that does not name
// one. A session with neither is an error rather than a peering that comes up
// announcing from whatever the daemon happened to be configured with.
func SessionConfig(sessions []model.Session, node model.Node, localAS int) ([]string, error) {
	if localAS < 0 || localAS > asMax {
		return nil, fmt.Errorf("local AS %d is out of range", localAS)
	}
	rows := make([]model.Session, len(sessions))
	copy(rows, sessions)
	sort.SliceStable(rows, func(i, j int) bool { return rows[i].ID < rows[j].ID })

	out := []string{}
	for _, s := range rows {
		lines, err := sessionLines(s, node, localAS)
		if err != nil {
			return nil, err
		}
		out = append(out, lines...)
	}
	return out, nil
}

func sessionLines(s model.Session, node model.Node, fabricAS int) ([]string, error) {
	if err := ValidateSession(s, nil); err != nil {
		return nil, err
	}
	as := s.LocalAS
	if as == 0 {
		as = fabricAS
	}
	if as == 0 {
		return nil, fmt.Errorf("session %s: no local AS, and the node has none configured", s.ID)
	}
	local := node.TunnelSrc
	if local == "" {
		// The session has to source from an address the customer can reach.
		// The node's tunnel source is the one address it is known by that is
		// not the control-plane API, which is deliberately not routable to
		// customers.
		return nil, fmt.Errorf("session %s: node %s has no tunnel_src to peer from", s.ID, node.ID)
	}
	if _, err := netip.ParseAddr(local); err != nil {
		return nil, fmt.Errorf("session %s: node %s has an unusable tunnel_src %q", s.ID, node.ID, local)
	}

	name := protocolName(s.ID)
	prefixes := append([]string(nil), s.Prefixes...)
	sort.Strings(prefixes)
	// Accept each prefix and anything more specific inside it: customers
	// de-aggregate under attack, and a filter that refused that would drop
	// the announcement at the moment it mattered most.
	terms := make([]string, 0, len(prefixes))
	for _, prefix := range prefixes {
		p, err := netip.ParsePrefix(prefix)
		if err != nil {
			return nil, fmt.Errorf("session %s: prefix %q: %v", s.ID, prefix, err)
		}
		terms = append(terms, p.Masked().String()+"+")
	}

	lines := []string{
		fmt.Sprintf("protocol bgp %s {", name),
	}
	if c := sanitise(s.Comment); c != "" {
		lines = append(lines, fmt.Sprintf("    description \"%s\";", c))
	}
	lines = append(lines,
		fmt.Sprintf("    local %s as %d;", local, as),
		fmt.Sprintf("    neighbor %s as %d;", s.PeerIP, s.PeerAS),
	)
	if s.Password != "" {
		lines = append(lines, fmt.Sprintf("    password \"%s\";", s.Password))
	}
	if s.Passive {
		lines = append(lines, "    passive;")
	}
	if s.Multihop > 0 {
		lines = append(lines, fmt.Sprintf("    multihop %d;", s.Multihop))
	}
	lines = append(lines,
		"    ipv4 {",
		fmt.Sprintf("        import filter { if net ~ [ %s ] then accept; reject; };", strings.Join(terms, ", ")),
		fmt.Sprintf("        import limit %d action restart;", ImportLimit(s)),
		// Nothing is announced back to the customer. What the fabric sends
		// them is the scrubbed traffic over the return tunnel, not routes.
		"        export none;",
		"    };",
		"}",
	)
	return lines, nil
}

// sanitise reduces operator free text to something that cannot close the
// string it is written into and continue as configuration.
//
// Quotes and backslashes are the escape; the braces and semicolons go too.
// They cannot break out on their own once the quotes are gone, but a
// description that reads like a second protocol block is the kind of thing
// that survives into an incident review as "was the config tampered with",
// and no description needs them.
func sanitise(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r < 0x20 || r > 0x7e {
			continue
		}
		switch r {
		case '"', '\\', '{', '}', ';':
			continue
		}
		b.WriteRune(r)
		if b.Len() >= 100 {
			break
		}
	}
	return strings.TrimSpace(b.String())
}
