package tunnel

import (
	"strings"
	"testing"

	"github.com/Jacksondude1223-bit/scrubline-cloud-scrub/internal/model"
)

func protectedSet(prefixes ...string) map[string]bool {
	out := map[string]bool{}
	for _, p := range prefixes {
		out[p] = true
	}
	return out
}

// The MTU has to leave room for the encapsulation, and the clamp has to leave
// room for the inner headers. Both numbers are the difference between a
// tunnel that works and one that carries a handshake and then hangs.
func TestDerivedMTUAndClampMatchTheOverhead(t *testing.T) {
	cases := []struct {
		name      string
		tunnel    model.Tunnel
		wantMTU   int
		wantClamp int
	}{
		// 1500 - 20 outer IPv4 - 4 GRE.
		{"gre", model.Tunnel{Type: model.TunnelGRE}, 1476, 1436},
		// The key costs four more bytes, and the MTU has to know that.
		{"gre with a key", model.Tunnel{Type: model.TunnelGRE, Key: 42}, 1472, 1432},
		// ipip has no header of its own beyond the outer IPv4.
		{"ipip", model.Tunnel{Type: model.TunnelIPIP}, 1480, 1440},
		// An unset type is GRE.
		{"default", model.Tunnel{}, 1476, 1436},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := DefaultMTU(c.tunnel); got != c.wantMTU {
				t.Fatalf("MTU: want %d, got %d", c.wantMTU, got)
			}
			if got := MSSFor(DefaultMTU(c.tunnel)); got != c.wantClamp {
				t.Fatalf("clamp: want %d, got %d", c.wantClamp, got)
			}
		})
	}
}

// A tunnel id becomes an interface name, and the kernel truncates a name over
// its limit rather than refusing it — so two tunnels could silently become
// one. The limit is enforced here instead.
func TestTunnelIDIsHeldToAnInterfaceName(t *testing.T) {
	if _, err := InterfaceName("northwind-primary-london"); err == nil {
		t.Fatal("expected an over-long id to be refused")
	}
	name, err := InterfaceName("northwind")
	if err != nil {
		t.Fatalf("a reasonable id was refused: %v", err)
	}
	if name != "scr-northwind" {
		t.Fatalf("unexpected interface name %q", name)
	}
	if len(name) > ifNameMax {
		t.Fatalf("name %q is over the kernel's limit", name)
	}
	for _, bad := range []string{"", "Northwind", "north wind", "north;wind", "-north", "north/wind", "north$(id)"} {
		if err := ValidateID(bad); err == nil {
			t.Fatalf("expected %q to be refused as an interface name", bad)
		}
	}
}

// Everything in a rendered line reaches a command on a scrubbing node, so a
// value that could break out of it is refused rather than quoted.
func TestRenderingRefusesValuesItCannotVouchFor(t *testing.T) {
	base := model.NodeTunnel{
		ID: "cust", Type: model.TunnelGRE, Local: "192.0.2.1", Remote: "198.51.100.1",
		Prefixes: []string{"203.0.113.0/24"}, MTU: 1476, MSSClamp: 1436, Interface: "scr-cust",
	}
	bad := []struct {
		name  string
		edit  func(*model.NodeTunnel)
		cause string
	}{
		{"injected local", func(n *model.NodeTunnel) { n.Local = "192.0.2.1; rm -rf /" }, "local"},
		{"injected remote", func(n *model.NodeTunnel) { n.Remote = "198.51.100.1 && reboot" }, "remote"},
		{"injected prefix", func(n *model.NodeTunnel) { n.Prefixes = []string{"203.0.113.0/24\nip link del eth0"} }, "prefix"},
		{"injected id", func(n *model.NodeTunnel) { n.ID = "a;b"; n.Interface = "" }, "id"},
		{"mismatched interface", func(n *model.NodeTunnel) { n.Interface = "eth0" }, "interface"},
		{"same both ends", func(n *model.NodeTunnel) { n.Remote = n.Local }, "local and remote"},
		{"unknown type", func(n *model.NodeTunnel) { n.Type = "wireguard" }, "unknown type"},
		{"ipip with a key", func(n *model.NodeTunnel) { n.Type = model.TunnelIPIP; n.Key = 7 }, "key"},
		{"mtu below the floor", func(n *model.NodeTunnel) { n.MTU = 100 }, "minimum"},
	}
	for _, c := range bad {
		t.Run(c.name, func(t *testing.T) {
			nt := base
			nt.Prefixes = append([]string(nil), base.Prefixes...)
			c.edit(&nt)
			_, err := Commands([]model.NodeTunnel{nt})
			if err == nil {
				t.Fatalf("expected %s to be refused", c.name)
			}
			if !strings.Contains(err.Error(), c.cause) {
				t.Fatalf("expected the error to name %q, got %v", c.cause, err)
			}
		})
	}
}

// A comment is a convenience, not a channel: it cannot carry a newline into
// the generated config.
func TestCommentsCannotEscapeTheConfig(t *testing.T) {
	lines, err := Commands([]model.NodeTunnel{{
		ID: "cust", Type: model.TunnelGRE, Local: "192.0.2.1", Remote: "198.51.100.1",
		Prefixes: []string{"203.0.113.0/24"}, MTU: 1476, Interface: "scr-cust",
		Comment: "primary\nip link del eth0",
	}})
	if err != nil {
		t.Fatalf("Commands: %v", err)
	}
	for _, l := range lines {
		if strings.Contains(l, "del eth0") && !strings.HasPrefix(l, "# ") {
			t.Fatalf("a comment reached a command line: %q", l)
		}
		if strings.Contains(l, "\n") {
			t.Fatalf("a rendered line contains a newline: %q", l)
		}
	}
}

// The rendered config is the whole tunnel: the link, its MTU, a route per
// prefix, and the clamp.
func TestCommandsRenderTheWholeTunnel(t *testing.T) {
	lines, err := Commands([]model.NodeTunnel{{
		ID: "northwind", Type: model.TunnelGRE, Local: "192.0.2.1", Remote: "198.51.100.1",
		Prefixes: []string{"203.0.113.0/24", "198.18.0.0/24"}, MTU: 1472, MSSClamp: 1432,
		Key: 42, Interface: "scr-northwind",
	}})
	if err != nil {
		t.Fatalf("Commands: %v", err)
	}
	got := strings.Join(lines, "\n")
	for _, want := range []string{
		"ip link add scr-northwind type gre local 192.0.2.1 remote 198.51.100.1 key 42",
		"ip link set scr-northwind mtu 1472 up",
		"ip route replace 198.18.0.0/24 dev scr-northwind",
		"ip route replace 203.0.113.0/24 dev scr-northwind",
		"maxseg size set 1432",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("expected %q in:\n%s", want, got)
		}
	}
	// Prefixes are sorted, so an unchanged tunnel renders identically and the
	// agent can tell when nothing moved.
	if strings.Index(got, "198.18.0.0/24") > strings.Index(got, "203.0.113.0/24") {
		t.Fatalf("routes are not in a stable order:\n%s", got)
	}
}

// A tunnel pointing at a prefix the policy does not protect is a typo that
// would otherwise sit there delivering nothing.
func TestValidateTiesTunnelsToProtectedPrefixes(t *testing.T) {
	protected := protectedSet("203.0.113.0/24")
	err := Validate(model.Tunnel{
		ID: "cust", Remote: "198.51.100.1", Prefixes: []string{"198.18.0.0/24"},
	}, protected)
	if err == nil || !strings.Contains(err.Error(), "protected list") {
		t.Fatalf("expected an unprotected prefix to be refused, got %v", err)
	}
	if err := Validate(model.Tunnel{
		ID: "cust", Remote: "198.51.100.1", Prefixes: []string{"203.0.113.0/24"},
	}, protected); err != nil {
		t.Fatalf("a valid tunnel was refused: %v", err)
	}
}

// An MTU that does not fit the encapsulation is refused with the value that
// would, rather than compiled into a tunnel that drops large packets.
func TestValidateRefusesAnMTUThatCannotFit(t *testing.T) {
	protected := protectedSet("203.0.113.0/24")
	err := Validate(model.Tunnel{
		ID: "cust", Remote: "198.51.100.1", Prefixes: []string{"203.0.113.0/24"},
		Type: model.TunnelGRE, MTU: 1500,
	}, protected)
	if err == nil || !strings.Contains(err.Error(), "1476") {
		t.Fatalf("expected the refusal to name the largest MTU that fits, got %v", err)
	}
}

// Anycast means every node carrying the prefixes builds its own tunnel to the
// one customer endpoint, each from its own address.
func TestForNodeFillsInTheLocalEnd(t *testing.T) {
	policy := model.Tunnel{ID: "northwind", Remote: "198.51.100.1", Prefixes: []string{"203.0.113.0/24"}}
	a, err := ForNode(policy, model.Node{ID: "node-a", TunnelSrc: "192.0.2.1"}, policy.Prefixes)
	if err != nil {
		t.Fatalf("ForNode: %v", err)
	}
	b, err := ForNode(policy, model.Node{ID: "node-b", TunnelSrc: "192.0.2.2"}, policy.Prefixes)
	if err != nil {
		t.Fatalf("ForNode: %v", err)
	}
	if a.Local == b.Local {
		t.Fatal("two nodes compiled the same local endpoint")
	}
	if a.Remote != b.Remote {
		t.Fatal("the customer endpoint should be the same from every node")
	}
	if a.MTU != 1476 || a.MSSClamp != 1436 {
		t.Fatalf("expected the derived MTU and clamp, got mtu=%d clamp=%d", a.MTU, a.MSSClamp)
	}

	// A node with nowhere to source a tunnel from cannot carry one.
	if _, err := ForNode(policy, model.Node{ID: "node-c"}, policy.Prefixes); err == nil {
		t.Fatal("expected a node with no tunnel_src to be refused")
	}
}

// A tunnel reported down takes its prefixes off that node: announcing a
// prefix you cannot deliver is worse than not announcing it.
func TestDeliverableFollowsReportedState(t *testing.T) {
	optional := model.NodeTunnel{ID: "cust"}
	required := model.NodeTunnel{ID: "cust", Required: true}

	if ok, _ := Deliverable(optional, model.TunnelDown); ok {
		t.Fatal("a tunnel reported down should not be deliverable")
	}
	if ok, _ := Deliverable(optional, model.TunnelUp); !ok {
		t.Fatal("a tunnel reported up should be deliverable")
	}
	// Silence is not bad news: a fabric whose provisioner reports nothing
	// should still carry traffic, not blank itself.
	if ok, _ := Deliverable(optional, model.TunnelUnknown); !ok {
		t.Fatal("an unreported optional tunnel should not withdraw the prefix")
	}
	// Unless the operator asked for the opposite.
	if ok, why := Deliverable(required, model.TunnelUnknown); ok {
		t.Fatalf("a required tunnel with no report should withdraw, got ok (%s)", why)
	}
}
