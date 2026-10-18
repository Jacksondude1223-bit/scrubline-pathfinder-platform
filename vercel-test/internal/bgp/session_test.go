package bgp

import (
	"strings"
	"testing"

	"github.com/Jacksondude1223-bit/scrubline-cloud-scrub/internal/model"
)

func testNode() model.Node {
	return model.Node{ID: "node-a", Name: "edge-lhr", Region: "lhr", TunnelSrc: "192.0.2.1"}
}

func testSession() model.Session {
	return model.Session{
		ID: "northwind", PeerIP: "198.51.100.1", PeerAS: 64512,
		Prefixes: []string{"203.0.113.0/24"},
	}
}

// A customer peering renders as a complete, filtered session: who, from
// where, what it will accept, and what happens when the peer sends more.
func TestSessionRendersAFilteredPeering(t *testing.T) {
	s := testSession()
	s.Comment = "Northwind Games"
	s.Password = "correct-horse"
	s.Passive = true
	s.Multihop = 2

	lines, err := SessionConfig([]model.Session{s}, testNode(), 65000)
	if err != nil {
		t.Fatalf("SessionConfig: %v", err)
	}
	got := strings.Join(lines, "\n")
	for _, want := range []string{
		"protocol bgp cust_northwind {",
		`description "Northwind Games";`,
		"local 192.0.2.1 as 65000;",
		"neighbor 198.51.100.1 as 64512;",
		`password "correct-horse";`,
		"passive;",
		"multihop 2;",
		"import filter { if net ~ [ 203.0.113.0/24+ ] then accept; reject; };",
		"import limit 8 action restart;",
		"export none;",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("expected %q in:\n%s", want, got)
		}
	}
}

// The filter accepts more-specifics inside an entitled prefix. Customers
// de-aggregate under attack, and a filter that refused that would drop the
// announcement at the moment it mattered most.
func TestSessionFilterAcceptsMoreSpecifics(t *testing.T) {
	lines, _ := SessionConfig([]model.Session{testSession()}, testNode(), 65000)
	got := strings.Join(lines, "\n")
	if !strings.Contains(got, "203.0.113.0/24+") {
		t.Fatalf("expected the filter to admit more-specifics:\n%s", got)
	}
}

// A session with no local AS anywhere would come up announcing from whatever
// the daemon happened to hold, which is not a decision this fabric gets to
// leave to a config file.
func TestSessionNeedsALocalAS(t *testing.T) {
	if _, err := SessionConfig([]model.Session{testSession()}, testNode(), 0); err == nil {
		t.Fatal("expected a session with no AS anywhere to be refused")
	}
	s := testSession()
	s.LocalAS = 65010
	lines, err := SessionConfig([]model.Session{s}, testNode(), 0)
	if err != nil {
		t.Fatalf("a session carrying its own AS was refused: %v", err)
	}
	if !strings.Contains(strings.Join(lines, "\n"), "as 65010;") {
		t.Fatal("expected the session's own AS to be used")
	}
}

// Everything here lands in a routing daemon's configuration file, so a value
// that could close its string and keep going is refused rather than quoted.
func TestSessionRefusesValuesItCannotVouchFor(t *testing.T) {
	protected := map[string]bool{"203.0.113.0/24": true}
	bad := []struct {
		name string
		edit func(*model.Session)
	}{
		{"password closing the string", func(s *model.Session) { s.Password = `x"; } protocol bgp evil {` }},
		{"password with a newline", func(s *model.Session) { s.Password = "x\nprotocol" }},
		{"password with a backslash", func(s *model.Session) { s.Password = `x\y` }},
		{"peer ip that is not one", func(s *model.Session) { s.PeerIP = "198.51.100.1; reboot" }},
		{"peer as out of range", func(s *model.Session) { s.PeerAS = 5000000000 }},
		{"negative multihop", func(s *model.Session) { s.Multihop = -1 }},
		{"id that is not a name", func(s *model.Session) { s.ID = "9north wind" }},
		{"unmasked prefix", func(s *model.Session) { s.Prefixes = []string{"203.0.113.5/24"} }},
		{"unprotected prefix", func(s *model.Session) { s.Prefixes = []string{"198.18.0.0/24"} }},
		{"no prefixes at all", func(s *model.Session) { s.Prefixes = nil }},
	}
	for _, c := range bad {
		t.Run(c.name, func(t *testing.T) {
			s := testSession()
			c.edit(&s)
			if err := ValidateSession(s, protected); err == nil {
				t.Fatalf("expected %s to be refused", c.name)
			}
		})
	}
}

// A description is a convenience, not a channel. It is free text an operator
// types, and it is written into a routing daemon's config, so what matters is
// that it cannot carry the characters that would end the string it sits in
// and start something else. Prose that merely reads like config is inert once
// those are gone.
func TestSessionDescriptionCannotEscape(t *testing.T) {
	s := testSession()
	s.Comment = "Northwind\"; } protocol bgp evil { neighbor 1.2.3.4 as 1;\n\tmore"
	lines, err := SessionConfig([]model.Session{s}, testNode(), 65000)
	if err != nil {
		t.Fatalf("SessionConfig: %v", err)
	}

	var description string
	for _, l := range lines {
		if strings.Contains(l, "description ") {
			description = l
		}
		if strings.Contains(l, "\n") {
			t.Fatalf("a rendered line contains a newline: %q", l)
		}
	}
	if description == "" {
		t.Fatal("expected a description line")
	}
	// Exactly the two quotes that delimit it, and nothing that could close a
	// block or end a statement early.
	if strings.Count(description, `"`) != 2 {
		t.Fatalf("the description is not a single quoted string: %q", description)
	}
	for _, bad := range []string{"{", "}", ";", "\\"} {
		inner := strings.TrimSuffix(strings.TrimPrefix(description, `    description "`), `";`)
		if strings.Contains(inner, bad) {
			t.Fatalf("the description carried %q into the config: %q", bad, description)
		}
	}
	// The block has exactly the structure a clean session has: the
	// description added no blocks and closed none.
	clean := testSession()
	cleanLines, err := SessionConfig([]model.Session{clean}, testNode(), 65000)
	if err != nil {
		t.Fatalf("SessionConfig: %v", err)
	}
	joined, cleanJoined := strings.Join(lines, "\n"), strings.Join(cleanLines, "\n")
	for _, brace := range []string{"{", "}"} {
		if strings.Count(joined, brace) != strings.Count(cleanJoined, brace) {
			t.Fatalf("the description changed the block structure (%q): got %d, a clean session has %d\n%s",
				brace, strings.Count(joined, brace), strings.Count(cleanJoined, brace), joined)
		}
	}
}

// A customer peers where they have a path, not with the whole fabric.
func TestSessionScoping(t *testing.T) {
	lhr := model.Node{ID: "node-a", Name: "edge-lhr", Region: "lhr"}
	fra := model.Node{ID: "node-b", Name: "edge-fra", Region: "fra"}

	byRegion := testSession()
	byRegion.Regions = []string{"lhr"}
	if !TerminatesOn(byRegion, lhr) || TerminatesOn(byRegion, fra) {
		t.Fatal("region scoping did not select the right node")
	}

	byNode := testSession()
	byNode.Nodes = []string{"edge-fra"}
	if TerminatesOn(byNode, lhr) || !TerminatesOn(byNode, fra) {
		t.Fatal("node scoping did not select the right node")
	}

	// Unscoped means everywhere, which is the documented default.
	if !TerminatesOn(testSession(), lhr) || !TerminatesOn(testSession(), fra) {
		t.Fatal("an unscoped session should terminate everywhere")
	}
}

// The import limit is a backstop against a leak. It has headroom over the
// prefix count on purpose, because de-aggregating under attack is normal.
func TestImportLimitHasHeadroomAndCanBeSet(t *testing.T) {
	s := testSession()
	if got := ImportLimit(s); got <= len(s.Prefixes) {
		t.Fatalf("expected headroom over %d prefixes, got a limit of %d", len(s.Prefixes), got)
	}
	s.MaxPrefixes = 3
	if got := ImportLimit(s); got != 3 {
		t.Fatalf("expected an explicit limit to win, got %d", got)
	}
}

// A node with no address to peer from cannot terminate a session; saying so
// beats compiling one that never comes up.
func TestSessionNeedsAnAddressToPeerFrom(t *testing.T) {
	if _, err := SessionConfig([]model.Session{testSession()}, model.Node{ID: "node-a"}, 65000); err == nil {
		t.Fatal("expected a node with no tunnel_src to be refused")
	}
}
