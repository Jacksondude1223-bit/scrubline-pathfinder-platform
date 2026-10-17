package bgp

import (
	"strings"
	"testing"

	"github.com/Jacksondude1223-bit/scrubline-cloud-scrub/internal/model"
)

func announce(prefix, node string, prepends int, communities ...string) model.Announcement {
	return model.Announcement{
		Prefix: prefix, NodeID: node, State: model.StateAnnounce,
		Prepends: prepends, NextHop: "198.51.100.1", Communities: communities,
	}
}

func TestAnnounceRendersPrependsAndCommunities(t *testing.T) {
	got, err := Commands([]model.Announcement{announce("203.0.113.0/24", "n1", 2, "65000:100")}, 65001)
	if err != nil {
		t.Fatalf("Commands: %v", err)
	}
	want := "announce route 203.0.113.0/24 next-hop 198.51.100.1 as-path [ 65001 65001 65001 ] community [ 65000:100 ]"
	if len(got) != 1 || got[0] != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

// Two prepends means two *extra* copies of the local AS beyond the one the
// path carries anyway.
func TestPrependCountIsPaddingNotPathLength(t *testing.T) {
	for prepends, want := range map[int]string{
		0: "announce route 203.0.113.0/24 next-hop 198.51.100.1",
		1: "announce route 203.0.113.0/24 next-hop 198.51.100.1 as-path [ 65001 65001 ]",
		3: "announce route 203.0.113.0/24 next-hop 198.51.100.1 as-path [ 65001 65001 65001 65001 ]",
	} {
		got, err := Commands([]model.Announcement{announce("203.0.113.0/24", "n1", prepends)}, 65001)
		if err != nil {
			t.Fatalf("prepends %d: %v", prepends, err)
		}
		if got[0] != want {
			t.Fatalf("prepends %d: got %q, want %q", prepends, got[0], want)
		}
	}
}

func TestWithdrawCarriesNoAttributes(t *testing.T) {
	a := announce("203.0.113.0/24", "n1", 3, "65000:100")
	a.State = model.StateWithdraw
	got, err := Commands([]model.Announcement{a}, 65001)
	if err != nil {
		t.Fatalf("Commands: %v", err)
	}
	want := "withdraw route 203.0.113.0/24 next-hop 198.51.100.1"
	if got[0] != want {
		t.Fatalf("got %q, want %q", got[0], want)
	}
}

// Asking for prepends without an AS to pad with would quietly announce at full
// preference, which is the opposite of what the plan asked for.
func TestPrependsWithoutALocalASIsAnError(t *testing.T) {
	if _, err := Commands([]model.Announcement{announce("203.0.113.0/24", "n1", 2)}, 0); err == nil {
		t.Fatal("expected an error when prepends are requested with no local AS")
	}
	// With no prepends asked for, no AS is needed.
	if _, err := Commands([]model.Announcement{announce("203.0.113.0/24", "n1", 0)}, 0); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// These lines are written into a routing daemon's control pipe. A community
// carrying a newline would be a second command.
func TestCommunityInjectionIsRefused(t *testing.T) {
	for _, bad := range []string{
		"65000:100\nannounce route 0.0.0.0/0 next-hop 10.0.0.1",
		"65000:100 next-hop 10.0.0.1",
		"; rm -rf /",
		"65000:99999",
		"65000",
		"",
		"not-a-community",
	} {
		_, err := Commands([]model.Announcement{announce("203.0.113.0/24", "n1", 0, bad)}, 65001)
		if err == nil {
			t.Fatalf("community %q should be refused", bad)
		}
	}
}

func TestValidCommunityForms(t *testing.T) {
	for _, good := range []string{"65000:100", "0:0", "65535:65535", "4200000000:1:2", "no-export", "NO-EXPORT", "blackhole"} {
		if err := ValidateCommunity(good); err != nil {
			t.Fatalf("community %q should be accepted: %v", good, err)
		}
	}
}

func TestMalformedPrefixOrNextHopIsRefused(t *testing.T) {
	bad := announce("not-a-prefix", "n1", 0)
	if _, err := Commands([]model.Announcement{bad}, 65001); err == nil {
		t.Fatal("expected an unparseable prefix to be refused")
	}
	badHop := announce("203.0.113.0/24", "n1", 0)
	badHop.NextHop = "not-an-address"
	if _, err := Commands([]model.Announcement{badHop}, 65001); err == nil {
		t.Fatal("expected an unparseable next hop to be refused")
	}
}

func TestUnknownStateIsRefused(t *testing.T) {
	a := announce("203.0.113.0/24", "n1", 0)
	a.State = "maybe"
	if _, err := Commands([]model.Announcement{a}, 65001); err == nil {
		t.Fatal("expected an unknown state to be refused")
	}
}

// The agent diffs rendered output to tell whether the plan moved, so an
// unchanged plan has to render identically every time.
func TestRenderingIsDeterministic(t *testing.T) {
	plan := []model.Announcement{
		announce("203.0.114.0/24", "n2", 1),
		announce("203.0.113.0/24", "n2", 1),
		announce("203.0.113.0/24", "n1", 0),
	}
	first, err := Commands(plan, 65001)
	if err != nil {
		t.Fatalf("Commands: %v", err)
	}
	for i := 0; i < 20; i++ {
		got, err := Commands(plan, 65001)
		if err != nil {
			t.Fatalf("Commands: %v", err)
		}
		if strings.Join(got, "\n") != strings.Join(first, "\n") {
			t.Fatalf("rendering changed between calls:\n%v\n%v", first, got)
		}
	}
	if !strings.Contains(first[0], "203.0.113.0/24") {
		t.Fatalf("expected output sorted by prefix, got %v", first)
	}
}

// A next hop is optional: without one the speaker falls back to its session
// address.
func TestMissingNextHopIsAllowed(t *testing.T) {
	a := announce("203.0.113.0/24", "n1", 0)
	a.NextHop = ""
	got, err := Commands([]model.Announcement{a}, 65001)
	if err != nil {
		t.Fatalf("Commands: %v", err)
	}
	if got[0] != "announce route 203.0.113.0/24" {
		t.Fatalf("unexpected command %q", got[0])
	}
}
