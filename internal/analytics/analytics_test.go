package analytics

import (
	"testing"
	"time"

	"github.com/Jacksondude1223-bit/scrubline-cloud-scrub/internal/pipeline"
	"github.com/Jacksondude1223-bit/scrubline-cloud-scrub/internal/telemetry"
)

// harness drives a collector on a clock the test moves by hand.
type harness struct {
	*Collector
	clock time.Time
}

func newHarness() *harness {
	h := &harness{Collector: New(), clock: time.Unix(1_700_000_000, 0).UTC()}
	h.SetClock(func() time.Time { return h.clock })
	return h
}

func (h *harness) advance(d time.Duration) { h.clock = h.clock.Add(d) }

// report builds a node report carrying one prefix row.
func report(node, prefix string, row pipeline.PrefixStats) telemetry.Report {
	row.Prefix = prefix
	return telemetry.Report{
		NodeID: node,
		Stats:  pipeline.Stats{Prefixes: []pipeline.PrefixStats{row}},
	}
}

// A customer's prefix is carried by the whole fabric, so their numbers are
// the sum across the nodes scrubbing for them — not any one node's view.
func TestSummarySumsTheFleet(t *testing.T) {
	h := newHarness()
	for _, node := range []string{"node-a", "node-b", "node-c"} {
		h.Observe(report(node, "203.0.113.0/24", pipeline.PrefixStats{
			Flows: 100, Offered: 300_000, OfferedPPS: 30_000,
		}), Attribution{})
	}

	got := h.Summary("203.0.113.0/24", time.Hour)
	if got.Nodes != 3 {
		t.Fatalf("expected three scrubbers counted, got %d", got.Nodes)
	}
	if got.OfferedPPS != 90_000 {
		t.Fatalf("expected the fleet's offered rate summed, got %d", got.OfferedPPS)
	}
	if got.Offered != 900_000 || got.Flows != 300 {
		t.Fatalf("expected the fleet's volume summed, got %+v", got)
	}
}

// A node that stops reporting is not still scrubbing at the rate it last
// claimed. Leaving its number in the total would show a customer an attack
// that ended.
func TestStaleNodesLeaveTheFleetTotal(t *testing.T) {
	h := newHarness()
	h.Observe(report("node-a", "203.0.113.0/24", pipeline.PrefixStats{OfferedPPS: 40_000}), Attribution{})
	h.Observe(report("node-b", "203.0.113.0/24", pipeline.PrefixStats{OfferedPPS: 40_000}), Attribution{})
	if got := h.Summary("203.0.113.0/24", time.Hour); got.OfferedPPS != 80_000 {
		t.Fatalf("expected both nodes counted, got %d", got.OfferedPPS)
	}

	h.advance(NodeFreshness + time.Second)
	h.Observe(report("node-a", "203.0.113.0/24", pipeline.PrefixStats{OfferedPPS: 40_000}), Attribution{})
	got := h.Summary("203.0.113.0/24", time.Hour)
	if got.OfferedPPS != 40_000 {
		t.Fatalf("expected the silent node dropped from the total, got %d", got.OfferedPPS)
	}
	if got.Nodes != 1 {
		t.Fatalf("expected one scrubber counted, got %d", got.Nodes)
	}
}

// Nodes report cumulative counters, so a restart sends them back to zero. The
// difference has to read as "this node restarted", not as a customer whose
// traffic went negative or, worse, as a counter that never moves again.
func TestCounterResetIsNotNegativeTraffic(t *testing.T) {
	h := newHarness()
	h.Observe(report("node-a", "203.0.113.0/24", pipeline.PrefixStats{Flows: 1000, Offered: 500_000}), Attribution{})
	h.advance(time.Minute)
	// The agent restarted: counters start again from a small number.
	h.Observe(report("node-a", "203.0.113.0/24", pipeline.PrefixStats{Flows: 7, Offered: 3_000}), Attribution{})

	got := h.Summary("203.0.113.0/24", time.Hour)
	if got.Flows != 1007 || got.Offered != 503_000 {
		t.Fatalf("expected the restart counted as 7 new flows, got %+v", got)
	}

	h.advance(time.Minute)
	h.Observe(report("node-a", "203.0.113.0/24", pipeline.PrefixStats{Flows: 20, Offered: 9_000}), Attribution{})
	if got := h.Summary("203.0.113.0/24", time.Hour); got.Flows != 1020 {
		t.Fatalf("expected counting to continue from the restarted counter, got %d", got.Flows)
	}
}

// An attack is opened when a meaningful share of a prefix's traffic is being
// scrubbed, and it carries the rules that did the scrubbing.
func TestAttackEventRecordsItsVectors(t *testing.T) {
	h := newHarness()
	attr := Attribution{Rules: map[string]Scope{
		"udp-flood": {Prefixes: []string{"203.0.113.0/24"}, Stage: "asic"},
	}}
	r := report("node-a", "203.0.113.0/24", pipeline.PrefixStats{
		Flows: 500, FlowsDropped: 480,
		Offered: 900_000, Dropped: 850_000,
		OfferedPPS: 90_000, DroppedPPS: 85_000, PeakPPS: 120_000,
	})
	r.Stats.Rules = []pipeline.RuleStats{{RuleID: "udp-flood", Stage: "asic", Drops: 480, PPSDropped: 850_000}}
	h.Observe(r, attr)

	events := h.Events("203.0.113.0/24", time.Hour)
	if len(events) != 1 {
		t.Fatalf("expected one attack recorded, got %d", len(events))
	}
	e := events[0]
	if !e.Ongoing {
		t.Fatal("expected the attack to be reported as still running")
	}
	if e.PeakDroppedPPS != 85_000 || e.PeakPPS != 120_000 {
		t.Fatalf("expected the peaks recorded, got %+v", e)
	}
	if len(e.Vectors) != 1 || e.Vectors[0].RuleID != "udp-flood" || e.Vectors[0].Dropped != 850_000 {
		t.Fatalf("expected the rule that stopped it named, got %+v", e.Vectors)
	}
	if !h.Summary("203.0.113.0/24", time.Hour).UnderAttack {
		t.Fatal("expected the summary to say the prefix is under attack")
	}
}

// A burst train is quiet between bursts by design. Closing the event on the
// first quiet poll would record one attack as dozens, which is exactly the
// reporting the attacker's interval is paying for.
func TestABurstTrainIsOneAttackNotFifty(t *testing.T) {
	h := newHarness()
	burst := pipeline.PrefixStats{OfferedPPS: 400_000, DroppedPPS: 390_000, Pulsing: true, PeakPPS: 400_000}
	// Between bursts there is nothing at all on the line: no traffic, no
	// drops, and the node reporting no pulse. Only the settle window holds
	// the event open across this.
	quiet := pipeline.PrefixStats{}

	var wentQuiet time.Time
	for i := 0; i < 6; i++ {
		h.Observe(report("node-a", "203.0.113.0/24", burst), Attribution{})
		h.advance(20 * time.Second)
		wentQuiet = h.clock
		h.Observe(report("node-a", "203.0.113.0/24", quiet), Attribution{})
		h.advance(20 * time.Second)
	}

	events := h.Events("203.0.113.0/24", time.Hour)
	if len(events) != 1 {
		t.Fatalf("expected a burst train recorded as one attack, got %d", len(events))
	}
	if !events[0].Ongoing {
		t.Fatal("expected the attack to still be open across the gap between bursts")
	}
	if !events[0].Pulse {
		t.Fatal("expected the event marked as a recognised burst train")
	}

	// The train really stops.
	h.advance(AttackSettle)
	h.Observe(report("node-a", "203.0.113.0/24", quiet), Attribution{})

	events = h.Events("203.0.113.0/24", time.Hour)
	if len(events) != 1 || events[0].Ongoing {
		t.Fatalf("expected the attack closed once it was genuinely over, got %+v", events)
	}
	// Dated to when the traffic stopped, not to the end of the settle window:
	// a customer is not under attack for the two minutes spent confirming it.
	if events[0].EndedAt == nil || !events[0].EndedAt.Equal(wentQuiet) {
		t.Fatalf("expected the end dated to %v, got %v", wentQuiet, events[0].EndedAt)
	}
}

// A trickle of drops against a quiet prefix is not an attack. Without a
// magnitude floor every stray packet would be billed to a customer as one.
func TestATrickleIsNotAnAttack(t *testing.T) {
	h := newHarness()
	h.Observe(report("node-a", "203.0.113.0/24", pipeline.PrefixStats{
		OfferedPPS: 40, DroppedPPS: 40, Flows: 10, FlowsDropped: 10,
	}), Attribution{})
	if got := h.Events("203.0.113.0/24", time.Hour); len(got) != 0 {
		t.Fatalf("expected no attack recorded for a trickle, got %+v", got)
	}
}

// The series is aligned to its step, so two reads of the same dashboard line
// up, and a point reports the worst moment inside it rather than an average.
func TestSeriesIsAlignedAndKeepsPeaks(t *testing.T) {
	h := newHarness()
	for i := 0; i < 10; i++ {
		pps := uint64(1_000)
		if i == 4 {
			pps = 250_000
		}
		h.Observe(report("node-a", "203.0.113.0/24", pipeline.PrefixStats{
			Offered: uint64(i+1) * 1_000, OfferedPPS: pps,
		}), Attribution{})
		h.advance(time.Minute)
	}

	points := h.Series("203.0.113.0/24", 10*time.Minute, 5*time.Minute)
	if len(points) < 2 {
		t.Fatalf("expected the window covered, got %d points", len(points))
	}
	for _, p := range points {
		if p.At.Unix()%int64((5*time.Minute).Seconds()) != 0 {
			t.Fatalf("point %v is not aligned to the step", p.At)
		}
	}
	var peak uint64
	for _, p := range points {
		if p.OfferedPPS > peak {
			peak = p.OfferedPPS
		}
	}
	if peak != 250_000 {
		t.Fatalf("expected the burst to survive aggregation, got %d", peak)
	}
}

// History for a prefix the fabric no longer protects is dropped rather than
// frozen at the numbers it had when the policy was withdrawn.
func TestForgetDropsWithdrawnPrefixes(t *testing.T) {
	h := newHarness()
	h.Observe(report("node-a", "203.0.113.0/24", pipeline.PrefixStats{Flows: 5}), Attribution{})
	h.Observe(report("node-a", "198.51.100.0/24", pipeline.PrefixStats{Flows: 5}), Attribution{})
	h.Forget(map[string]struct{}{"203.0.113.0/24": {}})

	if got := h.Prefixes(); len(got) != 1 || got[0] != "203.0.113.0/24" {
		t.Fatalf("expected only the still-protected prefix kept, got %v", got)
	}
}

// Per-node bookkeeping is reclaimed when a node stops reporting, so the
// delta state stays bounded by the live fleet.
func TestNodeStateIsReclaimed(t *testing.T) {
	h := newHarness()
	h.Observe(report("node-gone", "203.0.113.0/24", pipeline.PrefixStats{Flows: 5}), Attribution{})
	h.advance(11 * NodeFreshness)
	h.Observe(report("node-here", "203.0.113.0/24", pipeline.PrefixStats{Flows: 5}), Attribution{})

	h.mu.Lock()
	defer h.mu.Unlock()
	for key := range h.prefixCounters {
		if key.node == "node-gone" {
			t.Fatal("expected state for the departed node reclaimed")
		}
	}
	if _, ok := h.series["203.0.113.0/24"].gauges["node-gone"]; ok {
		t.Fatal("expected the departed node's gauge reclaimed")
	}
}

// The prefix table is bounded: it is reachable from node reports, and an
// unbounded one is a memory-exhaustion vector whatever its keys.
func TestPrefixTableIsBounded(t *testing.T) {
	h := newHarness()
	for i := 0; i < MaxPrefixes+50; i++ {
		prefix := time.Unix(int64(i), 0).String() + "/32"
		h.Observe(report("node-a", prefix, pipeline.PrefixStats{Flows: 1}), Attribution{})
	}
	if got := len(h.Prefixes()); got != MaxPrefixes {
		t.Fatalf("expected the table held at %d, got %d", MaxPrefixes, got)
	}
}
