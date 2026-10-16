package steering

import (
	"testing"
	"time"
)

type harness struct {
	c     *Controller
	clock time.Time
}

func newHarness() *harness {
	h := &harness{clock: time.Unix(1_700_000_000, 0).UTC()}
	h.c = New()
	h.c.SetClock(func() time.Time { return h.clock })
	return h
}

func (h *harness) advance(d time.Duration) { h.clock = h.clock.Add(d) }

// observe runs one round at the given load ratio and returns the node's padding.
func (h *harness) observe(ratio float64) int {
	const capacity = 1_000_000
	return h.c.Observe([]Sample{{
		NodeID: "n1", CapacityPPS: capacity, Fresh: true,
		OfferedPPS: uint64(ratio * capacity),
	}})["n1"]
}

// settle runs rounds far enough apart that dwell never blocks a change.
func (h *harness) settle(ratio float64, rounds int) int {
	got := 0
	for i := 0; i < rounds; i++ {
		got = h.observe(ratio)
		h.advance(MinDwell)
	}
	return got
}

func TestSaturatedNodeIsPaddedOneStepAtATime(t *testing.T) {
	h := newHarness()
	if got := h.observe(0.95); got != 1 {
		t.Fatalf("first round over the mark should add one prepend, got %d", got)
	}
	h.advance(MinDwell)
	if got := h.observe(0.95); got != 2 {
		t.Fatalf("second round should add another, got %d", got)
	}
}

// Shedding is bounded. A node at the cap keeps scrubbing what reaches it.
func TestEscalationIsBounded(t *testing.T) {
	h := newHarness()
	if got := h.settle(0.99, 10); got != MaxEscalation {
		t.Fatalf("expected padding clamped to %d, got %d", MaxEscalation, got)
	}
}

// Withdrawing a saturated node would dump its whole share on its neighbours
// and can cascade. Load may pad a node; only death withdraws one.
func TestLoadNeverWithdrawsANode(t *testing.T) {
	h := newHarness()
	for i := 0; i < 20; i++ {
		if got := h.observe(5.0); got > MaxEscalation {
			t.Fatalf("load padded past the cap: %d", got)
		}
		h.advance(MinDwell)
	}
}

func TestRecoveryUnwindsThePadding(t *testing.T) {
	h := newHarness()
	if got := h.settle(0.99, 5); got != MaxEscalation {
		t.Fatalf("expected a saturated node fully padded, got %d", got)
	}
	if got := h.settle(0.10, 5); got != 0 {
		t.Fatalf("expected the padding to unwind once load fell, got %d", got)
	}
}

// The band between the watermarks is the whole point: a node sitting between
// them must not move, however many rounds pass.
func TestLoadInsideTheBandDoesNotMove(t *testing.T) {
	h := newHarness()
	h.settle(0.99, 2) // pad it first, so a change in either direction is visible
	before := h.observe(0.65)
	h.advance(MinDwell)
	for i := 0; i < 10; i++ {
		if got := h.observe(0.65); got != before {
			t.Fatalf("round %d: padding moved inside the hysteresis band: %d then %d", i, before, got)
		}
		h.advance(MinDwell)
	}
}

// Load crossing a watermark repeatedly must not become a stream of BGP
// updates. A level holds for MinDwell whatever the load does.
func TestFlappingLoadCannotFlapTheAnnouncement(t *testing.T) {
	h := newHarness()
	first := h.observe(0.99)
	changes := 0
	last := first
	for i := 0; i < 200; i++ {
		ratio := 0.99
		if i%2 == 0 {
			ratio = 0.05
		}
		got := h.observe(ratio)
		if got != last {
			changes++
			last = got
		}
		h.advance(time.Second)
	}
	// 200 seconds of alternating load, with a 30s dwell, cannot produce more
	// than one change per dwell window.
	if maxChanges := int(200*time.Second/MinDwell) + 1; changes > maxChanges {
		t.Fatalf("padding changed %d times in 200s; dwell should cap it at %d", changes, maxChanges)
	}
}

func TestDwellBlocksAChangeUntilItElapses(t *testing.T) {
	h := newHarness()
	if got := h.observe(0.99); got != 1 {
		t.Fatalf("expected the first escalation, got %d", got)
	}
	h.advance(MinDwell - time.Second)
	if got := h.observe(0.99); got != 1 {
		t.Fatalf("expected the level held inside the dwell window, got %d", got)
	}
	h.advance(2 * time.Second)
	if got := h.observe(0.99); got != 2 {
		t.Fatalf("expected the level to move once dwell elapsed, got %d", got)
	}
}

// A node that does not know its own packet ceiling cannot be measured, so it
// is left alone rather than guessed at.
func TestNodeWithoutAPacketCeilingIsNeverPadded(t *testing.T) {
	c := New()
	for i := 0; i < 10; i++ {
		got := c.Observe([]Sample{{NodeID: "n1", OfferedPPS: 9_000_000, CapacityPPS: 0, Fresh: true}})
		if got["n1"] != 0 {
			t.Fatalf("a node with no declared ceiling was padded: %d", got["n1"])
		}
	}
	if reason := c.Levels()["n1"].Reason; reason == "" {
		t.Fatal("the controller should say why it is holding")
	}
}

// Acting on a measurement that stopped arriving is worse than not acting.
func TestStaleCountersHoldTheLevel(t *testing.T) {
	h := newHarness()
	h.settle(0.99, 2)
	before := h.c.Levels()["n1"].Prepends
	if before == 0 {
		t.Fatal("expected the node padded before going quiet")
	}
	for i := 0; i < 10; i++ {
		got := h.c.Observe([]Sample{{NodeID: "n1", CapacityPPS: 1_000_000, OfferedPPS: 0, Fresh: false}})
		if got["n1"] != before {
			t.Fatalf("a stale report moved the level: %d then %d", before, got["n1"])
		}
		h.advance(MinDwell)
	}
}

// Nodes that leave the fleet must not stay in the table forever.
func TestLevelsAreForgottenWhenANodeLeaves(t *testing.T) {
	c := New()
	c.Observe([]Sample{{NodeID: "a", Fresh: true, CapacityPPS: 10}, {NodeID: "b", Fresh: true, CapacityPPS: 10}})
	c.Observe([]Sample{{NodeID: "a", Fresh: true, CapacityPPS: 10}})
	levels := c.Levels()
	if _, ok := levels["b"]; ok {
		t.Fatalf("a departed node is still tracked: %+v", levels)
	}
	if _, ok := levels["a"]; !ok {
		t.Fatal("the remaining node was forgotten")
	}
}

// Each node is judged on its own load.
func TestNodesAreSteeredIndependently(t *testing.T) {
	c := New()
	got := c.Observe([]Sample{
		{NodeID: "hot", CapacityPPS: 1000, OfferedPPS: 950, Fresh: true},
		{NodeID: "cold", CapacityPPS: 1000, OfferedPPS: 50, Fresh: true},
	})
	if got["hot"] != 1 {
		t.Fatalf("the saturated node should shed, got %d", got["hot"])
	}
	if got["cold"] != 0 {
		t.Fatalf("the idle node should not be padded, got %d", got["cold"])
	}
}

func TestZeroValueControllerDoesNotPanic(t *testing.T) {
	var c Controller
	if got := c.Observe([]Sample{{NodeID: "n1", CapacityPPS: 10, OfferedPPS: 9, Fresh: true}}); got["n1"] != 1 {
		t.Fatalf("expected a usable zero-value controller, got %d", got["n1"])
	}
}
