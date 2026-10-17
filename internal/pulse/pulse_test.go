package pulse

import (
	"fmt"
	"testing"
	"time"
)

type harness struct {
	d     *Detector
	clock time.Time
}

func newHarness() *harness {
	h := &harness{clock: time.Unix(1_700_000_000, 0).UTC()}
	h.d = New()
	h.d.SetClock(func() time.Time { return h.clock })
	return h
}

func (h *harness) advance(d time.Duration) { h.clock = h.clock.Add(d) }

// burst sends one Resolution-length burst, then goes quiet for gap.
func (h *harness) burst(key string, pps uint64, gap time.Duration) {
	h.d.Observe(key, pps)
	h.advance(gap)
}

// steady sends pps every Resolution for d.
func (h *harness) steady(key string, pps uint64, d time.Duration) {
	for elapsed := time.Duration(0); elapsed < d; elapsed += Resolution {
		h.d.Observe(key, pps)
		h.advance(Resolution)
	}
}

// The attack this exists for: short heavy bursts on a repeating interval,
// whose average never crosses a volumetric threshold.
func TestBurstTrainIsRecognised(t *testing.T) {
	h := newHarness()
	for i := 0; i < 4; i++ {
		h.burst("203.0.113.0/24", 500_000, 10*time.Second)
	}
	got := h.d.Assess("203.0.113.0/24")
	if !got.Pulsing {
		t.Fatalf("expected a burst train to be recognised: %+v", got)
	}
	if got.Bursts < MinBursts {
		t.Fatalf("expected at least %d bursts, got %+v", MinBursts, got)
	}
	// The whole point: the mean is nowhere near the peak, so a mean-based
	// threshold would have seen nothing.
	if got.MeanPPS*4 > got.PeakPPS {
		t.Fatalf("this test is not exercising a low average: %+v", got)
	}
	if got.Crest < MinCrest {
		t.Fatalf("expected a high crest factor, got %+v", got)
	}
}

// Steady traffic is not a pulse, however heavy.
func TestSteadyTrafficIsNotAPulse(t *testing.T) {
	h := newHarness()
	h.steady("203.0.113.0/24", 900_000, Horizon)
	got := h.d.Assess("203.0.113.0/24")
	if got.Pulsing {
		t.Fatalf("heavy steady traffic was called a pulse: %+v", got)
	}
	if got.Crest > 1.5 {
		t.Fatalf("steady traffic should sit near a crest of one, got %+v", got)
	}
}

// A game server has busy moments. One burst is not an attack.
func TestASingleBurstIsNotAPulse(t *testing.T) {
	h := newHarness()
	h.steady("203.0.113.0/24", 1000, 5*time.Second)
	h.d.Observe("203.0.113.0/24", 400_000) // one spike: a map change, a join wave
	h.advance(Resolution)
	h.steady("203.0.113.0/24", 1000, 20*time.Second)

	if got := h.d.Assess("203.0.113.0/24"); got.Pulsing {
		t.Fatalf("a single burst was called a pulse train: %+v", got)
	}
}

// One long burst is one burst, not a train.
func TestOneLongBurstIsCountedOnce(t *testing.T) {
	h := newHarness()
	h.steady("203.0.113.0/24", 500_000, 10*time.Second)
	h.advance(20 * time.Second)
	got := h.d.Assess("203.0.113.0/24")
	if got.Bursts > 1 {
		t.Fatalf("a single continuous burst was counted as %d: %+v", got.Bursts, got)
	}
	if got.Pulsing {
		t.Fatalf("one long burst is not a train: %+v", got)
	}
}

// The property that defeats hit-and-run: the flag stands through the gaps,
// so nothing downstream disengages between bursts.
func TestTheFlagLatchesAcrossTheGaps(t *testing.T) {
	h := newHarness()
	for i := 0; i < 4; i++ {
		h.burst("203.0.113.0/24", 500_000, 10*time.Second)
	}
	if !h.d.Pulsing("203.0.113.0/24") {
		t.Fatal("expected the train to be recognised")
	}

	// Go completely quiet for longer than the horizon. A measurement would
	// now show nothing at all; the flag has to stand anyway.
	h.advance(Horizon + time.Second)
	got := h.d.Assess("203.0.113.0/24")
	if !got.Pulsing {
		t.Fatalf("the flag dropped during a gap, which is what the attack is for: %+v", got)
	}
	if got.HeldFor <= 0 {
		t.Fatalf("expected the hold to be reported, got %+v", got)
	}

	// It does eventually lapse, once the attack really has stopped.
	h.advance(Hold + time.Second)
	if h.d.Pulsing("203.0.113.0/24") {
		t.Fatal("the flag never lapsed")
	}
}

// Every burst pushes the lapse out, so an attacker cannot tune their
// interval to sit just past it.
func TestEachBurstExtendsTheHold(t *testing.T) {
	h := newHarness()
	for i := 0; i < 4; i++ {
		h.burst("203.0.113.0/24", 500_000, 10*time.Second)
	}
	first := h.d.Assess("203.0.113.0/24").HeldFor

	h.advance(Hold / 2)
	h.d.Observe("203.0.113.0/24", 500_000)
	again := h.d.Assess("203.0.113.0/24")
	if !again.Pulsing {
		t.Fatalf("expected the flag still up: %+v", again)
	}
	if again.HeldFor <= first-Hold/2 {
		t.Fatalf("a further burst did not push the lapse out: %v then %v", first, again.HeldFor)
	}
}

// Keys are judged separately: one customer under attack is not every
// customer under attack.
func TestKeysAreJudgedSeparately(t *testing.T) {
	h := newHarness()
	for i := 0; i < 4; i++ {
		h.d.Observe("203.0.113.0/24", 500_000)
		h.d.Observe("198.51.100.0/24", 200) // a trickle, well under the floor
		h.advance(10 * time.Second)
	}
	if !h.d.Pulsing("203.0.113.0/24") {
		t.Fatal("expected the attacked prefix flagged")
	}
	if h.d.Pulsing("198.51.100.0/24") {
		t.Fatal("a quiet prefix was flagged because its neighbour was attacked")
	}
}

func TestUnknownKeyIsQuiet(t *testing.T) {
	h := newHarness()
	if got := h.d.Assess("nobody"); got.Pulsing || got.PeakPPS != 0 {
		t.Fatalf("expected nothing for an unknown key, got %+v", got)
	}
}

// A bucket left behind by a quiet stretch must not be counted again when
// the ring wraps onto it.
func TestStaleBucketsAreNotRecounted(t *testing.T) {
	h := newHarness()
	h.d.Observe("k", 800_000)
	h.advance(Horizon + Resolution) // wrap the ring well past the horizon
	h.d.Observe("k", 1000)
	got := h.d.Assess("k")
	if got.PeakPPS != 1000 {
		t.Fatalf("a stale bucket was counted again: peak %d, expected 1000", got.PeakPPS)
	}
}

// The table is reachable from traffic, so it has to stay bounded.
func TestSeriesTableStaysBounded(t *testing.T) {
	h := newHarness()
	for i := 0; i < maxSeries+2000; i++ {
		h.d.Observe(fmt.Sprintf("key-%d", i), 10)
		if n, _ := h.d.Tracked(); n > maxSeries {
			t.Fatalf("the table grew past its bound: %d after %d keys", n, i+1)
		}
	}
}

// Keys that leave the policy are forgotten.
func TestForgetDropsKeysOutsideThePolicy(t *testing.T) {
	h := newHarness()
	h.d.Observe("a", 10)
	h.d.Observe("b", 10)
	h.d.Forget(map[string]struct{}{"a": {}})
	if n, _ := h.d.Tracked(); n != 1 {
		t.Fatalf("expected one key to survive, got %d", n)
	}
	if got := h.d.Assess("b"); got.PeakPPS != 0 {
		t.Fatalf("expected the dropped key forgotten, got %+v", got)
	}
}

func TestZeroValueDetectorDoesNotPanic(t *testing.T) {
	var d Detector
	d.Observe("k", 10)
	if got := d.Assess("k"); got.PeakPPS != 10 {
		t.Fatalf("expected a usable zero-value detector, got %+v", got)
	}
}

// The ring walk runs at most once per bucket, so a flood does not pay for
// it on every packet.
func BenchmarkObserve(b *testing.B) {
	d := New()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		d.Observe("203.0.113.0/24", 100)
	}
}

// Shape alone cannot decide: a sparse trickle has the same crest factor and
// duty cycle as an attack. The floor is what tells them apart.
func TestSparseTrickleIsNotAPulse(t *testing.T) {
	h := newHarness()
	for i := 0; i < 6; i++ {
		h.burst("203.0.113.0/24", 50, 8*time.Second) // sparse, but nothing
	}
	got := h.d.Assess("203.0.113.0/24")
	if got.Pulsing {
		t.Fatalf("a sparse trickle was called a pulse attack: %+v", got)
	}
	// It has the shape; it just has no magnitude.
	if got.Crest < MinCrest {
		t.Fatalf("this test is not exercising the floor: %+v", got)
	}
}

func TestTheFloorIsTunable(t *testing.T) {
	h := newHarness()
	h.d.SetFloor(100)
	for i := 0; i < 4; i++ {
		h.burst("203.0.113.0/24", 500, 10*time.Second)
	}
	if !h.d.Pulsing("203.0.113.0/24") {
		t.Fatalf("a deployment that set a low floor should see this: %+v", h.d.Assess("203.0.113.0/24"))
	}

	// The same traffic against the default floor is nothing.
	other := newHarness()
	for i := 0; i < 4; i++ {
		other.burst("203.0.113.0/24", 500, 10*time.Second)
	}
	if other.d.Pulsing("203.0.113.0/24") {
		t.Fatal("the default floor should not flag 500 pps bursts")
	}
}

// An attacker who stretches their interval past the horizon, hoping the
// hold lapses, keeps the flag up anyway: staying flagged asks less than
// becoming flagged did.
func TestStretchingTheIntervalDoesNotClearTheFlag(t *testing.T) {
	h := newHarness()
	for i := 0; i < 4; i++ {
		h.burst("203.0.113.0/24", 500_000, 10*time.Second)
	}
	if !h.d.Pulsing("203.0.113.0/24") {
		t.Fatal("expected the train recognised")
	}
	// Now one lone burst every couple of minutes: too few in any horizon to
	// re-trip the detector from cold.
	for i := 0; i < 4; i++ {
		h.advance(2 * time.Minute)
		h.d.Observe("203.0.113.0/24", 500_000)
		if !h.d.Pulsing("203.0.113.0/24") {
			t.Fatalf("round %d: stretching the interval cleared the flag", i)
		}
	}
	// Stopping really does clear it.
	h.advance(Hold + time.Minute)
	if h.d.Pulsing("203.0.113.0/24") {
		t.Fatal("the flag never lapsed after the attack stopped")
	}
}
