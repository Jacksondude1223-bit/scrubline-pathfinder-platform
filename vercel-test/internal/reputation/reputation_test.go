package reputation

import (
	"fmt"
	"testing"
	"time"
)

type harness struct {
	*Cache
	clock time.Time
}

func newHarness(cfg Config) *harness {
	h := &harness{Cache: New(), clock: time.Unix(1_700_000_000, 0)}
	h.SetClock(func() time.Time { return h.clock })
	h.Configure(cfg)
	return h
}

func (h *harness) advance(d time.Duration) { h.clock = h.clock.Add(d) }

func (h *harness) check(src string) State { return h.Cache.Check(src, h.clock) }

func (h *harness) strike(src string) bool { return h.Cache.Strike(src, h.clock) }

func (h *harness) promote(src string, p Proof) { h.Cache.Promote(src, p, h.clock) }

func boxing() Config { return Config{Boxing: true, FastPassProof: ProofChallenge} }

// A source that answered a challenge is fast-passed until its trust lapses.
func TestChallengeVerifiedSourceIsFastPassed(t *testing.T) {
	h := newHarness(boxing())
	if got := h.check("192.0.2.5"); got != Unknown {
		t.Fatalf("an unseen source should be unknown, got %v", got)
	}
	h.promote("192.0.2.5", ProofChallenge)
	if got := h.check("192.0.2.5"); got != Trusted {
		t.Fatalf("expected the verified source trusted, got %v", got)
	}

	h.advance(TrustTTL + time.Second)
	if got := h.check("192.0.2.5"); got != Trusted {
		t.Logf("state after TTL: %v", got)
	}
	if got := h.check("192.0.2.5"); got == Trusted {
		t.Fatal("trust outlived its TTL")
	}
}

// Completing a handshake can be done blind, so by default it does not earn a
// fast pass — a spoofer could clear it for any address. An operator can widen
// that deliberately.
func TestHandshakeAloneDoesNotFastPassByDefault(t *testing.T) {
	h := newHarness(boxing())
	h.promote("192.0.2.5", ProofHandshake)
	if got := h.check("192.0.2.5"); got != Unknown {
		t.Fatalf("a handshake should not fast-pass by default, got %v", got)
	}

	wide := newHarness(Config{Boxing: true, FastPassProof: ProofHandshake})
	wide.promote("192.0.2.5", ProofHandshake)
	if got := wide.check("192.0.2.5"); got != Trusted {
		t.Fatalf("an operator who opted in should get the fast pass, got %v", got)
	}
}

// One bad packet is ordinary. Boxing on it would turn every false positive
// into a minutes-long outage for that source.
func TestOneStrikeIsNotAPenalty(t *testing.T) {
	h := newHarness(boxing())
	for i := 0; i < StrikesToBox-1; i++ {
		if h.strike("198.51.100.9") {
			t.Fatalf("boxed after %d strikes, before the threshold", i+1)
		}
		if got := h.check("198.51.100.9"); got == Penalised {
			t.Fatalf("penalised after %d strikes", i+1)
		}
	}
	if !h.strike("198.51.100.9") {
		t.Fatalf("expected the box after %d strikes", StrikesToBox)
	}
	if got := h.check("198.51.100.9"); got != Penalised {
		t.Fatalf("expected the source boxed, got %v", got)
	}
}

// Strikes lapse. Four failures in half a minute is behaviour; four in a day
// is noise.
func TestStrikesLapseOutsideTheWindow(t *testing.T) {
	h := newHarness(boxing())
	for i := 0; i < StrikesToBox-1; i++ {
		h.strike("198.51.100.9")
	}
	h.advance(StrikeWindow + time.Second)
	if h.strike("198.51.100.9") {
		t.Fatal("strikes from an expired window counted toward the box")
	}
	if got := h.check("198.51.100.9"); got == Penalised {
		t.Fatal("a source was boxed on lapsed strikes")
	}
}

// This is the one that matters. Source addresses in a flood are written by
// the attacker, so if a stateless signal could box a trusted source, anyone
// could get a real player banned by spoofing their address.
func TestATrustedSourceCannotBeBoxedBySpoofedTraffic(t *testing.T) {
	h := newHarness(boxing())
	h.promote("192.0.2.5", ProofChallenge)

	// An attacker floods, claiming to be the player.
	for i := 0; i < StrikesToBox*5; i++ {
		if h.strike("192.0.2.5") {
			t.Fatal("a trusted source was boxed by traffic claiming its address")
		}
	}
	if got := h.check("192.0.2.5"); got != Trusted {
		t.Fatalf("the real player lost its fast pass to a spoofer, got %v", got)
	}
	// It is counted, though: an operator should be able to see this happening.
	if got := h.Stats().Shielded; got != uint64(StrikesToBox*5) {
		t.Fatalf("expected the shielded strikes counted, got %d", got)
	}
}

// The penalty lengthens with repetition and decays with good behaviour.
func TestPenaltyEscalatesAndDecays(t *testing.T) {
	h := newHarness(boxing())
	box := func() time.Duration {
		for i := 0; i < StrikesToBox; i++ {
			h.strike("198.51.100.9")
		}
		e := h.entries["198.51.100.9"]
		return e.penalisedUntil.Sub(h.clock)
	}

	first := box()
	if first != time.Minute {
		t.Fatalf("expected a one-minute first penalty, got %s", first)
	}
	h.advance(first + time.Second)
	second := box()
	if second != 10*time.Minute {
		t.Fatalf("expected ten minutes on the second, got %s", second)
	}
	h.advance(second + time.Second)
	third := box()
	if third != time.Hour {
		t.Fatalf("expected an hour on the third, got %s", third)
	}
	h.advance(third + time.Second)
	if fourth := box(); fourth != time.Hour {
		t.Fatalf("expected the ladder to stop at an hour, got %s", fourth)
	}

	// Behave for long enough and the ladder comes back down, so a source
	// that misbehaved once last week does not start at the top.
	h.advance(3 * EscalationDecay)
	if got := box(); got != time.Minute {
		t.Fatalf("expected escalation to decay back to a minute, got %s", got)
	}
}

// Clearing a gate wipes the strikes accumulated getting there, so a client
// that fumbles its opening packets and then connects properly is not still
// carrying them.
func TestClearingAGateForgivesTheStrikesBefore(t *testing.T) {
	h := newHarness(boxing())
	for i := 0; i < StrikesToBox-1; i++ {
		h.strike("192.0.2.5")
	}
	h.promote("192.0.2.5", ProofChallenge)
	if got := h.entries["192.0.2.5"].strikes; got != 0 {
		t.Fatalf("expected the earlier strikes cleared, got %d", got)
	}
}

// Clearing a gate does not clear a penalty. A boxed source is dropped at the
// top of the pipeline and never reaches a gate, so promoting itself out
// would be a path that does not exist — and if it did, serving a penalty
// would be optional. Release is the way out, and an operator makes it.
func TestABoxedSourceCannotPromoteItselfOut(t *testing.T) {
	h := newHarness(boxing())
	for i := 0; i < StrikesToBox; i++ {
		h.strike("198.51.100.9")
	}
	if got := h.check("198.51.100.9"); got != Penalised {
		t.Fatalf("expected the source boxed, got %v", got)
	}

	h.promote("198.51.100.9", ProofChallenge)
	if got := h.check("198.51.100.9"); got != Penalised {
		t.Fatalf("a boxed source promoted itself out of the box, got %v", got)
	}
}

// Boxing off records everything and drops nothing, which is how this is
// rolled out in front of real customers.
func TestObserveModeRecordsWithoutDropping(t *testing.T) {
	h := newHarness(Config{Boxing: false, FastPassProof: ProofChallenge})
	for i := 0; i < StrikesToBox; i++ {
		if h.strike("198.51.100.9") {
			t.Fatal("observe mode reported a drop")
		}
	}
	if got := h.check("198.51.100.9"); got == Penalised {
		t.Fatal("observe mode penalised a source")
	}
	// But the operator can still see what it would have done.
	if got := h.Stats().Demotions; got != 1 {
		t.Fatalf("expected the demotion recorded, got %d", got)
	}
}

// The table is keyed by the one field an attacker can vary without limit, so
// the bound is what stops the cache becoming the exhaustion vector it exists
// to prevent. At the bound a source takes the ordinary path: lost
// optimisation, never lost protection.
func TestTableIsBounded(t *testing.T) {
	h := newHarness(boxing())
	for i := 0; i < MaxTracked+5000; i++ {
		h.promote(fmt.Sprintf("10.%d.%d.%d", i>>16&0xff, i>>8&0xff, i&0xff), ProofChallenge)
	}
	if got := len(h.entries); got > MaxTracked {
		t.Fatalf("the table grew past its bound: %d", got)
	}
	if h.Stats().Full == 0 {
		t.Fatal("expected the refusals to be counted")
	}
}

// Expired entries are reclaimed, so a flood of one-off sources does not hold
// the table at its bound forever.
func TestExpiredEntriesAreReclaimed(t *testing.T) {
	h := newHarness(boxing())
	for i := 0; i < 1000; i++ {
		h.promote(fmt.Sprintf("10.0.%d.%d", i>>8, i&0xff), ProofChallenge)
	}
	h.advance(TrustTTL + EscalationDecay + time.Hour)
	// A sweep runs on the next insertion that needs room.
	h.Cache.sweep(h.clock)
	if got := len(h.entries); got != 0 {
		t.Fatalf("expected spent entries reclaimed, got %d", got)
	}
}

// A source cannot shed its escalation by waiting out the shortest penalty:
// the level outlives the box.
func TestEscalationOutlivesThePenalty(t *testing.T) {
	h := newHarness(boxing())
	for i := 0; i < StrikesToBox; i++ {
		h.strike("198.51.100.9")
	}
	h.advance(2 * time.Minute) // past the one-minute box, well inside decay
	h.Cache.sweep(h.clock)
	if _, ok := h.entries["198.51.100.9"]; !ok {
		t.Fatal("the escalation level was reclaimed with the penalty")
	}
	for i := 0; i < StrikesToBox; i++ {
		h.strike("198.51.100.9")
	}
	if got := h.entries["198.51.100.9"].penalisedUntil.Sub(h.clock); got != 10*time.Minute {
		t.Fatalf("expected the second penalty to be longer, got %s", got)
	}
}

// An operator can forgive a false positive without resetting the ladder.
func TestReleaseFreesASourceButKeepsItsHistory(t *testing.T) {
	h := newHarness(boxing())
	for i := 0; i < StrikesToBox; i++ {
		h.strike("198.51.100.9")
	}
	if !h.Release("198.51.100.9") {
		t.Fatal("expected the release to take")
	}
	if got := h.check("198.51.100.9"); got == Penalised {
		t.Fatal("the source is still boxed after release")
	}
	if got := h.entries["198.51.100.9"].level; got == 0 {
		t.Fatal("releasing reset the escalation level; the next offence should not start from scratch")
	}
	if h.Release("203.0.113.1") {
		t.Fatal("releasing an unknown source reported success")
	}
}

// The two tiers are separate decisions: a deployment can shed known-bad
// traffic early without short-cutting anything, or the reverse.
func TestTheTiersAreIndependent(t *testing.T) {
	noFast := newHarness(Config{Boxing: true, NoFastPass: true, FastPassProof: ProofChallenge})
	noFast.promote("192.0.2.5", ProofChallenge)
	if got := noFast.check("192.0.2.5"); got == Trusted {
		t.Fatal("the fast pass was off but a source still took it")
	}
	for i := 0; i < StrikesToBox; i++ {
		noFast.strike("198.51.100.9")
	}
	if got := noFast.check("198.51.100.9"); got != Penalised {
		t.Fatalf("the penalty box should still work with the fast pass off, got %v", got)
	}

	noBox := newHarness(Config{Boxing: false, FastPassProof: ProofChallenge})
	noBox.promote("192.0.2.5", ProofChallenge)
	if got := noBox.check("192.0.2.5"); got != Trusted {
		t.Fatalf("the fast pass should still work with boxing off, got %v", got)
	}
}
