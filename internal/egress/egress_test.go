package egress

import (
	"fmt"
	"testing"
	"time"
)

type harness struct {
	*Tracker
	clock time.Time
}

func newHarness() *harness {
	h := &harness{Tracker: New(), clock: time.Unix(1_700_000_000, 0)}
	h.SetClock(func() time.Time { return h.clock })
	return h
}

func (h *harness) advance(d time.Duration) { h.clock = h.clock.Add(d) }

func (h *harness) ret(prefix, client string, packets int) bool {
	return h.Return(prefix, client, packets, h.clock)
}

func (h *harness) confirmed(prefix, client string) bool {
	return h.Confirmed(prefix, client, h.clock)
}

func (h *harness) visibility(prefix string) Visibility {
	return h.Visibility(prefix, h.clock)
}

const pfx = "203.0.113.0/24"

// A client the origin is talking to becomes confirmed, with no idea what
// protocol either of them is speaking.
func TestSustainedReturnTrafficConfirmsAClient(t *testing.T) {
	h := newHarness()
	if h.confirmed(pfx, "192.0.2.50") {
		t.Fatal("an unseen client should not be confirmed")
	}

	var promoted bool
	for i := 0; i < MinTicks; i++ {
		promoted = h.ret(pfx, "192.0.2.50", 4) || promoted
		h.advance(Tick)
	}
	if !promoted {
		t.Fatal("expected the client promoted once the traffic was sustained")
	}
	if !h.confirmed(pfx, "192.0.2.50") {
		t.Fatal("expected the client confirmed")
	}
	if got := h.Stats().Promotions; got != 1 {
		t.Fatalf("expected one promotion, got %d", got)
	}
}

// A burst of replies in one instant is what an origin sends when it is
// bouncing errors at a flood. A conversation is spread out, which is why the
// test is distinct ticks and not a packet count.
func TestABurstOfRepliesIsNotAConversation(t *testing.T) {
	h := newHarness()
	// Far more than MinPackets, all in the same tick.
	for i := 0; i < MinPackets*5; i++ {
		if h.ret(pfx, "192.0.2.50", 1) {
			t.Fatal("a single burst confirmed a client")
		}
	}
	if h.confirmed(pfx, "192.0.2.50") {
		t.Fatal("a single burst confirmed a client")
	}

	// Spread the same traffic out and it counts.
	for i := 0; i < MinTicks; i++ {
		h.advance(Tick)
		h.ret(pfx, "192.0.2.50", MinPackets)
	}
	if !h.confirmed(pfx, "192.0.2.50") {
		t.Fatal("sustained traffic should confirm")
	}
}

// A trickle of replies spread thin is not a conversation either.
func TestTooFewPacketsIsNotConfirmation(t *testing.T) {
	h := newHarness()
	for i := 0; i < MinTicks+2; i++ {
		h.ret(pfx, "192.0.2.50", 1)
		h.advance(Tick)
	}
	if h.confirmed(pfx, "192.0.2.50") {
		t.Fatalf("expected %d packets to be too few", MinTicks+2)
	}
}

// Confirmation stands through a pause and then lapses. A paused client is
// still a client; an address silent for longer has probably changed hands.
func TestConfirmationOutlivesAPauseThenLapses(t *testing.T) {
	h := newHarness()
	for i := 0; i < MinTicks; i++ {
		h.ret(pfx, "192.0.2.50", MinPackets)
		h.advance(Tick)
	}
	if !h.confirmed(pfx, "192.0.2.50") {
		t.Fatal("expected confirmation")
	}
	h.advance(ConfirmTTL / 2)
	if !h.confirmed(pfx, "192.0.2.50") {
		t.Fatal("confirmation should outlive a pause")
	}
	h.advance(ConfirmTTL)
	if h.confirmed(pfx, "192.0.2.50") {
		t.Fatal("confirmation outlived its TTL")
	}
}

// Confirmation is per prefix. The origin for one customer vouching for a
// client says nothing about another customer's service.
func TestConfirmationIsPerPrefix(t *testing.T) {
	h := newHarness()
	for i := 0; i < MinTicks; i++ {
		h.ret(pfx, "192.0.2.50", MinPackets)
		h.advance(Tick)
	}
	if !h.confirmed(pfx, "192.0.2.50") {
		t.Fatal("expected confirmation on the prefix that saw the traffic")
	}
	if h.confirmed("198.51.100.0/24", "192.0.2.50") {
		t.Fatal("confirmation leaked to another customer's prefix")
	}
}

// With direct server return there is no egress to watch. Reading that as
// "no client is confirmed" would cap every real player on the service, so
// the prefix is recognised as asymmetric instead.
func TestIngressWithoutEgressReadsAsAsymmetric(t *testing.T) {
	h := newHarness()
	if got := h.visibility(pfx); got != Unknown {
		t.Fatalf("an untouched prefix should be unknown, got %v", got)
	}

	h.Ingress(pfx, h.clock)
	if got := h.visibility(pfx); got != Asymmetric {
		t.Fatalf("ingress with no egress should read asymmetric, got %v", got)
	}

	h.ret(pfx, "192.0.2.50", 1)
	if got := h.visibility(pfx); got != Visible {
		t.Fatalf("once return traffic appears the path is visible, got %v", got)
	}

	// And it goes back to asymmetric if the return path disappears while
	// ingress keeps arriving — a route change mid-attack, say.
	h.advance(VisibilityWindow + time.Second)
	h.Ingress(pfx, h.clock)
	if got := h.visibility(pfx); got != Asymmetric {
		t.Fatalf("a return path that went away should read asymmetric, got %v", got)
	}
}

// An idle prefix is not asymmetric: with no traffic in either direction
// there is nothing to conclude.
func TestAnIdlePrefixIsNotAsymmetric(t *testing.T) {
	h := newHarness()
	h.Ingress(pfx, h.clock)
	h.advance(VisibilityWindow + time.Second)
	if got := h.visibility(pfx); got != Unknown {
		t.Fatalf("an idle prefix should be unknown, got %v", got)
	}
}

// The client table is bounded, and at the bound a client is simply not
// confirmed — it loses the fast path and nothing else.
func TestClientTableIsBounded(t *testing.T) {
	h := newHarness()
	for i := 0; i < MaxClients+2000; i++ {
		h.ret(pfx, fmt.Sprintf("10.%d.%d.%d", i>>16&0xff, i>>8&0xff, i&0xff), 1)
	}
	if got := h.Stats().Clients; got > MaxClients {
		t.Fatalf("the table grew past its bound: %d", got)
	}
	if h.Stats().Full == 0 {
		t.Fatal("expected the refusals counted")
	}
}

// Prefixes the node no longer carries are dropped, and their clients with
// them.
func TestForgetDropsWithdrawnPrefixes(t *testing.T) {
	h := newHarness()
	h.ret(pfx, "192.0.2.50", 1)
	h.ret("198.51.100.0/24", "192.0.2.51", 1)
	if got := h.Stats().Clients; got != 2 {
		t.Fatalf("expected two clients tracked, got %d", got)
	}

	h.Forget(map[string]struct{}{pfx: {}})
	s := h.Stats()
	if s.Prefixes != 1 || s.Clients != 1 {
		t.Fatalf("expected the withdrawn prefix and its clients dropped, got %+v", s)
	}
}

// Clients with nothing left to say are reclaimed, so a churn of one-off
// addresses does not hold the table at its bound.
func TestSpentClientsAreReclaimed(t *testing.T) {
	h := newHarness()
	for i := 0; i < 500; i++ {
		h.ret(pfx, fmt.Sprintf("10.0.%d.%d", i>>8, i&0xff), 1)
	}
	h.advance(ConfirmWindow + ConfirmTTL + time.Hour)
	h.ret(pfx, "192.0.2.99", 1)
	if got := h.Stats().Clients; got > 2 {
		t.Fatalf("expected spent clients reclaimed, got %d", got)
	}
}

// Lockdown without a grace window is a trap with no exit: a new client is
// unconfirmed, so it is held back, so its packets never reach the origin, so
// the origin never answers, so it is never confirmed.
func TestANewSourceGetsAGraceWindow(t *testing.T) {
	h := newHarness()
	if !h.InGrace(pfx, "192.0.2.50", DefaultGrace, h.clock) {
		t.Fatal("a source seen for the first time should be inside its grace")
	}
	h.advance(DefaultGrace / 2)
	if !h.InGrace(pfx, "192.0.2.50", DefaultGrace, h.clock) {
		t.Fatal("the grace ended early")
	}
	h.advance(DefaultGrace)
	if h.InGrace(pfx, "192.0.2.50", DefaultGrace, h.clock) {
		t.Fatal("the grace outlived its window")
	}
}

// The grace runs from when the source was first seen, not from the last
// packet — otherwise a flood renews its own grace forever by continuing.
func TestGraceDoesNotRenewItself(t *testing.T) {
	h := newHarness()
	for i := 0; i < 20; i++ {
		h.InGrace(pfx, "198.51.100.9", DefaultGrace, h.clock)
		h.advance(DefaultGrace / 4)
	}
	if h.InGrace(pfx, "198.51.100.9", DefaultGrace, h.clock) {
		t.Fatal("a source that kept sending renewed its own grace")
	}
}

// With the table full a source gets no grace: during the flood that filled
// it, strict is the posture lockdown exists for.
func TestGraceIsRefusedWhenTheTableIsFull(t *testing.T) {
	h := newHarness()
	for i := 0; i < MaxClients; i++ {
		h.ret(pfx, fmt.Sprintf("10.%d.%d.%d", i>>16&0xff, i>>8&0xff, i&0xff), 1)
	}
	if h.InGrace(pfx, "192.0.2.77", DefaultGrace, h.clock) {
		t.Fatal("a full table still handed out grace")
	}
}
