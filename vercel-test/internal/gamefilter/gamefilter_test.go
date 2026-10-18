package gamefilter

import (
	"bytes"
	"fmt"
	"net/netip"
	"testing"
	"time"
)

var raknetMagic = []byte{0x00, 0xff, 0xff, 0x00, 0xfe, 0xfe, 0xfe, 0xfe, 0xfd, 0xfd, 0xfd, 0xfd, 0x12, 0x34, 0x56, 0x78}

func bindTo(profile string, observe bool) Binding {
	p, ok := Builtin(profile)
	if !ok {
		panic("unknown builtin " + profile)
	}
	return Binding{
		ID: "gf-1", Dst: netip.MustParsePrefix("203.0.113.0/24"), HasDst: true,
		Proto: "udp", DPort: 19132, Profile: p, Observe: observe,
	}
}

func newEngine(t *testing.T, b Binding) (*Engine, func(time.Duration)) {
	t.Helper()
	e := New([]Binding{b}, []byte("fabric-secret"))
	clock := time.Unix(1_700_000_000, 0).UTC()
	e.SetClock(func() time.Time { return clock })
	return e, func(d time.Duration) { clock = clock.Add(d) }
}

func flow(payload []byte) Flow {
	return Flow{
		SrcIP: "192.0.2.50", DstIP: "203.0.113.10", Proto: "udp", DPort: 19132,
		Payload: payload, HasPayload: true,
	}
}

// Junk aimed at a game port is the whole point: right port, nothing else
// right.
func TestJunkOnAGamePortIsDropped(t *testing.T) {
	e, _ := newEngine(t, bindTo("raknet", false))
	got := e.Inspect(flow(bytes.Repeat([]byte{0x41}, 1200)))
	if got.Verdict != VerdictDrop {
		t.Fatalf("expected a flood packet dropped, got %+v", got)
	}
	if got.Reason == "" || got.FilterID != "gf-1" {
		t.Fatalf("a drop must say which binding and why: %+v", got)
	}
}

// A source has to complete the protocol's own opening sequence before it can
// send gameplay volume.
func TestRaknetHandshakeGate(t *testing.T) {
	e, _ := newEngine(t, bindTo("raknet", false))

	// A connected datagram from a source that never connected.
	if got := e.Inspect(flow([]byte{0x84, 0x01, 0x02, 0x03})); got.Verdict != VerdictDrop {
		t.Fatalf("expected gameplay from an unconnected source to drop, got %+v", got)
	}
	// Opening the connection is allowed.
	open1 := append([]byte{0x05}, raknetMagic...)
	if got := e.Inspect(flow(open1)); got.Verdict != VerdictPass {
		t.Fatalf("expected the opening packet to pass, got %+v", got)
	}
	// Still not admitted for bulk traffic.
	if got := e.Inspect(flow([]byte{0x84, 0x01, 0x02, 0x03})); got.Verdict != VerdictDrop {
		t.Fatalf("a half-finished handshake must not admit a source, got %+v", got)
	}
	// Completing it does admit.
	open2 := append([]byte{0x07}, raknetMagic...)
	if got := e.Inspect(flow(open2)); got.Verdict != VerdictPass {
		t.Fatalf("expected the completing packet to pass, got %+v", got)
	}
	if got := e.Inspect(flow([]byte{0x84, 0x01, 0x02, 0x03})); got.Verdict != VerdictPass {
		t.Fatalf("expected a connected source to send gameplay, got %+v", got)
	}
}

// A2S has a real challenge, which is what lets the filter gate it without
// touching the client.
func TestA2SChallengeAndEcho(t *testing.T) {
	b := bindTo("a2s", false)
	b.DPort = 27015
	e, _ := newEngine(t, b)

	query := func(payload []byte) Flow {
		f := flow(payload)
		f.DPort = 27015
		return f
	}
	info := []byte{0xFF, 0xFF, 0xFF, 0xFF, 'U'}
	first := e.Inspect(query(info))
	if first.Verdict != VerdictChallenge {
		t.Fatalf("expected an unverified query to be challenged, got %+v", first)
	}
	if len(first.Reply) != 9 {
		t.Fatalf("expected a 5-byte header plus a 4-byte cookie, got %d bytes", len(first.Reply))
	}
	if !bytes.Equal(first.Reply[:5], []byte{0xFF, 0xFF, 0xFF, 0xFF, 'A'}) {
		t.Fatalf("the reply is not an A2S challenge: %x", first.Reply)
	}

	// Echoing the cookie back admits the source.
	cookie := first.Reply[5:]
	echoed := append(append([]byte{}, info...), cookie...)
	if got := e.Inspect(query(echoed)); got.Verdict != VerdictPass {
		t.Fatalf("expected the echoed challenge to admit the source, got %+v", got)
	}
	// And it stays admitted.
	if got := e.Inspect(query(info)); got.Verdict != VerdictPass {
		t.Fatalf("expected an admitted source to keep querying, got %+v", got)
	}
}

// A spoofed source cannot guess the cookie, which is what the gate is for.
func TestWrongCookieIsChallengedAgainNotAdmitted(t *testing.T) {
	b := bindTo("a2s", false)
	b.DPort = 27015
	e, _ := newEngine(t, b)
	f := flow(append([]byte{0xFF, 0xFF, 0xFF, 0xFF, 'U'}, 0xDE, 0xAD, 0xBE, 0xEF))
	f.DPort = 27015
	for i := 0; i < 5; i++ {
		if got := e.Inspect(f); got.Verdict != VerdictChallenge {
			t.Fatalf("a guessed cookie must not admit a source, got %+v", got)
		}
	}
}

// Two sources must not share a cookie, or one spoofer harvests a cookie and
// hands it to the whole flood.
func TestCookiesAreBoundToTheSource(t *testing.T) {
	b := bindTo("a2s", false)
	b.DPort = 27015
	e, _ := newEngine(t, b)
	info := []byte{0xFF, 0xFF, 0xFF, 0xFF, 'U'}

	mk := func(src string) Flow {
		f := flow(info)
		f.SrcIP, f.DPort = src, 27015
		return f
	}
	a := e.Inspect(mk("192.0.2.1"))
	c := e.Inspect(mk("192.0.2.2"))
	if bytes.Equal(a.Reply[5:], c.Reply[5:]) {
		t.Fatal("two sources were issued the same cookie")
	}
	// Replaying A's cookie from C's address does not work.
	stolen := mk("192.0.2.2")
	stolen.Payload = append(append([]byte{}, info...), a.Reply[5:]...)
	if got := e.Inspect(stolen); got.Verdict != VerdictChallenge {
		t.Fatalf("a cookie minted for another source was accepted: %+v", got)
	}
}

// Under anycast a source's packets land on different scrubbers, so a cookie
// minted by one has to verify on another.
func TestCookiesVerifyAcrossNodes(t *testing.T) {
	b := bindTo("a2s", false)
	b.DPort = 27015
	nodeA, _ := newEngine(t, b)
	nodeB, _ := newEngine(t, b) // same secret, same clock

	info := []byte{0xFF, 0xFF, 0xFF, 0xFF, 'U'}
	f := flow(info)
	f.DPort = 27015
	challenged := nodeA.Inspect(f)
	if challenged.Verdict != VerdictChallenge {
		t.Fatalf("expected a challenge from the first node, got %+v", challenged)
	}
	echoed := flow(append(append([]byte{}, info...), challenged.Reply[5:]...))
	echoed.DPort = 27015
	if got := nodeB.Inspect(echoed); got.Verdict != VerdictPass {
		t.Fatalf("a cookie from one node was refused by another: %+v", got)
	}
}

// A client that answers a moment after the cookie rotates must not be
// refused.
func TestThePreviousEpochCookieIsStillAccepted(t *testing.T) {
	b := bindTo("a2s", false)
	b.DPort = 27015
	e, advance := newEngine(t, b)
	info := []byte{0xFF, 0xFF, 0xFF, 0xFF, 'U'}
	f := flow(info)
	f.DPort = 27015

	challenged := e.Inspect(f)
	advance(cookieEpoch + time.Second) // the cookie has rotated
	echoed := flow(append(append([]byte{}, info...), challenged.Reply[5:]...))
	echoed.DPort = 27015
	if got := e.Inspect(echoed); got.Verdict != VerdictPass {
		t.Fatalf("a cookie one epoch old should still be accepted, got %+v", got)
	}
	// Two epochs on it is gone.
	e2, advance2 := newEngine(t, b)
	c2 := e2.Inspect(f)
	advance2(3 * cookieEpoch)
	stale := flow(append(append([]byte{}, info...), c2.Reply[5:]...))
	stale.DPort = 27015
	if got := e2.Inspect(stale); got.Verdict != VerdictChallenge {
		t.Fatalf("a long-expired cookie should be challenged again, got %+v", got)
	}
}

// The filter only looks at traffic an operator bound it to.
func TestTrafficOutsideTheBindingIsUntouched(t *testing.T) {
	e, _ := newEngine(t, bindTo("raknet", false))
	for _, tc := range []struct {
		name string
		mut  func(*Flow)
	}{
		{"another port", func(f *Flow) { f.DPort = 443 }},
		{"another protocol", func(f *Flow) { f.Proto = "tcp" }},
		{"another address", func(f *Flow) { f.DstIP = "198.51.100.1" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := flow(bytes.Repeat([]byte{0x41}, 1200)) // junk that would be dropped
			tc.mut(&f)
			got := e.Inspect(f)
			if got.Verdict != VerdictPass || got.FilterID != "" {
				t.Fatalf("traffic outside the binding was judged: %+v", got)
			}
		})
	}
}

// The filter cannot judge what it was not given, and must not blackhole a
// customer because the datapath is not supplying payloads.
func TestNoPayloadIsNeverADrop(t *testing.T) {
	e, _ := newEngine(t, bindTo("raknet", false))
	f := flow(nil)
	f.HasPayload = false
	got := e.Inspect(f)
	if got.Verdict != VerdictUninspectable {
		t.Fatalf("expected an uninspectable verdict, got %+v", got)
	}
	if got.FilterID == "" {
		t.Fatal("it should still say which binding could not inspect")
	}
}

// Observe mode is how a binding is rolled out: the verdict is recorded, the
// packet is not acted on.
func TestObserveModeNeverDrops(t *testing.T) {
	e, _ := newEngine(t, bindTo("raknet", true))
	got := e.Inspect(flow(bytes.Repeat([]byte{0x41}, 1200)))
	if got.Verdict != VerdictPass {
		t.Fatalf("observe mode must not drop, got %+v", got)
	}
	if got.Reason == "" || got.FilterID != "gf-1" {
		t.Fatalf("observe mode must still report what it would have done: %+v", got)
	}
}

// A reprogram arrives every couple of seconds; forgetting every admitted
// player each time would re-challenge the whole server.
func TestSessionsSurviveAReprogram(t *testing.T) {
	b := bindTo("raknet", false)
	e, _ := newEngine(t, b)
	e.Inspect(flow(append([]byte{0x07}, raknetMagic...))) // completes the handshake

	e.Load([]Binding{b}, []byte("fabric-secret"))
	if got := e.Inspect(flow([]byte{0x84, 0x01})); got.Verdict != VerdictPass {
		t.Fatalf("a reprogram re-challenged a connected player: %+v", got)
	}

	// A binding that is gone takes its sessions with it.
	other := b
	other.ID = "gf-2"
	e.Load([]Binding{other}, []byte("fabric-secret"))
	if n, _ := e.Sessions(); n != 0 {
		t.Fatalf("expected sessions for the removed binding to be dropped, got %d", n)
	}
}

// A spoofed flood presents unbounded sources. The table has to stay bounded
// or the scrubbing node is itself the casualty.
func TestSessionTableStaysBounded(t *testing.T) {
	e, _ := newEngine(t, bindTo("raknet", false))
	open := append([]byte{0x07}, raknetMagic...)
	for i := 0; i < maxSessions+5000; i++ {
		f := flow(open)
		f.SrcIP = fmt.Sprintf("10.%d.%d.%d", (i>>16)&0xff, (i>>8)&0xff, i&0xff)
		e.Inspect(f)
		if n, _ := e.Sessions(); n > maxSessions {
			t.Fatalf("the session table grew past its bound: %d after %d sources", n, i+1)
		}
	}
}

// An admitted source that goes quiet is forgotten, so an address does not
// stay admitted after it changes hands.
func TestAdmissionExpires(t *testing.T) {
	e, advance := newEngine(t, bindTo("raknet", false))
	e.Inspect(flow(append([]byte{0x07}, raknetMagic...)))
	if got := e.Inspect(flow([]byte{0x84, 0x01})); got.Verdict != VerdictPass {
		t.Fatalf("expected the source admitted, got %+v", got)
	}
	advance(DefaultSessionTTL + time.Second)
	if got := e.Inspect(flow([]byte{0x84, 0x01})); got.Verdict != VerdictDrop {
		t.Fatalf("expected admission to lapse, got %+v", got)
	}
}

func TestSignatureBoundsAndMagic(t *testing.T) {
	sig := Signature{MinLen: 4, MaxLen: 16, AnyMagic: []Magic{{Offset: 1, Bytes: []byte{0xAA, 0xBB}}}}
	for _, tc := range []struct {
		name    string
		payload []byte
		ok      bool
	}{
		{"valid", []byte{0x01, 0xAA, 0xBB, 0x02}, true},
		{"too short", []byte{0x01, 0xAA}, false},
		{"too long", bytes.Repeat([]byte{0x01}, 17), false},
		{"magic at the wrong offset", []byte{0xAA, 0xBB, 0x01, 0x02}, false},
		{"no magic", []byte{0x01, 0x02, 0x03, 0x04}, false},
		{"magic runs off the end", []byte{0x01, 0x02, 0x03, 0xAA}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := sig.Validate(tc.payload)
			if tc.ok && err != nil {
				t.Fatalf("expected %x to validate: %v", tc.payload, err)
			}
			if !tc.ok && err == nil {
				t.Fatalf("expected %x to be refused", tc.payload)
			}
		})
	}
}

func TestSignaturePacketIDs(t *testing.T) {
	sig := Signature{PacketIDs: []byte{0x01, 0x05}}
	if err := sig.Validate([]byte{0x05, 0x00}); err != nil {
		t.Fatalf("expected an allowed packet id: %v", err)
	}
	if err := sig.Validate([]byte{0x99}); err == nil {
		t.Fatal("expected a disallowed packet id to be refused")
	}
	if err := sig.Validate(nil); err == nil {
		t.Fatal("expected an empty packet to be refused when ids are restricted")
	}
}

// An empty signature accepts anything; it is only useful behind a gate.
func TestEmptySignatureAcceptsAnything(t *testing.T) {
	if err := (Signature{}).Validate(bytes.Repeat([]byte{0x41}, 900)); err != nil {
		t.Fatalf("an empty signature should accept anything: %v", err)
	}
}

func TestZeroValueEngineDoesNotPanic(t *testing.T) {
	var e Engine
	if got := e.Inspect(flow([]byte{0x01})); got.Verdict != VerdictPass {
		t.Fatalf("a zero-value engine should pass everything, got %+v", got)
	}
}

// A flood of sources that send one opener and never finish used to fill the
// session table, and once it is full the engine admits without tracking — so
// the filter stopped protecting the players who had actually connected.
// Unverified sources belong in the ring, which they churn on their own.
func TestAnOpenerFloodCannotEvictConnectedPlayers(t *testing.T) {
	e, _ := newEngine(t, bindTo("raknet", false))

	// A real player completes the handshake.
	player := flow([]byte{0x07})
	player.SrcIP = "192.0.2.50"
	if got := e.Inspect(player); got.Verdict != VerdictPass {
		t.Fatalf("the player did not get in: %+v", got)
	}

	// Then far more spoofed sources than either table holds send one opener
	// each and never come back.
	opener := []byte{0x01}
	for i := 0; i < scratchSlots*3; i++ {
		f := flow(opener)
		f.SrcIP = fmt.Sprintf("10.%d.%d.%d", i>>16&0xff, i>>8&0xff, i&0xff)
		e.Inspect(f)
	}

	sessions, max := e.Sessions()
	if sessions != 1 {
		t.Fatalf("expected only the connected player in the session table, got %d of %d", sessions, max)
	}
	if got := e.pending.len(); got > scratchSlots {
		t.Fatalf("the ring grew past its bound: %d", got)
	}

	// And the player is still tracked, not riding the untracked path.
	got := e.Inspect(player)
	if got.Verdict != VerdictPass {
		t.Fatalf("the connected player was dropped after the flood: %+v", got)
	}
	if got.Reason == "session table full, admitting without tracking" {
		t.Fatal("the flood pushed a connected player onto the untracked path")
	}
}

// The ring evicts its own oldest entry rather than scanning or refusing, so
// a source that is genuinely mid-handshake during a flood may be forgotten —
// it simply starts again, which is what an opening sequence is for.
func TestTheRingEvictsItsOldestEntry(t *testing.T) {
	e, _ := newEngine(t, bindTo("raknet", false))
	key := func(i int) sessionID {
		return sessionID{binding: "gf-1", src: fmt.Sprintf("10.0.%d.%d", i>>8, i&0xff)}
	}
	now := time.Unix(1_700_000_000, 0).UTC()

	e.pending.note(key(0), now, time.Minute)
	if !e.pending.seen(key(0), now) {
		t.Fatal("expected the first source noted")
	}
	for i := 1; i <= scratchSlots; i++ {
		e.pending.note(key(i), now, time.Minute)
	}
	if e.pending.seen(key(0), now) {
		t.Fatal("expected the oldest entry evicted once the ring wrapped")
	}
	if got := e.pending.len(); got > scratchSlots {
		t.Fatalf("the index outgrew the ring: %d", got)
	}
	// The newest is still there.
	if !e.pending.seen(key(scratchSlots), now) {
		t.Fatal("expected the newest entry kept")
	}
}

// Re-noting a source refreshes it rather than consuming another slot.
func TestRenotingDoesNotConsumeASlot(t *testing.T) {
	e, _ := newEngine(t, bindTo("raknet", false))
	k := sessionID{binding: "gf-1", src: "192.0.2.50"}
	now := time.Unix(1_700_000_000, 0).UTC()
	for i := 0; i < 100; i++ {
		e.pending.note(k, now, time.Minute)
	}
	if got := e.pending.len(); got != 1 {
		t.Fatalf("expected one entry, got %d", got)
	}
}
