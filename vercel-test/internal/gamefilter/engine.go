package gamefilter

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"net/netip"
	"strings"
	"sync"
	"time"
)

const (
	// DefaultSessionTTL is how long a source stays admitted without being
	// seen again. Long enough to span a quiet moment in a match, short
	// enough that an address does not stay admitted after it changes hands.
	DefaultSessionTTL = 2 * time.Minute
	// cookieEpoch is how often the challenge value rotates. The previous
	// epoch is also accepted, so a cookie is good for one to two of these
	// and a client is never refused for answering a moment too late.
	cookieEpoch = 2 * time.Minute
	// scratchSlots bounds the ring that holds sources part-way through a
	// gate. It is small on purpose: a handshake completes in milliseconds,
	// so this only has to cover the ones genuinely in flight, and anything
	// larger is just more room for a flood to sit in.
	scratchSlots = 1 << 13

	// maxSessions bounds the per-source table. A spoofed flood presents
	// effectively unlimited sources; without a bound the table is a
	// memory-exhaustion vector on the scrubbing node itself, which is the
	// same reason the ZC rate table is bounded.
	maxSessions = 1 << 16
)

// Binding is one profile applied to one port on one protected address: an
// operator says what runs where, and the filter only looks at traffic that
// matches.
type Binding struct {
	ID      string
	Dst     netip.Prefix
	HasDst  bool
	Proto   string
	DPort   int
	Profile Profile
	// Observe runs the binding without dropping, so a rollout can be watched
	// before it is trusted.
	Observe bool
}

// Flow is what the filter needs to know about a packet.
type Flow struct {
	SrcIP   string
	DstIP   string
	Proto   string
	DPort   int
	Payload []byte
	// HasPayload separates "an empty packet" from "the datapath did not give
	// us the bytes", which are very different things.
	HasPayload bool
}

// session is a source that has cleared a gate. Nothing else is kept here:
// sources part-way through one live in the ring, so the bound on this table
// is a bound on connected players rather than on anyone who sent a packet.
type session struct {
	expires time.Time
}

// sessionID keys the source table. A struct key costs no allocation, where
// joining the two into a string cost one on every packet.
type sessionID struct {
	binding string
	src     string
}

// scratch holds the sources part-way through a gate, separately from the ones
// that have cleared it.
//
// They used to share the session table, and an unverified source occupied a
// slot there for the whole TTL on the strength of one opening packet. A
// spoofed flood of openers filled it, and once full the engine admits
// without tracking — so a flood of addresses that never completed anything
// pushed real players off the protected path. Those entries were never even
// read to decide anything.
//
// A ring rather than a bounded map: eviction is overwriting the oldest slot,
// with no scan and no decision about who to drop. A flood churns its own
// entries out and never reaches the sessions of connected players.
type scratch struct {
	slots []scratchSlot
	index map[sessionID]int
	next  int
}

type scratchSlot struct {
	key     sessionID
	expires time.Time
	used    bool
}

func newScratch(size int) *scratch {
	return &scratch{slots: make([]scratchSlot, size), index: make(map[sessionID]int, size)}
}

// seen reports whether a source is part-way through a gate.
func (r *scratch) seen(key sessionID, now time.Time) bool {
	i, ok := r.index[key]
	if !ok {
		return false
	}
	slot := &r.slots[i]
	if !slot.used || slot.key != key || now.After(slot.expires) {
		return false
	}
	return true
}

// note records a source as in flight, evicting whatever is oldest.
func (r *scratch) note(key sessionID, now time.Time, ttl time.Duration) {
	if i, ok := r.index[key]; ok {
		slot := &r.slots[i]
		if slot.used && slot.key == key {
			slot.expires = now.Add(ttl)
			return
		}
	}
	slot := &r.slots[r.next]
	if slot.used {
		// The index entry for the evicted source goes with it, or the map
		// would grow without bound beside a fixed ring.
		if i, ok := r.index[slot.key]; ok && i == r.next {
			delete(r.index, slot.key)
		}
	}
	*slot = scratchSlot{key: key, expires: now.Add(ttl), used: true}
	r.index[key] = r.next
	r.next = (r.next + 1) % len(r.slots)
}

// forget drops entries for bindings that are no longer installed.
func (r *scratch) forget(live map[string]struct{}) {
	for key, i := range r.index {
		if _, ok := live[key.binding]; ok {
			continue
		}
		r.slots[i] = scratchSlot{}
		delete(r.index, key)
	}
}

func (r *scratch) len() int { return len(r.index) }

// Engine applies bindings to packets and remembers which sources have
// cleared a gate.
//
// The challenge secret is shared across the fabric rather than generated per
// node. Under anycast a source's packets can land on different scrubbers, so
// a cookie minted by one has to verify on another; a per-node secret would
// refuse legitimate clients whenever BGP moved them.
type Engine struct {
	mu       sync.Mutex
	bindings []Binding
	secret   []byte
	sessions map[sessionID]*session
	// pending holds sources part-way through a gate. Keeping them out of
	// the session table is what stops a flood of openers evicting players
	// who actually connected.
	pending *scratch
	// lastSweep throttles reclaiming the session table to once per TTL, so a
	// flood of fresh sources cannot make every packet pay for a full scan.
	lastSweep time.Time
	now       func() time.Time
}

func New(bindings []Binding, secret []byte) *Engine {
	return &Engine{
		bindings: bindings,
		secret:   secret,
		sessions: map[sessionID]*session{},
		pending:  newScratch(scratchSlots),
		now:      time.Now,
	}
}

// SetClock replaces the time source, for tests.
func (e *Engine) SetClock(now func() time.Time) {
	e.mu.Lock()
	e.now = now
	e.mu.Unlock()
}

func (e *Engine) clock() time.Time {
	if e.now == nil {
		return time.Now()
	}
	return e.now()
}

// Load installs a new set of bindings, keeping the sessions of bindings that
// survive. A reprogram arrives every couple of seconds, and forgetting every
// admitted player each time would re-challenge the whole server.
func (e *Engine) Load(bindings []Binding, secret []byte) {
	e.mu.Lock()
	defer e.mu.Unlock()
	live := make(map[string]struct{}, len(bindings))
	for _, b := range bindings {
		live[b.ID] = struct{}{}
	}
	e.pending.forget(live)
	for key := range e.sessions {
		if _, ok := live[key.binding]; !ok {
			delete(e.sessions, key)
		}
	}
	e.bindings = bindings
	e.secret = secret
}

// Bindings reports how many bindings are installed.
func (e *Engine) Bindings() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return len(e.bindings)
}

// Sessions reports how many sources are tracked, and the bound.
func (e *Engine) Sessions() (int, int) {
	e.mu.Lock()
	defer e.mu.Unlock()
	return len(e.sessions), maxSessions
}

// Inspect applies the first binding that matches the flow. A flow that
// matches no binding is not this filter's business and comes back as a pass
// with no filter named.
func (e *Engine) Inspect(f Flow) Result {
	e.mu.Lock()
	defer e.mu.Unlock()

	b, ok := e.match(f)
	if !ok {
		return Result{Verdict: VerdictPass}
	}
	res := e.apply(b, f)
	if b.Observe && res.Verdict != VerdictPass {
		// Observe-only: the verdict is recorded but the packet is not acted
		// on, so a binding can be watched before it is trusted.
		return Result{
			Verdict: VerdictPass, FilterID: b.ID, Profile: b.Profile.Name,
			Reason: "observe only: would have " + string(res.Verdict) + " (" + res.Reason + ")",
		}
	}
	return res
}

// Validate runs only the signature check: is this packet shaped like the
// protocol its port speaks?
//
// It is the fast path's half of Inspect. A source that has already cleared a
// gate does not need re-challenging or re-scoring — that is what clearing it
// established — but it does still need this, because the source address on
// a packet is written by whoever sent it. Without this check, spoofing a
// verified player's address would be a way to have junk forwarded.
//
// It touches no session state, so it neither admits nor expires anything.
func (e *Engine) Validate(f Flow) Result {
	e.mu.Lock()
	defer e.mu.Unlock()

	b, ok := e.match(f)
	if !ok {
		return Result{Verdict: VerdictPass}
	}
	base := Result{FilterID: b.ID, Profile: b.Profile.Name}
	if !f.HasPayload {
		base.Verdict = VerdictUninspectable
		base.Reason = "no payload supplied, nothing to inspect"
		return base
	}
	if err := b.Profile.Signature.Validate(f.Payload); err != nil {
		if b.Observe {
			base.Verdict = VerdictPass
			base.Reason = "observe only: would have drop (" + err.Error() + ")"
			return base
		}
		base.Verdict = VerdictDrop
		base.Reason = err.Error()
		return base
	}
	base.Verdict = VerdictPass
	base.Reason = b.Profile.reasonWellFormed
	return base
}

func (e *Engine) match(f Flow) (Binding, bool) {
	addr, addrErr := netip.ParseAddr(f.DstIP)
	addrOK := addrErr == nil
	proto := strings.ToLower(f.Proto)
	for _, b := range e.bindings {
		if b.Proto != "" && b.Proto != "any" && b.Proto != proto {
			continue
		}
		if b.DPort != 0 && b.DPort != f.DPort {
			continue
		}
		if b.HasDst && !(addrOK && b.Dst.Contains(addr)) {
			continue
		}
		return b, true
	}
	return Binding{}, false
}

// apply runs one binding. Callers hold e.mu.
func (e *Engine) apply(b Binding, f Flow) Result {
	base := Result{FilterID: b.ID, Profile: b.Profile.Name}
	if !f.HasPayload {
		// The filter cannot judge what it was not given. Dropping here would
		// mean a datapath that does not supply payloads silently blackholes
		// a customer, so this passes and is counted instead.
		base.Verdict = VerdictUninspectable
		base.Reason = "no payload supplied, nothing to inspect"
		return base
	}
	if err := b.Profile.Signature.Validate(f.Payload); err != nil {
		base.Verdict = VerdictDrop
		base.Reason = err.Error()
		return base
	}

	switch b.Profile.Gate.Kind {
	case GateHandshake:
		return e.handshake(b, f, base)
	case GateChallenge:
		return e.challenge(b, f, base)
	}
	base.Verdict = VerdictPass
	base.Reason = b.Profile.reasonWellFormed
	return base
}

// handshake admits a source once it has completed the protocol's own opening
// sequence. Until then it may send only the opening packet types, which is
// what stops a flood of plausible-looking gameplay packets from a source
// that never connected.
func (e *Engine) handshake(b Binding, f Flow, base Result) Result {
	key := sessionKey(b.ID, f.SrcIP)
	now := e.clock()
	s := e.lookup(key, now)
	if s != nil {
		s.expires = now.Add(ttl(b.Profile))
		base.Verdict = VerdictPass
		base.Reason = b.Profile.reasonAdmitted
		return base
	}

	if len(f.Payload) == 0 {
		base.Verdict = VerdictDrop
		base.Reason = "empty packet from a source that has not connected"
		return base
	}
	id := f.Payload[0]
	gate := b.Profile.Gate
	if !containsByte(gate.OpenerIDs, id) && !containsByte(gate.CompleteIDs, id) {
		base.Verdict = VerdictDrop
		// Only a drop pays for a formatted reason; the pass path uses the
		// strings precomputed when the profile was loaded.
		base.Reason = fmt.Sprintf("packet id 0x%02x from a source that has not completed the handshake", id)
		return base
	}
	if containsByte(gate.CompleteIDs, id) {
		if e.admit(key, now, ttl(b.Profile)) {
			base.Verdict = VerdictPass
			base.Reason = b.Profile.reasonAdmitted
			base.Cleared = GateHandshake
			return base
		}
		// The table is full of live sources. Let the packet through rather
		// than evicting a connected player for a source we cannot track.
		base.Verdict = VerdictPass
		base.Reason = "session table full, admitting without tracking"
		return base
	}
	// An opener earns a slot in the ring, not in the session table. The
	// source has proved only that it can write a packet id.
	e.pending.note(key, now, ttl(b.Profile))
	base.Verdict = VerdictPass
	base.Reason = "handshake in progress"
	return base
}

// challenge answers the protocol's own challenge and admits a source once it
// echoes the value back.
func (e *Engine) challenge(b Binding, f Flow, base Result) Result {
	key := sessionKey(b.ID, f.SrcIP)
	now := e.clock()
	gate := b.Profile.Gate

	if s := e.lookup(key, now); s != nil {
		s.expires = now.Add(ttl(b.Profile))
		base.Verdict = VerdictPass
		base.Reason = b.Profile.reasonAdmitted
		return base
	}
	if !gate.queryID(f.Payload) {
		base.Verdict = VerdictDrop
		base.Reason = "not a query this protocol challenges, from an unverified source"
		return base
	}

	want := e.cookie(f, now)
	if echoed := echo(f.Payload, gate); echoed != nil {
		if hmac.Equal(echoed, want) || hmac.Equal(echoed, e.cookieAt(f, now.Add(-cookieEpoch))) {
			if !e.admit(key, now, ttl(b.Profile)) {
				base.Verdict = VerdictPass
				base.Reason = "session table full, admitting without tracking"
				base.Cleared = GateChallenge
				return base
			}
			base.Verdict = VerdictPass
			base.Reason = b.Profile.reasonAdmitted
			base.Cleared = GateChallenge
			return base
		}
	}
	base.Verdict = VerdictChallenge
	base.Reason = "unverified source challenged"
	base.Reply = append(append([]byte(nil), gate.ReplyPrefix...), want...)
	return base
}

// echo pulls the cookie a follow-up packet claims to be answering with.
func echo(payload []byte, g Gate) []byte {
	if g.CookieLen <= 0 {
		return nil
	}
	end := g.EchoOffset + g.CookieLen
	if g.EchoOffset < 0 || end > len(payload) {
		return nil
	}
	return payload[g.EchoOffset:end]
}

// cookie derives the challenge value for a source. It is a keyed hash of the
// source, the destination and the epoch, so no state is needed to mint one
// and any node in the fabric derives the same value.
func (e *Engine) cookie(f Flow, now time.Time) []byte {
	return e.cookieAt(f, now)
}

func (e *Engine) cookieAt(f Flow, at time.Time) []byte {
	mac := hmac.New(sha256.New, e.secret)
	_, _ = mac.Write([]byte(f.SrcIP))
	_, _ = mac.Write([]byte{0})
	_, _ = mac.Write([]byte(f.DstIP))
	_, _ = mac.Write([]byte{0})
	var scratch [8]byte
	binary.BigEndian.PutUint64(scratch[:], uint64(f.DPort))
	_, _ = mac.Write(scratch[:])
	binary.BigEndian.PutUint64(scratch[:], uint64(at.Unix()/int64(cookieEpoch.Seconds())))
	_, _ = mac.Write(scratch[:])
	return mac.Sum(nil)[:4]
}

func (e *Engine) lookup(key sessionID, now time.Time) *session {
	s, ok := e.sessions[key]
	if !ok {
		return nil
	}
	if now.After(s.expires) {
		delete(e.sessions, key)
		return nil
	}
	return s
}

// admit marks a source as through the gate, and reports whether it could be
// tracked.
func (e *Engine) admit(key sessionID, now time.Time, ttl time.Duration) bool {
	if s, ok := e.sessions[key]; ok {
		s.expires = now.Add(ttl)
		return true
	}
	if !e.room(now) {
		return false
	}
	e.sessions[key] = &session{expires: now.Add(ttl)}
	return true
}

// room makes space in the session table, scanning at most once per TTL:
// with the table full, scanning per packet would be its own denial of
// service.
func (e *Engine) room(now time.Time) bool {
	if len(e.sessions) < maxSessions {
		return true
	}
	if !e.lastSweep.IsZero() && now.Sub(e.lastSweep) < DefaultSessionTTL {
		return false
	}
	e.lastSweep = now
	for key, s := range e.sessions {
		if now.After(s.expires) {
			delete(e.sessions, key)
		}
	}
	return len(e.sessions) < maxSessions
}

func ttl(p Profile) time.Duration {
	if p.SessionTTL > 0 {
		return p.SessionTTL
	}
	return DefaultSessionTTL
}

func sessionKey(bindingID, srcIP string) sessionID {
	return sessionID{binding: bindingID, src: srcIP}
}
