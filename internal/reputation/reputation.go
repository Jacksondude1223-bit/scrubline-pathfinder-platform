// Package reputation remembers what a source has already proved, so the
// datapath does not re-derive it per packet.
//
// Two tiers, pulling in opposite directions. A source that has cleared a
// protocol gate is trusted for a while and takes a shorter path: it has
// already demonstrated it is the thing the port speaks, and scoring it again
// on every packet buys nothing. A source that keeps failing is dropped at the
// top of the pipeline instead of walking every stage to reach the same
// verdict, which is where the headroom comes from during an attack — most of
// the packets are the attacker's.
//
// # Why a trusted source cannot be demoted
//
// The obvious design — any source that trips a check goes in the penalty box
// — turns the box into a weapon. Source addresses in a UDP flood are written
// by the attacker, so anyone can send a packet claiming to be a real player
// and have that player banned. The mitigation becomes a better denial of
// service than the attack it was defending against.
//
// So demotion applies only to sources that are not currently trusted. That is
// not a loophole for an abusive verified client: trust skips the stateless
// checks, never the per-source rate cap, so the worst a trusted source can do
// is use its full allowance. Strikes against trusted sources are counted and
// exposed, so an operator can see one misbehaving and act deliberately.
//
// # What counts as proof
//
// Clearing a challenge gate proves a return path: the source echoed a value
// it could only have learned from a reply sent to that address. Completing a
// handshake does not — the opening sequence can be sent blind, so a spoofer
// can clear it for any address including a real player's. Both are recorded,
// and which one a deployment is willing to fast-path is a policy decision.
package reputation

import (
	"sort"
	"time"

	"github.com/Jacksondude1223-bit/scrubline-cloud-scrub/internal/model"
)

const (
	// TrustTTL is how long a source stays trusted after it last cleared a
	// gate. Short enough that an address changing hands is not fast-passed
	// on the last tenant's evidence, long enough to cover a quiet stretch in
	// a session.
	TrustTTL = 5 * time.Minute

	// StrikesToBox is how many failures put a source in the penalty box. One
	// is not enough: a single bad packet from an address is ordinary — a
	// stale client, a retransmit, a scan — and boxing on it would turn every
	// false positive into a minutes-long outage for that source.
	StrikesToBox = 4
	// StrikeWindow is how long strikes accumulate for. A source that fails
	// four times in half a minute is behaving differently from one that
	// fails four times a day.
	StrikeWindow = 30 * time.Second

	// EscalationDecay is how long a boxed source must go without further
	// strikes before its escalation drops a level. Without it, a source that
	// misbehaved once last week comes back to the longest penalty.
	EscalationDecay = time.Hour

	// MaxTracked bounds the table. It is keyed by source address, which is
	// the one field an attacker can vary without limit, so the bound is what
	// stops the cache becoming the memory-exhaustion vector it exists to
	// prevent.
	MaxTracked = 1 << 16

	// sweepInterval throttles reclaiming expired entries. With the table
	// full, scanning per packet would be its own denial of service.
	sweepInterval = 5 * time.Second
)

// penaltyLadder is how long each successive stretch in the box lasts.
var penaltyLadder = []time.Duration{time.Minute, 10 * time.Minute, time.Hour}

// Proof is what a source demonstrated when it cleared a gate.
type Proof uint8

const (
	// ProofNone is a source that has proved nothing.
	ProofNone Proof = iota
	// ProofHandshake is a completed opening sequence. It can be sent blind,
	// so it is evidence the source speaks the protocol, not evidence that
	// the address is real.
	ProofHandshake
	// ProofChallenge is an echoed cookie. The source could only have learned
	// it from a reply, so the address answers for itself.
	ProofChallenge
)

func (p Proof) String() string {
	switch p {
	case ProofHandshake:
		return "handshake"
	case ProofChallenge:
		return "challenge"
	default:
		return "none"
	}
}

// State is what the cache knows about a source right now.
type State uint8

const (
	// Unknown means the source takes the ordinary path.
	Unknown State = iota
	// Trusted means it cleared a gate recently and may skip the stateless
	// checks. Never the rate cap.
	Trusted
	// Penalised means it is in the box and should be dropped at the top of
	// the pipeline.
	Penalised
)

// entry is one source's record. Both tiers share it, because a source moves
// between them and splitting the table would mean two lookups per packet.
type entry struct {
	trustedUntil   time.Time
	proof          Proof
	penalisedUntil time.Time
	// level indexes penaltyLadder for the next time this source is boxed.
	level int
	// strikes accumulate inside a window; windowEnds is when they lapse.
	strikes    int
	windowEnds time.Time
	// lastStrike drives escalation decay.
	lastStrike time.Time
}

// Stats is what the cache is holding, for the exposition.
type Stats struct {
	Tracked   int `json:"tracked"`
	Max       int `json:"max"`
	Trusted   int `json:"trusted"`
	Penalised int `json:"penalised"`
	// FastPassed and Boxed count packets taken off the slow path and dropped
	// at the top respectively. Promotions and Demotions count the transitions.
	FastPassed uint64 `json:"fast_passed"`
	Boxed      uint64 `json:"boxed"`
	Promotions uint64 `json:"promotions"`
	Demotions  uint64 `json:"demotions"`
	Strikes    uint64 `json:"strikes"`
	// Shielded counts strikes that landed on a trusted source and were
	// therefore not acted on. A rising value is either a spoofing attempt
	// against a real player, or a verified client genuinely misbehaving;
	// both are worth an operator's attention and neither should silently
	// black-hole somebody.
	Shielded uint64 `json:"shielded"`
	// Full counts sources the table had no room for. They take the ordinary
	// path, so this is lost optimisation rather than lost protection.
	Full uint64 `json:"full"`
}

// Cache is the two-tier source table.
//
// It is not safe for concurrent use. The pipeline owns one and holds its own
// lock across a decision, which is where every call comes from; a second lock
// on this path would cost more than the lookups it guards.
type Cache struct {
	entries map[string]*entry
	// fastPassProof is the weakest proof that earns a fast pass. Policy
	// decides it, because whether a blind-sendable handshake is good enough
	// depends on what the deployment is defending against.
	fastPassProof Proof
	// noFastPass turns the trusted tier off without touching the penalty
	// tier.
	noFastPass bool
	// boxing off makes the cache observe without dropping, which is how a
	// penalty box is rolled out.
	boxing bool

	lastSweep time.Time
	stats     Stats
	now       func() time.Time
}

// Config is the policy knobs a deployment sets.
type Config struct {
	// FastPassProof is the weakest proof that skips the stateless checks.
	FastPassProof Proof
	// NoFastPass turns the trusted tier off entirely, so every packet takes
	// the full path however much its source has proved. The penalty tier is
	// unaffected: shedding known-bad traffic early and short-cutting
	// verified traffic are separate decisions, and a deployment may well
	// want one without the other.
	NoFastPass bool
	// Boxing enables dropping penalised sources. Off means strikes are
	// recorded and exposed but nothing is dropped, which is how it is
	// rolled out safely.
	Boxing bool
}

func New() *Cache {
	return &Cache{
		entries:       map[string]*entry{},
		fastPassProof: ProofChallenge,
		now:           func() time.Time { return time.Now() },
	}
}

// Configure applies the policy knobs.
func (c *Cache) Configure(cfg Config) {
	if c == nil {
		return
	}
	if cfg.FastPassProof == ProofNone {
		cfg.FastPassProof = ProofChallenge
	}
	c.fastPassProof = cfg.FastPassProof
	c.noFastPass = cfg.NoFastPass
	c.boxing = cfg.Boxing
}

// SetClock replaces the time source, so tests can walk a penalty ladder
// without waiting out an hour.
func (c *Cache) SetClock(now func() time.Time) {
	if c == nil {
		return
	}
	c.now = now
}

func (c *Cache) clock() time.Time {
	if c.now == nil {
		return time.Now()
	}
	return c.now()
}

// Check reports what the datapath should do with a source before it does any
// other work.
//
// The nil receiver is the no-cache case and answers Unknown, so a Pipeline
// built as a plain struct literal behaves as it did before this existed.
// Promote and Strike are no-ops on nil for the same reason.
func (c *Cache) Check(src string, now time.Time) State {
	if c == nil {
		return Unknown
	}
	e := c.entries[src]
	if e == nil {
		return Unknown
	}
	if c.boxing && now.Before(e.penalisedUntil) {
		c.stats.Boxed++
		return Penalised
	}
	if !c.noFastPass && now.Before(e.trustedUntil) && e.proof >= c.fastPassProof {
		c.stats.FastPassed++
		return Trusted
	}
	return Unknown
}

// Promote records that a source cleared a gate.
//
// Re-clearing refreshes the TTL and can only raise the proof level, never
// lower it: a challenge-verified source that later completes a handshake has
// not become less trustworthy.
func (c *Cache) Promote(src string, proof Proof, now time.Time) {
	if c == nil || src == "" || proof == ProofNone {
		return
	}
	e := c.lookupOrCreate(src, now)
	if e == nil {
		return
	}
	if e.trustedUntil.Before(now) {
		c.stats.Promotions++
	}
	e.trustedUntil = now.Add(TrustTTL)
	if proof > e.proof {
		e.proof = proof
	}
	// Clearing a gate is the clearest evidence a source is real, so it also
	// clears the strikes it accumulated getting there. A client that fumbles
	// its opening packets a few times and then connects properly should not
	// be carrying them afterwards.
	//
	// It does not clear a penalty. A boxed source is dropped at the top of
	// the pipeline, so it never reaches a gate to clear one — letting it
	// promote itself out here would describe a path that does not exist.
	// Release is the way out, and it is an operator's decision.
	e.strikes = 0
}

// Strike records a failure against a source and reports whether it is now
// boxed.
//
// A trusted source is never boxed by this. See the package comment: source
// addresses are attacker-controlled, so acting on a stateless signal would
// let anyone ban anyone. The strike is counted as shielded instead.
func (c *Cache) Strike(src string, now time.Time) bool {
	if c == nil || src == "" {
		return false
	}
	c.stats.Strikes++
	e := c.entries[src]
	if e != nil && now.Before(e.trustedUntil) {
		c.stats.Shielded++
		return false
	}
	if e == nil {
		e = c.lookupOrCreate(src, now)
		if e == nil {
			return false
		}
	}

	// Escalation decays before this strike is counted, so a source returning
	// after a long quiet stretch starts lower than it left off.
	//
	// Clean time runs from whichever came later: the last strike, or the end
	// of the penalty it earned. Measuring from the strike alone handed a
	// level back for the time the source spent serving its sentence, which
	// meant the longest penalty always decayed itself the moment it expired.
	e.decayLocked(now)
	e.lastStrike = now

	if now.After(e.windowEnds) {
		e.strikes = 0
		e.windowEnds = now.Add(StrikeWindow)
	}
	e.strikes++
	if e.strikes < StrikesToBox {
		return false
	}

	e.strikes = 0
	e.windowEnds = time.Time{}
	level := e.level
	if level >= len(penaltyLadder) {
		level = len(penaltyLadder) - 1
	}
	e.penalisedUntil = now.Add(penaltyLadder[level])
	if e.level < len(penaltyLadder)-1 {
		e.level++
	}
	c.stats.Demotions++
	return c.boxing
}

// Release takes a source out of the box early, for an operator correcting a
// false positive. The escalation level is left alone: the next offence should
// not start from scratch just because this one was forgiven.
func (c *Cache) Release(src string) bool {
	if c == nil {
		return false
	}
	e := c.entries[src]
	if e == nil || e.penalisedUntil.IsZero() {
		return false
	}
	e.penalisedUntil = time.Time{}
	e.strikes = 0
	return true
}

// lookupOrCreate finds a source's record, making one if there is room.
// Returning nil means the table is full, which costs an optimisation and
// never a protection: the source simply takes the ordinary path.
func (c *Cache) lookupOrCreate(src string, now time.Time) *entry {
	if e, ok := c.entries[src]; ok {
		return e
	}
	if len(c.entries) >= MaxTracked && !c.sweep(now) {
		c.stats.Full++
		return nil
	}
	e := &entry{}
	c.entries[src] = e
	return e
}

// sweep reclaims entries that have nothing left to say, and reports whether
// there is room now. It scans at most once per interval: with the table full,
// scanning per packet would be its own denial of service.
func (c *Cache) sweep(now time.Time) bool {
	if !c.lastSweep.IsZero() && now.Sub(c.lastSweep) < sweepInterval {
		return false
	}
	c.lastSweep = now
	for src, e := range c.entries {
		if e.spent(now) {
			delete(c.entries, src)
		}
	}
	return len(c.entries) < MaxTracked
}

// decayLocked walks an entry's escalation back down for clean time served.
func (e *entry) decayLocked(now time.Time) {
	clean := e.cleanSince()
	for e.level > 0 && !clean.IsZero() && now.Sub(clean) >= EscalationDecay {
		e.level--
		clean = clean.Add(EscalationDecay)
	}
}

// cleanSince is when this source last stopped being in trouble: the later of
// its last strike and the end of its penalty.
func (e *entry) cleanSince() time.Time {
	clean := e.lastStrike
	if e.penalisedUntil.After(clean) {
		clean = e.penalisedUntil
	}
	return clean
}

// spent reports whether an entry still carries anything worth remembering.
// An escalation level outlives its penalty by EscalationDecay, so a source
// cannot shed its history by waiting out the shortest stretch.
func (e *entry) spent(now time.Time) bool {
	if now.Before(e.trustedUntil) || now.Before(e.penalisedUntil) || now.Before(e.windowEnds) {
		return false
	}
	// An escalation level outlives its penalty by EscalationDecay, measured
	// from the same point the decay is, so a source cannot shed its history
	// by waiting out the shortest stretch.
	if clean := e.cleanSince(); e.level > 0 && !clean.IsZero() && now.Sub(clean) < EscalationDecay {
		return false
	}
	return true
}

// Stats copies the counters out, with the live tier sizes counted fresh.
func (c *Cache) Stats() Stats {
	if c == nil {
		return Stats{}
	}
	now := c.clock()
	out := c.stats
	out.Max = MaxTracked
	out.Tracked = len(c.entries)
	for _, e := range c.entries {
		if now.Before(e.trustedUntil) {
			out.Trusted++
		}
		if now.Before(e.penalisedUntil) {
			out.Penalised++
		}
	}
	return out
}

// Sources lists what the cache is holding, newest penalty first, for an
// operator looking at who is in the box. It is a debugging view and is not on
// any hot path.
func (c *Cache) Sources(limit int) []model.SourceReputation {
	if c == nil {
		return nil
	}
	now := c.clock()
	out := make([]model.SourceReputation, 0, len(c.entries))
	for src, e := range c.entries {
		row := model.SourceReputation{Source: src, Proof: e.proof.String()}
		if now.Before(e.trustedUntil) {
			row.State = "trusted"
			row.ExpiresIn = e.trustedUntil.Sub(now).Seconds()
		} else if now.Before(e.penalisedUntil) {
			row.State = "penalised"
			row.ExpiresIn = e.penalisedUntil.Sub(now).Seconds()
		} else {
			row.State = "tracked"
		}
		row.Level = e.level
		row.Strikes = e.strikes
		out = append(out, row)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].State != out[j].State {
			// Penalised first: it is the list an operator is looking for.
			return out[i].State < out[j].State
		}
		if out[i].ExpiresIn != out[j].ExpiresIn {
			return out[i].ExpiresIn > out[j].ExpiresIn
		}
		return out[i].Source < out[j].Source
	})
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out
}
