package pipeline

import (
	"fmt"
	"log"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Jacksondude1223-bit/scrubline-cloud-scrub/internal/gamefilter"
	"github.com/Jacksondude1223-bit/scrubline-cloud-scrub/internal/ml"
	"github.com/Jacksondude1223-bit/scrubline-cloud-scrub/internal/model"
	"github.com/Jacksondude1223-bit/scrubline-cloud-scrub/internal/pulse"
)

const (
	// rateWindow is the span the ZC behavioral cap measures over. The cap is a
	// packets-per-second number, so the window is one second.
	rateWindow = time.Second
	// rateSlots divides that window. The cap used to be a fixed window that
	// reset wholesale, which let a source send its whole allowance at the
	// end of one window and again at the start of the next: twice the cap,
	// and exactly the shape a pulse attack sends. Counting over a trailing
	// window built from slots closes that.
	//
	// The slots hold exact counts rather than the usual weighted estimate of
	// the previous window, because that estimate assumes traffic is spread
	// evenly through it and over-counts a source that sends in bursts —
	// which would drop a flow sitting exactly at its cap.
	rateSlots    = 4
	rateSlotSpan = rateWindow / rateSlots
	// loadWindowSeconds is how long the offered-load average looks back. The
	// steering controller reacts to this number by moving BGP announcements,
	// so it is deliberately smoothed: a one-second spike must not reach the
	// routing table.
	loadWindowSeconds = 10
	// maxBuckets bounds the per-source rate table. A spoofed flood presents
	// effectively unlimited source addresses; without a bound the table is a
	// memory-exhaustion vector on the scrubbing node itself.
	maxBuckets = 1 << 16
)

// bucket is one source's trailing-window counter for one rule. slotID
// records which slot each count belongs to, so a slot left behind by a
// quiet stretch is recognised as stale rather than counted again when the
// ring wraps onto it.
type bucket struct {
	slotID [rateSlots]int64
	count  [rateSlots]int
}

// rateSlotOf is the slot a moment falls in, counted from the epoch so it is
// monotonic and comparable across buckets.
func rateSlotOf(t time.Time) int64 {
	return t.UnixNano() / int64(rateSlotSpan)
}

// add folds a rate into the trailing window and reports the window's total.
func (b *bucket) add(now time.Time, pps int) int {
	slot := rateSlotOf(now)
	oldest := slot - rateSlots + 1
	idx := int(((slot % rateSlots) + rateSlots) % rateSlots)
	if b.slotID[idx] != slot {
		b.slotID[idx] = slot
		b.count[idx] = 0
	}
	b.count[idx] += pps

	total := 0
	for i := 0; i < rateSlots; i++ {
		if b.slotID[i] >= oldest && b.slotID[i] <= slot {
			total += b.count[i]
		}
	}
	return total
}

// idle reports whether a bucket has seen nothing for a whole window, which
// is what makes it reclaimable.
func (b *bucket) idle(now time.Time) bool {
	oldest := rateSlotOf(now) - rateSlots + 1
	for i := 0; i < rateSlots; i++ {
		if b.slotID[i] >= oldest {
			return false
		}
	}
	return true
}

// bucketID keys the per-source rate table. A struct key costs no allocation,
// where joining the two into a string cost one on every packet that reached
// a ZC rate rule.
type bucketID struct {
	rule string
	src  string
}

// loadBucket is one second of the rolling load window. second identifies which
// second it holds, so a bucket left behind by a quiet period is recognised as
// stale rather than counted again.
type loadBucket struct {
	second  int64
	offered uint64
	dropped uint64
}

// compiledMatch is a model.Match with its CIDRs parsed and its string fields
// folded once, at Load time. Matching used to parse the rule's CIDR text on
// every rule for every flow, which cost more than the comparison itself.
type compiledMatch struct {
	src, dst       netip.Prefix
	hasSrc, hasDst bool
	// never marks a match whose CIDR text does not parse. Such a rule can never
	// fire, which is what the per-flow parse used to do by returning false.
	never        bool
	proto, flags string
	dport, sport int
}

func compileMatch(m model.Match) compiledMatch {
	c := compiledMatch{
		proto: strings.ToLower(m.Proto),
		flags: strings.ToLower(m.TCPFlags),
		dport: m.DPort,
		sport: m.SPort,
	}
	if m.SrcCIDR != "" {
		p, err := netip.ParsePrefix(m.SrcCIDR)
		if err != nil {
			c.never = true
		} else {
			c.src, c.hasSrc = p, true
		}
	}
	if m.DstCIDR != "" {
		p, err := netip.ParsePrefix(m.DstCIDR)
		if err != nil {
			c.never = true
		} else {
			c.dst, c.hasDst = p, true
		}
	}
	return c
}

func (c compiledMatch) matches(f parsedFlow) bool {
	if c.never {
		return false
	}
	if c.hasSrc && !(f.srcOK && c.src.Contains(f.src)) {
		return false
	}
	if c.hasDst && !(f.dstOK && c.dst.Contains(f.dst)) {
		return false
	}
	if c.proto != "" && c.proto != "any" && c.proto != f.proto {
		return false
	}
	if c.dport != 0 && c.dport != f.dport {
		return false
	}
	if c.sport != 0 && c.sport != f.sport {
		return false
	}
	if c.flags != "" && c.flags != f.flags {
		return false
	}
	return true
}

// compiledRule is one row of any stage. limit carries the FPGA meter or the ZC
// behavioral cap; it is zero on stages and actions that do not meter. stats is
// resolved once at Load so counting a match costs a pointer hop, not a lookup.
type compiledRule struct {
	match  compiledMatch
	action model.Action
	ruleID string
	limit  int
	stats  *ruleStats
}

// ruleStats counts what one rule did. Counters survive a reprogram for rules
// that remain in the policy: a node re-polls every couple of seconds, and
// resetting on every poll would make the series useless.
type ruleStats struct {
	ruleID     string
	stage      model.Stage
	matches    atomic.Uint64
	drops      atomic.Uint64
	ppsSeen    atomic.Uint64
	ppsDropped atomic.Uint64
}

// stageIndex orders the per-stage counters.
const (
	idxASIC = iota
	idxFPGA
	idxZC
	stageCount
)

var stagesInOrder = [stageCount]model.Stage{model.StageASIC, model.StageFPGA, model.StageZC}

func stageIndex(s model.Stage) int {
	switch s {
	case model.StageFPGA:
		return idxFPGA
	case model.StageZC:
		return idxZC
	default:
		return idxASIC
	}
}

// filterStats counts what one game filter did.
type filterStats struct {
	id            string
	profile       string
	inspected     atomic.Uint64
	dropped       atomic.Uint64
	challenged    atomic.Uint64
	uninspectable atomic.Uint64
	ppsDropped    atomic.Uint64
}

// counters are the node-level totals behind /metrics. They are atomics so a
// scrape never has to wait on the datapath.
type counters struct {
	decisions    atomic.Uint64
	unowned      atomic.Uint64
	dropped      [stageCount]atomic.Uint64
	permitted    [stageCount]atomic.Uint64
	ppsDropped   [stageCount]atomic.Uint64
	ppsPermitted [stageCount]atomic.Uint64
	mlScored     atomic.Uint64
	mlDrops      atomic.Uint64
	mlPasses     atomic.Uint64
}

// compiledProgram is the per-flow form of a model.Program.
type compiledProgram struct {
	prefixes []netip.Prefix
	// prefixText is the same prefixes as written, for keying measurements
	// without formatting one per packet.
	prefixText     []string
	asic, fpga, zc []compiledRule
}

func compileProgram(prog model.Program) *compiledProgram {
	cp := &compiledProgram{}
	for _, cidr := range prog.Prefixes {
		if p, err := netip.ParsePrefix(cidr); err == nil {
			cp.prefixes = append(cp.prefixes, p)
			cp.prefixText = append(cp.prefixText, cidr)
		}
	}
	for _, acl := range prog.ASIC {
		cp.asic = append(cp.asic, compiledRule{match: compileMatch(acl.Match), action: acl.Action, ruleID: acl.RuleID})
	}
	for _, row := range prog.FPGA {
		cp.fpga = append(cp.fpga, compiledRule{match: compileMatch(row.Match), action: row.Action, ruleID: row.RuleID, limit: row.Meter})
	}
	for _, zc := range prog.ZC {
		cp.zc = append(cp.zc, compiledRule{match: compileMatch(zc.Match), action: zc.Action, ruleID: zc.RuleID, limit: zc.PPS})
	}
	return cp
}

// parsedFlow is a model.Flow with its addresses parsed and its string fields
// folded once per flow rather than once per rule.
type parsedFlow struct {
	src, dst     netip.Addr
	srcOK, dstOK bool
	proto, flags string
	dport, sport int
	pps          int
	srcIP        string
}

func parseFlow(f model.Flow) parsedFlow {
	pf := parsedFlow{
		proto: strings.ToLower(f.Proto),
		flags: strings.ToLower(f.Flags),
		dport: f.DPort,
		sport: f.SPort,
		pps:   f.PPS,
		srcIP: f.SrcIP,
	}
	pf.src, pf.srcOK = parseAddr(f.SrcIP)
	pf.dst, pf.dstOK = parseAddr(f.DstIP)
	return pf
}

func parseAddr(s string) (netip.Addr, bool) {
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Addr{}, false
	}
	return a, true
}

type Pipeline struct {
	mu       sync.Mutex
	program  model.Program
	compiled *compiledProgram
	buckets  map[bucketID]*bucket
	model    ml.Model
	// stats is keyed by rule ID, which a policy guarantees unique. It is the
	// handle that lets counters outlive a reprogram.
	stats    map[string]*ruleStats
	counters counters
	// games admits traffic to a game port only if it looks like that game.
	// It runs in front of the ZC rules, so a packet that is not the protocol
	// dies before it reaches the behavioral cap or the classifier.
	games *gamefilter.Engine
	// gameStats is keyed by filter ID and, like the rule counters, outlives
	// a reprogram.
	gameStats map[string]*filterStats
	// gameBindings is how many filters are installed, cached here so a
	// policy with none does not pay for the engine's lock on every packet.
	gameBindings int
	// pulses recognises burst attacks per protected prefix, and keeps the
	// flag up through the gaps between bursts.
	pulses *pulse.Detector
	// load is the rolling per-second window behind the offered-load average.
	load [loadWindowSeconds]loadBucket
	// lastSweep throttles reclaiming the rate table to once per window, so a
	// flood of fresh source addresses cannot make every packet pay for a full
	// scan of the table.
	lastSweep time.Time
	// now is swapped out in tests; production always uses the wall clock.
	now func() time.Time
}

func New(p model.Program) *Pipeline {
	pipe := &Pipeline{program: p, buckets: map[bucketID]*bucket{}, now: time.Now}
	compiled := compileProgram(p)
	pipe.attachStats(compiled)
	pipe.compiled = compiled
	pipe.loadGames(p)
	pipe.loadPulse(p)
	return pipe
}

// loadPulse installs the pulse detector and forgets prefixes the policy no
// longer protects. Callers hold p.mu, or hold the pipeline alone.
func (p *Pipeline) loadPulse(prog model.Program) {
	if p.pulses == nil {
		p.pulses = pulse.New()
		if p.now != nil {
			p.pulses.SetClock(p.clock)
		}
	}
	if prog.PulseFloorPPS > 0 {
		p.pulses.SetFloor(uint64(prog.PulseFloorPPS))
	}
	live := make(map[string]struct{}, len(prog.Prefixes))
	for _, cidr := range prog.Prefixes {
		live[cidr] = struct{}{}
	}
	p.pulses.Forget(live)
}

// loadGames installs the program's game filters. A filter that does not
// compile is dropped with a log line rather than taking the datapath down:
// the control plane validates these on save, so reaching here means
// something got past it, and a node that refuses to program at all is worse
// than one missing a filter. Callers hold p.mu, or hold the pipeline alone.
func (p *Pipeline) loadGames(prog model.Program) {
	bindings, err := gamefilter.Compile(prog.Games)
	if err != nil {
		log.Printf("pipeline: game filters in policy %s could not be compiled, running without them: %v", prog.PolicyID, err)
		bindings = nil
	}
	secret := []byte(prog.ChallengeSecret)
	if p.games == nil {
		p.games = gamefilter.New(bindings, secret)
		if p.now != nil {
			p.games.SetClock(p.clock)
		}
	} else {
		p.games.Load(bindings, secret)
	}

	p.gameBindings = len(bindings)
	next := make(map[string]*filterStats, len(bindings))
	for _, b := range bindings {
		if prev := p.gameStats[b.ID]; prev != nil && prev.profile == b.Profile.Name {
			next[b.ID] = prev
			continue
		}
		next[b.ID] = &filterStats{id: b.ID, profile: b.Profile.Name}
	}
	p.gameStats = next
}

// attachStats points every compiled rule at its counters, carrying over the
// counters of rules that survived the reprogram. Callers hold p.mu.
func (p *Pipeline) attachStats(cp *compiledProgram) {
	next := make(map[string]*ruleStats, len(cp.asic)+len(cp.fpga)+len(cp.zc))
	wire := func(rules []compiledRule, stage model.Stage) {
		for i := range rules {
			id := rules[i].ruleID
			rs, ok := next[id]
			if !ok {
				// A rule that kept its ID and stage keeps its counters; one
				// that moved stage starts over, because the series changed
				// meaning.
				if prev := p.stats[id]; prev != nil && prev.stage == stage {
					rs = prev
				} else {
					rs = &ruleStats{ruleID: id, stage: stage}
				}
				next[id] = rs
			}
			rules[i].stats = rs
		}
	}
	wire(cp.asic, model.StageASIC)
	wire(cp.fpga, model.StageFPGA)
	wire(cp.zc, model.StageZC)
	p.stats = next
}

// clock reads the pipeline's time source, tolerating a zero-value Pipeline.
func (p *Pipeline) clock() time.Time {
	if p.now == nil {
		return time.Now()
	}
	return p.now()
}

// Load installs a new program. Rate-limit state for ZC rules that survive the
// change is kept: the node agent re-polls every couple of seconds, and wiping
// the counters each time would mean a per-second cap could never be reached.
func (p *Pipeline) Load(prog model.Program) {
	compiled := compileProgram(prog)
	p.mu.Lock()
	defer p.mu.Unlock()
	live := make(map[string]struct{}, len(prog.ZC))
	for _, zc := range prog.ZC {
		live[zc.RuleID] = struct{}{}
	}
	for key := range p.buckets {
		if _, ok := live[key.rule]; !ok {
			delete(p.buckets, key)
		}
	}
	p.attachStats(compiled)
	p.loadGames(prog)
	p.loadPulse(prog)
	p.program = prog
	p.compiled = compiled
}

// Program identifies the program currently installed, so a caller that polls
// can skip reloading an unchanged one. CompiledAt is part of the identity: a
// recompile can reassign prefixes without changing the policy version.
func (p *Pipeline) Program() (policyID string, version int, compiledAt time.Time) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.program.PolicyID, p.program.Version, p.program.CompiledAt
}

func (p *Pipeline) SetModel(m ml.Model) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.model = m
}

func (p *Pipeline) Decide(f model.Flow) model.Decision {
	pf := parseFlow(f)
	p.mu.Lock()
	defer p.mu.Unlock()
	cp := p.compiled
	if cp == nil {
		cp = compileProgram(p.program)
		p.attachStats(cp)
		p.compiled = cp
	}

	// One clock read per decision, shared with the rate limiter below rather
	// than taken again there.
	now := p.clock()
	pps := nonNegative(pf.pps)

	p.counters.decisions.Add(1)
	prefix, owned := cp.owns(pf)
	if !owned {
		// Traffic for a prefix this node does not carry. Counted separately: a
		// rising number here means the steering layer and the fabric disagree
		// about who scrubs what. It still arrived, so it still counts as load.
		p.counters.unowned.Add(1)
		p.observeLoad(now, pps, false)
		return model.Decision{Action: model.ActionPermit, Stage: model.StageASIC, Reason: "prefix not assigned to this node"}
	}

	// Measured at the resolution a burst actually has, and keyed by the
	// prefix it is aimed at. A mean over ten seconds would average the
	// burst away, which is the blindness a pulse attack is paying for.
	if p.pulses != nil {
		p.pulses.Observe(prefix, pps)
	}

	d, decidedBy := p.evaluate(cp, pf, f, now)
	// Every outcome is recorded in one place, so no return path can forget a
	// counter.
	p.record(d, decidedBy, pf)
	p.observeLoad(now, pps, d.Action == model.ActionDrop || d.Action == model.ActionChallenge)
	return d
}

// observeLoad folds one decision into the rolling window. Callers hold p.mu.
func (p *Pipeline) observeLoad(now time.Time, pps uint64, dropped bool) {
	sec := now.Unix()
	// One modulo plus a predictable branch, rather than two modulos, on a
	// path that runs for every decision.
	idx := sec % loadWindowSeconds
	if idx < 0 {
		idx += loadWindowSeconds
	}
	b := &p.load[idx]
	if b.second != sec {
		*b = loadBucket{second: sec}
	}
	b.offered += pps
	if dropped {
		b.dropped += pps
	}
}

// loadRates averages the window into a per-second offered and dropped rate.
// Buckets outside the window are skipped, so a node that has gone quiet
// reports load falling away rather than holding its last peak. Callers hold
// p.mu.
func (p *Pipeline) loadRates(now time.Time) (offered, dropped uint64) {
	sec := now.Unix()
	oldest := sec - loadWindowSeconds + 1
	var o, d uint64
	for _, b := range p.load {
		if b.second < oldest || b.second > sec {
			continue
		}
		o += b.offered
		d += b.dropped
	}
	return o / loadWindowSeconds, d / loadWindowSeconds
}

// evaluate walks the three stages and returns the decision together with the
// rule that produced it, which is nil when no rule did. Callers hold p.mu.
func (p *Pipeline) evaluate(cp *compiledProgram, pf parsedFlow, f model.Flow, now time.Time) (model.Decision, *ruleStats) {
	for i := range cp.asic {
		acl := &cp.asic[i]
		if !acl.match.matches(pf) {
			continue
		}
		p.seen(acl.stats, pf)
		switch acl.action {
		case model.ActionDrop:
			return model.Decision{Action: model.ActionDrop, Stage: model.StageASIC, RuleID: acl.ruleID, Reason: "TCAM ACL drop"}, acl.stats
		case model.ActionPermit:
			// An explicit TCAM permit is terminal: it is how an allow-list
			// exempts a source from the stages behind it.
			return model.Decision{Action: model.ActionPermit, Stage: model.StageASIC, RuleID: acl.ruleID, Reason: "TCAM ACL permit"}, acl.stats
		}
		// count and inspect carry no TCAM verdict; fall through to the next row.
	}
	for i := range cp.fpga {
		row := &cp.fpga[i]
		if !row.match.matches(pf) {
			continue
		}
		p.seen(row.stats, pf)
		switch row.action {
		case model.ActionPermit:
			return model.Decision{Action: model.ActionPermit, Stage: model.StageFPGA, RuleID: row.ruleID, Reason: "FPGA permit"}, row.stats
		case model.ActionDrop:
			return model.Decision{Action: model.ActionDrop, Stage: model.StageFPGA, RuleID: row.ruleID, Reason: "FPGA drop"}, row.stats
		case model.ActionLimit:
			// Only a rate_limit row consults the meter. A count row used to drop
			// here too, which turned an observe-only rule into a drop rule.
			if row.limit > 0 && pf.pps > row.limit {
				return model.Decision{Action: model.ActionDrop, Stage: model.StageFPGA, RuleID: row.ruleID, Reason: fmt.Sprintf("FPGA meter %d pps exceeded", row.limit)}, row.stats
			}
		}
	}
	// The game filter is an admission check in front of the ZC path: a
	// packet that is not the protocol its port speaks dies here, before it
	// can reach the behavioral cap or the classifier and before it counts
	// as a flow either of them has to reason about.
	if d, decided := p.inspectGame(pf, f); decided {
		return d, nil
	}

	for i := range cp.zc {
		zc := &cp.zc[i]
		if !zc.match.matches(pf) {
			continue
		}
		p.seen(zc.stats, pf)
		switch zc.action {
		case model.ActionPermit:
			return model.Decision{Action: model.ActionPermit, Stage: model.StageZC, RuleID: zc.ruleID, Reason: "PF_RING ZC permit"}, zc.stats
		case model.ActionDrop:
			return model.Decision{Action: model.ActionDrop, Stage: model.StageZC, RuleID: zc.ruleID, Reason: "PF_RING ZC drop"}, zc.stats
		case model.ActionCount:
			// Observe-only: the match is counted, the verdict is left to a
			// later row.
			continue
		}
		// rate_limit and inspect both reach the ZC inspect path: the behavioral
		// cap first, then the classifier.
		if zc.limit > 0 && p.overRate(now, zc.ruleID, zc.limit, pf) {
			return model.Decision{Action: model.ActionDrop, Stage: model.StageZC, RuleID: zc.ruleID, Reason: fmt.Sprintf("PF_RING ZC behavioral cap %d pps exceeded", zc.limit)}, zc.stats
		}
		if p.model.Ready {
			score := ml.Score(p.model, f)
			p.counters.mlScored.Add(1)
			if score >= p.model.Threshold {
				p.counters.mlDrops.Add(1)
				return model.Decision{Action: model.ActionDrop, Stage: model.StageZC, RuleID: zc.ruleID, Reason: fmt.Sprintf("PF_RING ZC ml score %.2f", score), Score: score}, zc.stats
			}
			p.counters.mlPasses.Add(1)
			return model.Decision{Action: model.ActionPermit, Stage: model.StageZC, RuleID: zc.ruleID, Reason: fmt.Sprintf("PF_RING ZC ml pass %.2f", score), Score: score}, zc.stats
		}
		return model.Decision{Action: model.ActionPermit, Stage: model.StageZC, RuleID: zc.ruleID, Reason: "PF_RING ZC inspect pass"}, zc.stats
	}
	return model.Decision{Action: model.ActionPermit, Stage: model.StageASIC, Reason: "no matching drop rule"}, nil
}

// inspectGame runs the game filter and reports whether it decided the
// packet. A pass, or traffic no binding covers, leaves the verdict to the ZC
// rules behind it. Callers hold p.mu.
func (p *Pipeline) inspectGame(pf parsedFlow, f model.Flow) (model.Decision, bool) {
	// Most policies bind no game filter at all; those must not pay for the
	// engine on every packet.
	if p.games == nil || p.gameBindings == 0 {
		return model.Decision{}, false
	}
	res := p.games.Inspect(gamefilter.Flow{
		SrcIP: pf.srcIP, DstIP: f.DstIP, Proto: pf.proto, DPort: pf.dport,
		Payload: f.Payload, HasPayload: f.Payload != nil,
	})
	if res.FilterID == "" {
		// No binding covers this traffic.
		return model.Decision{}, false
	}
	fs := p.gameStats[res.FilterID]
	if fs != nil {
		fs.inspected.Add(1)
	}

	switch res.Verdict {
	case gamefilter.VerdictDrop:
		if fs != nil {
			fs.dropped.Add(1)
			fs.ppsDropped.Add(nonNegative(pf.pps))
		}
		return model.Decision{
			Action: model.ActionDrop, Stage: model.StageZC, Filter: res.FilterID,
			Reason: fmt.Sprintf("game filter %s: %s", res.Profile, res.Reason),
		}, true
	case gamefilter.VerdictChallenge:
		if fs != nil {
			fs.challenged.Add(1)
		}
		return model.Decision{
			Action: model.ActionChallenge, Stage: model.StageZC, Filter: res.FilterID,
			Reason: fmt.Sprintf("game filter %s: %s", res.Profile, res.Reason),
			Reply:  res.Reply,
		}, true
	case gamefilter.VerdictUninspectable:
		// Counted, never acted on: the filter cannot judge what it was not
		// given, and a datapath that supplies no payload must not blackhole
		// a customer.
		if fs != nil {
			fs.uninspectable.Add(1)
		}
	}
	return model.Decision{}, false
}

// seen counts a rule match. A rule that matched but left the verdict to a
// later row still matched, which is the point of an observe-only rule.
func (p *Pipeline) seen(rs *ruleStats, pf parsedFlow) {
	if rs == nil {
		return
	}
	rs.matches.Add(1)
	rs.ppsSeen.Add(nonNegative(pf.pps))
}

// record books the outcome against the node totals and the deciding rule.
func (p *Pipeline) record(d model.Decision, rs *ruleStats, pf parsedFlow) {
	idx := stageIndex(d.Stage)
	pps := nonNegative(pf.pps)
	if d.Action == model.ActionDrop || d.Action == model.ActionChallenge {
		p.counters.dropped[idx].Add(1)
		p.counters.ppsDropped[idx].Add(pps)
		if rs != nil {
			rs.drops.Add(1)
			rs.ppsDropped.Add(pps)
		}
		return
	}
	p.counters.permitted[idx].Add(1)
	p.counters.ppsPermitted[idx].Add(pps)
}

// nonNegative keeps a hand-built flow record from wrapping a counter. The API
// and the agent both reject a negative rate, but Decide is callable directly.
func nonNegative(pps int) uint64 {
	if pps <= 0 {
		return 0
	}
	return uint64(pps)
}

// Stats is a point-in-time copy of a node's datapath counters.
type Stats struct {
	Decisions uint64       `json:"decisions"`
	Unowned   uint64       `json:"unowned"`
	Stages    []StageStats `json:"stages"`
	Rules     []RuleStats  `json:"rules"`
	Games     []GameStats  `json:"games"`
	Pulse     []PulseStats `json:"pulse"`
	ML        MLStats      `json:"ml"`
	// Pulsing is true while any protected prefix is under a recognised
	// burst train, and PulsePeakPPS is the heaviest burst seen across them.
	// The peak is the number that matters: a pulse attack's whole point is
	// that its mean stays under a watermark.
	Pulsing      bool   `json:"pulsing"`
	PulsePeakPPS uint64 `json:"pulse_peak_pps"`
	// GameSessions is how many sources the game filter is tracking, against
	// its bound. At the bound it is admitting without tracking.
	GameSessions    int `json:"game_sessions"`
	GameSessionsMax int `json:"game_sessions_max"`
	// RateBuckets is the size of the per-source rate table. It is bounded, and
	// sitting at the bound means the behavioral cap is no longer tracking
	// every source.
	RateBuckets    int `json:"rate_buckets"`
	RateBucketsMax int `json:"rate_buckets_max"`
	// OfferedPPS and DroppedPPS are moving averages over LoadWindowSeconds,
	// not totals. They are what the steering controller reads to decide
	// whether this node is saturated.
	OfferedPPS        uint64 `json:"offered_pps"`
	DroppedPPS        uint64 `json:"dropped_pps"`
	LoadWindowSeconds int    `json:"load_window_seconds"`
}

type StageStats struct {
	Stage        model.Stage `json:"stage"`
	Dropped      uint64      `json:"dropped"`
	Permitted    uint64      `json:"permitted"`
	PPSDropped   uint64      `json:"pps_dropped"`
	PPSPermitted uint64      `json:"pps_permitted"`
}

type RuleStats struct {
	RuleID     string      `json:"rule_id"`
	Stage      model.Stage `json:"stage"`
	Matches    uint64      `json:"matches"`
	Drops      uint64      `json:"drops"`
	PPSSeen    uint64      `json:"pps_seen"`
	PPSDropped uint64      `json:"pps_dropped"`
}

// PulseStats is the shape of traffic aimed at one protected prefix.
type PulseStats struct {
	Prefix    string  `json:"prefix"`
	Pulsing   bool    `json:"pulsing"`
	PeakPPS   uint64  `json:"peak_pps"`
	MeanPPS   uint64  `json:"mean_pps"`
	Crest     float64 `json:"crest"`
	DutyCycle float64 `json:"duty_cycle"`
	Bursts    int     `json:"bursts"`
	HeldFor   float64 `json:"held_for_seconds"`
}

// GameStats is one game filter's counters.
type GameStats struct {
	FilterID      string `json:"filter_id"`
	Profile       string `json:"profile"`
	Inspected     uint64 `json:"inspected"`
	Dropped       uint64 `json:"dropped"`
	Challenged    uint64 `json:"challenged"`
	Uninspectable uint64 `json:"uninspectable"`
	PPSDropped    uint64 `json:"pps_dropped"`
}

type MLStats struct {
	Ready  bool   `json:"ready"`
	Scored uint64 `json:"scored"`
	Drops  uint64 `json:"drops"`
	Passes uint64 `json:"passes"`
}

// Stats copies the counters out. Rules are sorted by ID so a scrape is stable.
func (p *Pipeline) Stats() Stats {
	p.mu.Lock()
	defer p.mu.Unlock()
	offered, dropped := p.loadRates(p.clock())
	out := Stats{
		Decisions:         p.counters.decisions.Load(),
		Unowned:           p.counters.unowned.Load(),
		OfferedPPS:        offered,
		DroppedPPS:        dropped,
		LoadWindowSeconds: loadWindowSeconds,
		Stages:            make([]StageStats, 0, stageCount),
		Rules:             make([]RuleStats, 0, len(p.stats)),
		RateBuckets:       len(p.buckets),
		RateBucketsMax:    maxBuckets,
		ML: MLStats{
			Ready:  p.model.Ready,
			Scored: p.counters.mlScored.Load(),
			Drops:  p.counters.mlDrops.Load(),
			Passes: p.counters.mlPasses.Load(),
		},
	}
	for i, stage := range stagesInOrder {
		out.Stages = append(out.Stages, StageStats{
			Stage:        stage,
			Dropped:      p.counters.dropped[i].Load(),
			Permitted:    p.counters.permitted[i].Load(),
			PPSDropped:   p.counters.ppsDropped[i].Load(),
			PPSPermitted: p.counters.ppsPermitted[i].Load(),
		})
	}
	for _, rs := range p.stats {
		out.Rules = append(out.Rules, RuleStats{
			RuleID:     rs.ruleID,
			Stage:      rs.stage,
			Matches:    rs.matches.Load(),
			Drops:      rs.drops.Load(),
			PPSSeen:    rs.ppsSeen.Load(),
			PPSDropped: rs.ppsDropped.Load(),
		})
	}
	for _, gs := range p.gameStats {
		out.Games = append(out.Games, GameStats{
			FilterID:      gs.id,
			Profile:       gs.profile,
			Inspected:     gs.inspected.Load(),
			Dropped:       gs.dropped.Load(),
			Challenged:    gs.challenged.Load(),
			Uninspectable: gs.uninspectable.Load(),
			PPSDropped:    gs.ppsDropped.Load(),
		})
	}
	if p.games != nil {
		out.GameSessions, out.GameSessionsMax = p.games.Sessions()
	}
	if p.pulses != nil {
		for _, prefix := range p.pulses.Keys() {
			a := p.pulses.Assess(prefix)
			out.Pulse = append(out.Pulse, PulseStats{
				Prefix: prefix, Pulsing: a.Pulsing,
				PeakPPS: a.PeakPPS, MeanPPS: a.MeanPPS,
				Crest: a.Crest, DutyCycle: a.DutyCycle, Bursts: a.Bursts,
				HeldFor: a.HeldFor.Seconds(),
			})
			if a.Pulsing {
				out.Pulsing = true
				if a.PeakPPS > out.PulsePeakPPS {
					out.PulsePeakPPS = a.PeakPPS
				}
			}
		}
		sort.Slice(out.Pulse, func(i, j int) bool { return out.Pulse[i].Prefix < out.Pulse[j].Prefix })
	}
	sort.Slice(out.Rules, func(i, j int) bool { return out.Rules[i].RuleID < out.Rules[j].RuleID })
	sort.Slice(out.Games, func(i, j int) bool { return out.Games[i].FilterID < out.Games[j].FilterID })
	return out
}

// overRate accumulates the source's packet rate inside the current one-second
// window and reports whether it is above the rule's cap. Callers hold p.mu.
func (p *Pipeline) overRate(now time.Time, ruleID string, limit int, f parsedFlow) bool {
	if limit <= 0 {
		return false
	}
	if p.buckets == nil {
		p.buckets = map[bucketID]*bucket{}
	}
	key := bucketID{rule: ruleID, src: f.srcIP}
	b, ok := p.buckets[key]
	if !ok {
		if len(p.buckets) >= maxBuckets && !p.reclaim(now) {
			// The table is full of live sources. Tracking this one would let an
			// address flood evict real state, so it goes to the inspect path
			// untracked rather than being dropped on a cap we cannot measure.
			return false
		}
		b = &bucket{}
		p.buckets[key] = b
	}
	return b.add(now, f.pps) > limit
}

// reclaim frees room in the rate table by dropping buckets whose window has
// closed, and reports whether there is room now. It scans at most once per
// window: with the table full, scanning per packet would be its own denial of
// service. Callers hold p.mu.
func (p *Pipeline) reclaim(now time.Time) bool {
	if !p.lastSweep.IsZero() && now.Sub(p.lastSweep) < rateWindow {
		return false
	}
	p.lastSweep = now
	for key, b := range p.buckets {
		if b.idle(now) {
			delete(p.buckets, key)
		}
	}
	return len(p.buckets) < maxBuckets
}

// owns reports whether a flow is for a prefix this node carries, and which
// one. The prefix is how pulse measurement is keyed: an attack aimed at one
// customer is the unit that matters.
func (cp *compiledProgram) owns(f parsedFlow) (string, bool) {
	if !f.dstOK {
		return "", false
	}
	for i, pfx := range cp.prefixes {
		if pfx.Contains(f.dst) {
			return cp.prefixText[i], true
		}
	}
	return "", false
}

// ruleOf recovers the rule ID from a bucket key. Rule IDs are validated to
// exclude "|", so the first separator is the boundary.
func ruleOf(key string) string {
	if i := strings.Index(key, "|"); i >= 0 {
		return key[:i]
	}
	return key
}
