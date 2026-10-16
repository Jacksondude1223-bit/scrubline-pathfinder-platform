package pipeline

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Jacksondude1223-bit/scrubline-cloud-scrub/internal/ml"
	"github.com/Jacksondude1223-bit/scrubline-cloud-scrub/internal/model"
)

const (
	// rateWindow is the span the ZC behavioral cap measures over. The cap is a
	// packets-per-second number, so the window is one second.
	rateWindow = time.Second
	// maxBuckets bounds the per-source rate table. A spoofed flood presents
	// effectively unlimited source addresses; without a bound the table is a
	// memory-exhaustion vector on the scrubbing node itself.
	maxBuckets = 1 << 16
)

type bucket struct {
	windowStart time.Time
	pps         int
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
	prefixes       []netip.Prefix
	asic, fpga, zc []compiledRule
}

func compileProgram(prog model.Program) *compiledProgram {
	cp := &compiledProgram{}
	for _, cidr := range prog.Prefixes {
		if p, err := netip.ParsePrefix(cidr); err == nil {
			cp.prefixes = append(cp.prefixes, p)
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
	buckets  map[string]*bucket
	model    ml.Model
	// stats is keyed by rule ID, which a policy guarantees unique. It is the
	// handle that lets counters outlive a reprogram.
	stats    map[string]*ruleStats
	counters counters
	// lastSweep throttles reclaiming the rate table to once per window, so a
	// flood of fresh source addresses cannot make every packet pay for a full
	// scan of the table.
	lastSweep time.Time
	// now is swapped out in tests; production always uses the wall clock.
	now func() time.Time
}

func New(p model.Program) *Pipeline {
	pipe := &Pipeline{program: p, buckets: map[string]*bucket{}, now: time.Now}
	compiled := compileProgram(p)
	pipe.attachStats(compiled)
	pipe.compiled = compiled
	return pipe
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
		if _, ok := live[ruleOf(key)]; !ok {
			delete(p.buckets, key)
		}
	}
	p.attachStats(compiled)
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

	p.counters.decisions.Add(1)
	if !cp.owns(pf) {
		// Traffic for a prefix this node was not assigned. Counted separately:
		// a rising number here means the steering layer and the fabric
		// disagree about who scrubs what.
		p.counters.unowned.Add(1)
		return model.Decision{Action: model.ActionPermit, Stage: model.StageASIC, Reason: "prefix not assigned to this node"}
	}

	d, decidedBy := p.evaluate(cp, pf, f)
	// Every outcome is recorded in one place, so no return path can forget a
	// counter.
	p.record(d, decidedBy, pf)
	return d
}

// evaluate walks the three stages and returns the decision together with the
// rule that produced it, which is nil when no rule did. Callers hold p.mu.
func (p *Pipeline) evaluate(cp *compiledProgram, pf parsedFlow, f model.Flow) (model.Decision, *ruleStats) {
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
		if zc.limit > 0 && p.overRate(zc.ruleID, zc.limit, pf) {
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
	if d.Action == model.ActionDrop {
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
	ML        MLStats      `json:"ml"`
	// RateBuckets is the size of the per-source rate table. It is bounded, and
	// sitting at the bound means the behavioral cap is no longer tracking
	// every source.
	RateBuckets    int `json:"rate_buckets"`
	RateBucketsMax int `json:"rate_buckets_max"`
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
	out := Stats{
		Decisions:      p.counters.decisions.Load(),
		Unowned:        p.counters.unowned.Load(),
		Stages:         make([]StageStats, 0, stageCount),
		Rules:          make([]RuleStats, 0, len(p.stats)),
		RateBuckets:    len(p.buckets),
		RateBucketsMax: maxBuckets,
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
	sort.Slice(out.Rules, func(i, j int) bool { return out.Rules[i].RuleID < out.Rules[j].RuleID })
	return out
}

// overRate accumulates the source's packet rate inside the current one-second
// window and reports whether it is above the rule's cap. Callers hold p.mu.
func (p *Pipeline) overRate(ruleID string, limit int, f parsedFlow) bool {
	if limit <= 0 {
		return false
	}
	now := p.clock()
	if p.buckets == nil {
		p.buckets = map[string]*bucket{}
	}
	key := ruleID + "|" + f.srcIP
	b, ok := p.buckets[key]
	if !ok {
		if len(p.buckets) >= maxBuckets && !p.reclaim(now) {
			// The table is full of live sources. Tracking this one would let an
			// address flood evict real state, so it goes to the inspect path
			// untracked rather than being dropped on a cap we cannot measure.
			return false
		}
		b = &bucket{windowStart: now}
		p.buckets[key] = b
	}
	if now.Sub(b.windowStart) >= rateWindow {
		b.windowStart = now
		b.pps = 0
	}
	b.pps += f.pps
	return b.pps > limit
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
		if now.Sub(b.windowStart) >= rateWindow {
			delete(p.buckets, key)
		}
	}
	return len(p.buckets) < maxBuckets
}

func (cp *compiledProgram) owns(f parsedFlow) bool {
	if !f.dstOK {
		return false
	}
	for _, pfx := range cp.prefixes {
		if pfx.Contains(f.dst) {
			return true
		}
	}
	return false
}

// ruleOf recovers the rule ID from a bucket key. Rule IDs are validated to
// exclude "|", so the first separator is the boundary.
func ruleOf(key string) string {
	if i := strings.Index(key, "|"); i >= 0 {
		return key[:i]
	}
	return key
}
