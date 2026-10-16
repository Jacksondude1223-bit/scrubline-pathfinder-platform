package pipeline

import (
	"fmt"
	"net/netip"
	"strings"
	"sync"
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
// behavioral cap; it is zero on stages and actions that do not meter.
type compiledRule struct {
	match  compiledMatch
	action model.Action
	ruleID string
	limit  int
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
	// lastSweep throttles reclaiming the rate table to once per window, so a
	// flood of fresh source addresses cannot make every packet pay for a full
	// scan of the table.
	lastSweep time.Time
	// now is swapped out in tests; production always uses the wall clock.
	now func() time.Time
}

func New(p model.Program) *Pipeline {
	return &Pipeline{program: p, compiled: compileProgram(p), buckets: map[string]*bucket{}, now: time.Now}
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
		p.compiled = cp
	}
	if !cp.owns(pf) {
		return model.Decision{Action: model.ActionPermit, Stage: model.StageASIC, Reason: "prefix not assigned to this node"}
	}
	for _, acl := range cp.asic {
		if !acl.match.matches(pf) {
			continue
		}
		switch acl.action {
		case model.ActionDrop:
			return model.Decision{Action: model.ActionDrop, Stage: model.StageASIC, RuleID: acl.ruleID, Reason: "TCAM ACL drop"}
		case model.ActionPermit:
			// An explicit TCAM permit is terminal: it is how an allow-list
			// exempts a source from the stages behind it.
			return model.Decision{Action: model.ActionPermit, Stage: model.StageASIC, RuleID: acl.ruleID, Reason: "TCAM ACL permit"}
		}
		// count and inspect carry no TCAM verdict; fall through to the next row.
	}
	for _, row := range cp.fpga {
		if !row.match.matches(pf) {
			continue
		}
		switch row.action {
		case model.ActionPermit:
			return model.Decision{Action: model.ActionPermit, Stage: model.StageFPGA, RuleID: row.ruleID, Reason: "FPGA permit"}
		case model.ActionDrop:
			return model.Decision{Action: model.ActionDrop, Stage: model.StageFPGA, RuleID: row.ruleID, Reason: "FPGA drop"}
		case model.ActionLimit:
			// Only a rate_limit row consults the meter. A count row used to drop
			// here too, which turned an observe-only rule into a drop rule.
			if row.limit > 0 && pf.pps > row.limit {
				return model.Decision{Action: model.ActionDrop, Stage: model.StageFPGA, RuleID: row.ruleID, Reason: fmt.Sprintf("FPGA meter %d pps exceeded", row.limit)}
			}
		}
	}
	for _, zc := range cp.zc {
		if !zc.match.matches(pf) {
			continue
		}
		switch zc.action {
		case model.ActionPermit:
			return model.Decision{Action: model.ActionPermit, Stage: model.StageZC, RuleID: zc.ruleID, Reason: "PF_RING ZC permit"}
		case model.ActionDrop:
			return model.Decision{Action: model.ActionDrop, Stage: model.StageZC, RuleID: zc.ruleID, Reason: "PF_RING ZC drop"}
		case model.ActionCount:
			// Observe-only: record nothing and leave the verdict to a later row.
			continue
		}
		// rate_limit and inspect both reach the ZC inspect path: the behavioral
		// cap first, then the classifier.
		if zc.limit > 0 && p.overRate(zc.ruleID, zc.limit, pf) {
			return model.Decision{Action: model.ActionDrop, Stage: model.StageZC, RuleID: zc.ruleID, Reason: fmt.Sprintf("PF_RING ZC behavioral cap %d pps exceeded", zc.limit)}
		}
		if p.model.Ready {
			score := ml.Score(p.model, f)
			if score >= p.model.Threshold {
				return model.Decision{Action: model.ActionDrop, Stage: model.StageZC, RuleID: zc.ruleID, Reason: fmt.Sprintf("PF_RING ZC ml score %.2f", score), Score: score}
			}
			return model.Decision{Action: model.ActionPermit, Stage: model.StageZC, RuleID: zc.ruleID, Reason: fmt.Sprintf("PF_RING ZC ml pass %.2f", score), Score: score}
		}
		return model.Decision{Action: model.ActionPermit, Stage: model.StageZC, RuleID: zc.ruleID, Reason: "PF_RING ZC inspect pass"}
	}
	return model.Decision{Action: model.ActionPermit, Stage: model.StageASIC, Reason: "no matching drop rule"}
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
