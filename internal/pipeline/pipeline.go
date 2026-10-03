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

// compiledMatch holds a rule's CIDRs already parsed. Parsing them per packet
// per rule dominated the datapath: profiling put 84% of Decide's CPU in
// netip.ParsePrefix and netip.ParseAddr. Non-address fields are compared
// against raw exactly as before, so matching semantics are unchanged.
type compiledMatch struct {
	raw    model.Match
	src    netip.Prefix
	dst    netip.Prefix
	hasSrc bool
	hasDst bool
	// dead marks a rule whose CIDR did not parse. Such a rule never matched
	// before either, because contains() returned false for it.
	dead bool
}

type compiledACL struct {
	match  compiledMatch
	action model.Action
	ruleID string
}

type compiledMeter struct {
	match  compiledMatch
	action model.Action
	ruleID string
	meter  int
}

type compiledZC struct {
	match  compiledMatch
	action model.Action
	ruleID string
	pps    int
}

type compiledProgram struct {
	prefixes []netip.Prefix
	asic     []compiledACL
	fpga     []compiledMeter
	zc       []compiledZC
}

func compileMatch(m model.Match) compiledMatch {
	out := compiledMatch{raw: m}
	if m.SrcCIDR != "" {
		pfx, err := netip.ParsePrefix(m.SrcCIDR)
		if err != nil {
			out.dead = true
		} else {
			out.src, out.hasSrc = pfx, true
		}
	}
	if m.DstCIDR != "" {
		pfx, err := netip.ParsePrefix(m.DstCIDR)
		if err != nil {
			out.dead = true
		} else {
			out.dst, out.hasDst = pfx, true
		}
	}
	return out
}

func compileProgram(prog model.Program) compiledProgram {
	out := compiledProgram{
		prefixes: make([]netip.Prefix, 0, len(prog.Prefixes)),
		asic:     make([]compiledACL, 0, len(prog.ASIC)),
		fpga:     make([]compiledMeter, 0, len(prog.FPGA)),
		zc:       make([]compiledZC, 0, len(prog.ZC)),
	}
	for _, cidr := range prog.Prefixes {
		if pfx, err := netip.ParsePrefix(cidr); err == nil {
			out.prefixes = append(out.prefixes, pfx)
		}
	}
	for _, e := range prog.ASIC {
		out.asic = append(out.asic, compiledACL{match: compileMatch(e.Match), action: e.Action, ruleID: e.RuleID})
	}
	for _, e := range prog.FPGA {
		out.fpga = append(out.fpga, compiledMeter{match: compileMatch(e.Match), action: e.Action, ruleID: e.RuleID, meter: e.Meter})
	}
	for _, e := range prog.ZC {
		out.zc = append(out.zc, compiledZC{match: compileMatch(e.Match), action: e.Action, ruleID: e.RuleID, pps: e.PPS})
	}
	return out
}

// flowKey is the per-packet work that used to be repeated for every rule: the
// source and destination parsed once.
type flowKey struct {
	src   netip.Addr
	dst   netip.Addr
	srcOK bool
	dstOK bool
}

// matches reports whether the rule matches, with the addresses already parsed.
func (m *compiledMatch) matches(f model.Flow, k flowKey) bool {
	if m.dead {
		return false
	}
	if m.hasSrc && (!k.srcOK || !m.src.Contains(k.src)) {
		return false
	}
	if m.hasDst && (!k.dstOK || !m.dst.Contains(k.dst)) {
		return false
	}
	if m.raw.Proto != "" && m.raw.Proto != "any" && !strings.EqualFold(m.raw.Proto, f.Proto) {
		return false
	}
	if m.raw.DPort != 0 && m.raw.DPort != f.DPort {
		return false
	}
	if m.raw.SPort != 0 && m.raw.SPort != f.SPort {
		return false
	}
	if m.raw.TCPFlags != "" && !strings.EqualFold(m.raw.TCPFlags, f.Flags) {
		return false
	}
	return true
}

type Pipeline struct {
	mu      sync.Mutex
	program model.Program
	// compiled mirrors program with every CIDR pre-parsed.
	compiled compiledProgram
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

// Load installs a new program. Rate-limit state for ZC rules that survive the
// change is kept: the node agent re-polls every couple of seconds, and wiping
// the counters each time would mean a per-second cap could never be reached.
// clock reads the pipeline's time source, tolerating a zero-value Pipeline.
func (p *Pipeline) clock() time.Time {
	if p.now == nil {
		return time.Now()
	}
	return p.now()
}

func (p *Pipeline) Load(prog model.Program) {
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
	p.compiled = compileProgram(prog)
}

func (p *Pipeline) SetModel(m ml.Model) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.model = m
}

func (p *Pipeline) Decide(f model.Flow) model.Decision {
	// Parse the flow's addresses once, not once per rule.
	k := flowKey{}
	k.src, k.srcOK = parseAddr(f.SrcIP)
	k.dst, k.dstOK = parseAddr(f.DstIP)

	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.owns(k) {
		return model.Decision{Action: model.ActionPermit, Stage: model.StageASIC, Reason: "prefix not assigned to this node"}
	}
	for i := range p.compiled.asic {
		acl := &p.compiled.asic[i]
		if !acl.match.matches(f, k) {
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
	}
	for i := range p.compiled.fpga {
		row := &p.compiled.fpga[i]
		if !row.match.matches(f, k) {
			continue
		}
		if row.action == model.ActionPermit {
			return model.Decision{Action: model.ActionPermit, Stage: model.StageFPGA, RuleID: row.ruleID, Reason: "FPGA permit"}
		}
		if row.action == model.ActionDrop {
			return model.Decision{Action: model.ActionDrop, Stage: model.StageFPGA, RuleID: row.ruleID, Reason: "FPGA drop"}
		}
		if row.meter > 0 && f.PPS > row.meter {
			return model.Decision{Action: model.ActionDrop, Stage: model.StageFPGA, RuleID: row.ruleID, Reason: fmt.Sprintf("FPGA meter %d pps exceeded", row.meter)}
		}
	}
	for i := range p.compiled.zc {
		zc := &p.compiled.zc[i]
		if !zc.match.matches(f, k) {
			continue
		}
		if zc.action == model.ActionPermit {
			return model.Decision{Action: model.ActionPermit, Stage: model.StageZC, RuleID: zc.ruleID, Reason: "PF_RING ZC permit"}
		}
		if zc.action == model.ActionDrop {
			return model.Decision{Action: model.ActionDrop, Stage: model.StageZC, RuleID: zc.ruleID, Reason: "PF_RING ZC drop"}
		}
		if zc.pps > 0 && p.overRate(zc.ruleID, zc.pps, f) {
			return model.Decision{Action: model.ActionDrop, Stage: model.StageZC, RuleID: zc.ruleID, Reason: fmt.Sprintf("PF_RING ZC behavioral cap %d pps exceeded", zc.pps)}
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

func parseAddr(s string) (netip.Addr, bool) {
	if s == "" {
		return netip.Addr{}, false
	}
	a, err := netip.ParseAddr(s)
	return a, err == nil
}

// overRate accumulates the source's packet rate inside the current one-second
// window and reports whether it is above the rule's cap. Callers hold p.mu.
func (p *Pipeline) overRate(ruleID string, limit int, f model.Flow) bool {
	if limit <= 0 {
		return false
	}
	now := p.clock()
	if p.buckets == nil {
		p.buckets = map[string]*bucket{}
	}
	key := ruleID + "|" + f.SrcIP
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
	b.pps += f.PPS
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

func (p *Pipeline) owns(k flowKey) bool {
	if !k.dstOK {
		return false
	}
	for _, pfx := range p.compiled.prefixes {
		if pfx.Contains(k.dst) {
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
