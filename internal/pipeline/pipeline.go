package pipeline

import (
	"fmt"
	"net/netip"
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
	// rateShards splits that table so concurrent decisions for different
	// sources do not serialize on one lock. Must be a power of two.
	rateShards = 1 << 4
	// shardBuckets keeps the total bound at maxBuckets across all shards.
	shardBuckets = maxBuckets / rateShards
)

// rateKey identifies one source under one rule. A struct key avoids building a
// joined string on every decision, and lets Load read the rule back without
// parsing it out of the key.
type rateKey struct {
	rule string
	src  string
}

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

// state is the read-only half of the pipeline: the program and the model. It is
// swapped wholesale so Decide can take a consistent snapshot with a single
// atomic load instead of a mutex. Holding one lock across the whole decision
// meant the datapath did not scale with cores at all.
type state struct {
	program  model.Program
	compiled compiledProgram
	model    ml.Model
}

// rateShard is one slice of the per-source rate table with its own lock.
type rateShard struct {
	mu      sync.Mutex
	buckets map[rateKey]*bucket
	// lastSweep throttles reclaiming this shard to once per window, so a flood
	// of fresh source addresses cannot make every packet pay for a full scan.
	lastSweep time.Time
}

type Pipeline struct {
	cur atomic.Pointer[state]
	// writeMu serializes Load against SetModel; both read-modify-write cur.
	writeMu sync.Mutex
	shards  [rateShards]rateShard
	// now is set at construction (and by tests before any concurrent use);
	// production always uses the wall clock.
	now func() time.Time
}

func New(p model.Program) *Pipeline {
	// Shard maps are created on first use rather than here: the control plane
	// builds a Pipeline per /v1/decide request, and allocating every shard's map
	// up front made that request path pay for sixteen maps it would never touch.
	pipe := &Pipeline{now: time.Now}
	pipe.cur.Store(&state{program: p, compiled: compileProgram(p)})
	return pipe
}

// clock reads the pipeline's time source, tolerating a zero-value Pipeline.
func (p *Pipeline) clock() time.Time {
	if p.now == nil {
		return time.Now()
	}
	return p.now()
}

// snapshot returns the current program and model, tolerating a zero-value
// Pipeline that was never given one.
func (p *Pipeline) snapshot() *state {
	if st := p.cur.Load(); st != nil {
		return st
	}
	return &state{}
}

// Load installs a new program. Rate-limit state for ZC rules that survive the
// change is kept: the node agent re-polls every couple of seconds, and wiping
// the counters each time would mean a per-second cap could never be reached.
func (p *Pipeline) Load(prog model.Program) {
	p.writeMu.Lock()
	defer p.writeMu.Unlock()
	prev := p.snapshot()
	p.cur.Store(&state{program: prog, compiled: compileProgram(prog), model: prev.model})

	live := make(map[string]struct{}, len(prog.ZC))
	for _, zc := range prog.ZC {
		live[zc.RuleID] = struct{}{}
	}
	for i := range p.shards {
		sh := &p.shards[i]
		sh.mu.Lock()
		// A nil map ranges zero times, so an untouched shard costs nothing here.
		for key := range sh.buckets {
			if _, ok := live[key.rule]; !ok {
				delete(sh.buckets, key)
			}
		}
		sh.mu.Unlock()
	}
}

func (p *Pipeline) SetModel(m ml.Model) {
	p.writeMu.Lock()
	defer p.writeMu.Unlock()
	prev := p.snapshot()
	p.cur.Store(&state{program: prev.program, compiled: prev.compiled, model: m})
}

// bucketCount reports how many sources are currently tracked across all shards.
func (p *Pipeline) bucketCount() int {
	n := 0
	for i := range p.shards {
		sh := &p.shards[i]
		sh.mu.Lock()
		n += len(sh.buckets)
		sh.mu.Unlock()
	}
	return n
}

func (p *Pipeline) Decide(f model.Flow) model.Decision {
	// Parse the flow's addresses once, not once per rule.
	k := flowKey{}
	k.src, k.srcOK = parseAddr(f.SrcIP)
	k.dst, k.dstOK = parseAddr(f.DstIP)

	st := p.snapshot()
	if !owns(st, k) {
		return model.Decision{Action: model.ActionPermit, Stage: model.StageASIC, Reason: "prefix not assigned to this node"}
	}
	for i := range st.compiled.asic {
		acl := &st.compiled.asic[i]
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
	for i := range st.compiled.fpga {
		row := &st.compiled.fpga[i]
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
	for i := range st.compiled.zc {
		zc := &st.compiled.zc[i]
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
		if st.model.Ready {
			score := ml.Score(st.model, f)
			if score >= st.model.Threshold {
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
// window and reports whether it is above the rule's cap. Only the one shard
// holding this source is locked.
func (p *Pipeline) overRate(ruleID string, limit int, f model.Flow) bool {
	if limit <= 0 {
		return false
	}
	key := rateKey{rule: ruleID, src: f.SrcIP}
	sh := &p.shards[shardIndex(key)]
	now := p.clock()

	sh.mu.Lock()
	defer sh.mu.Unlock()
	if sh.buckets == nil {
		sh.buckets = map[rateKey]*bucket{}
	}
	b, ok := sh.buckets[key]
	if !ok {
		if len(sh.buckets) >= shardBuckets && !sh.reclaim(now) {
			// This shard is full of live sources. Tracking another would let an
			// address flood evict real state, so it goes to the inspect path
			// untracked rather than being dropped on a cap we cannot measure.
			return false
		}
		b = &bucket{windowStart: now}
		sh.buckets[key] = b
	}
	if now.Sub(b.windowStart) >= rateWindow {
		b.windowStart = now
		b.pps = 0
	}
	b.pps += f.PPS
	return b.pps > limit
}

// shardIndex picks the shard for a key. FNV-1a spreads rule/source pairs evenly
// so one shard does not fill while others sit idle. Written out rather than
// using hash/fnv to keep the interface and its boxing off the packet path.
func shardIndex(k rateKey) uint32 {
	const (
		offset32 = 2166136261
		prime32  = 16777619
	)
	h := uint32(offset32)
	for i := 0; i < len(k.rule); i++ {
		h = (h ^ uint32(k.rule[i])) * prime32
	}
	h = (h ^ uint32('|')) * prime32
	for i := 0; i < len(k.src); i++ {
		h = (h ^ uint32(k.src[i])) * prime32
	}
	return h & (rateShards - 1)
}

// reclaim frees room in this shard by dropping buckets whose window has closed,
// and reports whether there is room now. It scans at most once per window: with
// the shard full, scanning per packet would be its own denial of service.
// Callers hold sh.mu.
func (sh *rateShard) reclaim(now time.Time) bool {
	if !sh.lastSweep.IsZero() && now.Sub(sh.lastSweep) < rateWindow {
		return false
	}
	sh.lastSweep = now
	for key, b := range sh.buckets {
		if now.Sub(b.windowStart) >= rateWindow {
			delete(sh.buckets, key)
		}
	}
	return len(sh.buckets) < shardBuckets
}

func owns(st *state, k flowKey) bool {
	if !k.dstOK {
		return false
	}
	for _, pfx := range st.compiled.prefixes {
		if pfx.Contains(k.dst) {
			return true
		}
	}
	return false
}
