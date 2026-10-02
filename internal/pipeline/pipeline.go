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

type Pipeline struct {
	mu      sync.Mutex
	program model.Program
	buckets map[string]*bucket
	model   ml.Model
	// lastSweep throttles reclaiming the rate table to once per window, so a
	// flood of fresh source addresses cannot make every packet pay for a full
	// scan of the table.
	lastSweep time.Time
	// now is swapped out in tests; production always uses the wall clock.
	now func() time.Time
}

func New(p model.Program) *Pipeline {
	return &Pipeline{program: p, buckets: map[string]*bucket{}, now: time.Now}
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
}

func (p *Pipeline) SetModel(m ml.Model) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.model = m
}

func (p *Pipeline) Decide(f model.Flow) model.Decision {
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.owns(f.DstIP) {
		return model.Decision{Action: model.ActionPermit, Stage: model.StageASIC, Reason: "prefix not assigned to this node"}
	}
	for _, acl := range p.program.ASIC {
		if !match(acl.Match, f) {
			continue
		}
		switch acl.Action {
		case model.ActionDrop:
			return model.Decision{Action: model.ActionDrop, Stage: model.StageASIC, RuleID: acl.RuleID, Reason: "TCAM ACL drop"}
		case model.ActionPermit:
			// An explicit TCAM permit is terminal: it is how an allow-list
			// exempts a source from the stages behind it.
			return model.Decision{Action: model.ActionPermit, Stage: model.StageASIC, RuleID: acl.RuleID, Reason: "TCAM ACL permit"}
		}
	}
	for _, row := range p.program.FPGA {
		if !match(row.Match, f) {
			continue
		}
		if row.Action == model.ActionPermit {
			return model.Decision{Action: model.ActionPermit, Stage: model.StageFPGA, RuleID: row.RuleID, Reason: "FPGA permit"}
		}
		if row.Action == model.ActionDrop {
			return model.Decision{Action: model.ActionDrop, Stage: model.StageFPGA, RuleID: row.RuleID, Reason: "FPGA drop"}
		}
		if row.Meter > 0 && f.PPS > row.Meter {
			return model.Decision{Action: model.ActionDrop, Stage: model.StageFPGA, RuleID: row.RuleID, Reason: fmt.Sprintf("FPGA meter %d pps exceeded", row.Meter)}
		}
	}
	for _, zc := range p.program.ZC {
		if !match(zc.Match, f) {
			continue
		}
		if zc.Action == model.ActionPermit {
			return model.Decision{Action: model.ActionPermit, Stage: model.StageZC, RuleID: zc.RuleID, Reason: "PF_RING ZC permit"}
		}
		if zc.Action == model.ActionDrop {
			return model.Decision{Action: model.ActionDrop, Stage: model.StageZC, RuleID: zc.RuleID, Reason: "PF_RING ZC drop"}
		}
		if zc.PPS > 0 && p.overRate(zc.RuleID, zc.PPS, f) {
			return model.Decision{Action: model.ActionDrop, Stage: model.StageZC, RuleID: zc.RuleID, Reason: fmt.Sprintf("PF_RING ZC behavioral cap %d pps exceeded", zc.PPS)}
		}
		if p.model.Ready {
			score := ml.Score(p.model, f)
			if score >= p.model.Threshold {
				return model.Decision{Action: model.ActionDrop, Stage: model.StageZC, RuleID: zc.RuleID, Reason: fmt.Sprintf("PF_RING ZC ml score %.2f", score), Score: score}
			}
			return model.Decision{Action: model.ActionPermit, Stage: model.StageZC, RuleID: zc.RuleID, Reason: fmt.Sprintf("PF_RING ZC ml pass %.2f", score), Score: score}
		}
		return model.Decision{Action: model.ActionPermit, Stage: model.StageZC, RuleID: zc.RuleID, Reason: "PF_RING ZC inspect pass"}
	}
	return model.Decision{Action: model.ActionPermit, Stage: model.StageASIC, Reason: "no matching drop rule"}
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

func (p *Pipeline) owns(dst string) bool {
	ip, err := netip.ParseAddr(dst)
	if err != nil {
		return false
	}
	for _, cidr := range p.program.Prefixes {
		pfx, err := netip.ParsePrefix(cidr)
		if err == nil && pfx.Contains(ip) {
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

func match(m model.Match, f model.Flow) bool {
	if m.SrcCIDR != "" && !contains(m.SrcCIDR, f.SrcIP) {
		return false
	}
	if m.DstCIDR != "" && !contains(m.DstCIDR, f.DstIP) {
		return false
	}
	if m.Proto != "" && m.Proto != "any" && !strings.EqualFold(m.Proto, f.Proto) {
		return false
	}
	if m.DPort != 0 && m.DPort != f.DPort {
		return false
	}
	if m.SPort != 0 && m.SPort != f.SPort {
		return false
	}
	if m.TCPFlags != "" && !strings.EqualFold(m.TCPFlags, f.Flags) {
		return false
	}
	return true
}

func contains(cidr, ip string) bool {
	pfx, err := netip.ParsePrefix(cidr)
	if err != nil {
		return false
	}
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return false
	}
	return pfx.Contains(addr)
}
