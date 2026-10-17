package pipeline

import (
	"bytes"
	"fmt"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/Jacksondude1223-bit/scrubline-cloud-scrub/internal/compiler"
	"github.com/Jacksondude1223-bit/scrubline-cloud-scrub/internal/ml"
	"github.com/Jacksondude1223-bit/scrubline-cloud-scrub/internal/model"
)

func TestThreeStageDropPath(t *testing.T) {
	policy := model.Policy{
		ID: "pol-1", Version: 1,
		Protected: []string{"203.0.113.0/24"},
		Rules: []model.Rule{
			{ID: "tcam", Stage: model.StageASIC, Action: model.ActionDrop, Priority: 10, Match: model.Match{SrcCIDR: "198.51.100.0/24", DstCIDR: "203.0.113.0/24", Proto: "udp", DPort: 19132}},
			{ID: "fpga", Stage: model.StageFPGA, Action: model.ActionLimit, Priority: 20, PPS: 1000, Match: model.Match{DstCIDR: "203.0.113.0/24", Proto: "udp"}},
			{ID: "zc", Stage: model.StageZC, Action: model.ActionInspect, Priority: 30, PPS: 50, Match: model.Match{DstCIDR: "203.0.113.0/24", Proto: "tcp"}},
		},
	}
	nodes := []model.Node{{ID: "node-a", Name: "scrub-a", CapacityGbps: 100, Status: model.NodeReady}}
	progs := compiler.Compile(policy, nodes, compiler.Plan(policy, nodes, nil))
	pipe := New(*progs["node-a"])

	acl := pipe.Decide(model.Flow{SrcIP: "198.51.100.9", DstIP: "203.0.113.10", Proto: "udp", DPort: 19132, PPS: 10})
	if acl.Stage != model.StageASIC || acl.Action != model.ActionDrop {
		t.Fatalf("expected TCAM drop, got %+v", acl)
	}
	meter := pipe.Decide(model.Flow{SrcIP: "203.0.113.9", DstIP: "203.0.113.10", Proto: "udp", DPort: 80, PPS: 5000})
	if meter.Stage != model.StageFPGA || meter.Action != model.ActionDrop {
		t.Fatalf("expected FPGA meter drop, got %+v", meter)
	}
	ok := pipe.Decide(model.Flow{SrcIP: "192.0.2.9", DstIP: "203.0.113.10", Proto: "tcp", DPort: 443, PPS: 10})
	if ok.Stage != model.StageZC || ok.Action != model.ActionPermit {
		t.Fatalf("expected ZC pass, got %+v", ok)
	}
}

// Anycast means every node carries every protected prefix, so a flood on one
// prefix is absorbed by the whole fabric rather than by one scrubber.
func TestEveryNodeEnforcesEveryPrefix(t *testing.T) {
	nodes := []model.Node{
		{ID: "a", Name: "a", CapacityGbps: 10, Status: model.NodeReady},
		{ID: "b", Name: "b", CapacityGbps: 10, Status: model.NodeReady},
		{ID: "c", Name: "c", CapacityGbps: 10, Status: model.NodeReady},
	}
	policy := model.Policy{ID: "pol-1", Version: 1, Protected: []string{
		"203.0.113.0/24", "203.0.114.0/24", "203.0.115.0/24",
	}}
	progs := compiler.Compile(policy, nodes, compiler.Plan(policy, nodes, nil))

	flow := model.Flow{SrcIP: "198.51.100.1", DstIP: "203.0.114.9", Proto: "udp", PPS: 10}
	for _, n := range nodes {
		prog := progs[n.ID]
		if len(prog.Prefixes) != len(policy.Protected) {
			t.Fatalf("node %s enforces %v, expected all of %v", n.ID, prog.Prefixes, policy.Protected)
		}
		// Whichever node BGP steers the traffic to must recognise it as its own.
		if d := New(*prog).Decide(flow); d.Reason == "prefix not assigned to this node" {
			t.Fatalf("node %s would wave through traffic anycast sent it: %+v", n.ID, d)
		}
	}
}

// An explicit permit rule is an allow-list and must short-circuit the stages
// behind it. These used to be compiled into the program and then ignored.
func TestPermitShortCircuitsLaterStages(t *testing.T) {
	for _, tc := range []struct {
		name  string
		prog  model.Program
		stage model.Stage
	}{
		{
			name: "asic permit beats asic drop",
			prog: model.Program{
				Prefixes: []string{"203.0.113.0/24"},
				ASIC: []model.ACLEntry{
					{Priority: 1, Action: model.ActionPermit, RuleID: "allow", Match: model.Match{SrcCIDR: "192.0.2.5/32"}},
					{Priority: 2, Action: model.ActionDrop, RuleID: "denyall", Match: model.Match{Proto: "tcp"}},
				},
			},
			stage: model.StageASIC,
		},
		{
			name: "fpga permit beats fpga meter",
			prog: model.Program{
				Prefixes: []string{"203.0.113.0/24"},
				FPGA: []model.FPGAEntry{
					{Table: "scrub_meter", Action: model.ActionPermit, RuleID: "allow", Match: model.Match{SrcCIDR: "192.0.2.5/32"}},
					{Table: "scrub_meter", Action: model.ActionLimit, Meter: 1, RuleID: "meter", Match: model.Match{Proto: "tcp"}},
				},
			},
			stage: model.StageFPGA,
		},
		{
			name: "zc permit beats zc cap",
			prog: model.Program{
				Prefixes: []string{"203.0.113.0/24"},
				ZC: []model.ZCEntry{
					{Cluster: "zc:a", Action: model.ActionPermit, RuleID: "allow", Match: model.Match{SrcCIDR: "192.0.2.5/32"}},
					{Cluster: "zc:a", Action: model.ActionInspect, PPS: 1, RuleID: "cap", Match: model.Match{Proto: "tcp"}},
				},
			},
			stage: model.StageZC,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := New(tc.prog)
			d := p.Decide(model.Flow{SrcIP: "192.0.2.5", DstIP: "203.0.113.9", Proto: "tcp", DPort: 443, PPS: 5000})
			if d.Action != model.ActionPermit {
				t.Fatalf("expected permit, got %+v", d)
			}
			if d.Stage != tc.stage || d.RuleID != "allow" {
				t.Fatalf("expected the permit rule to decide at %s, got %+v", tc.stage, d)
			}
		})
	}
}

// An explicit drop on the FPGA or ZC stage still has to drop.
func TestExplicitDropsStillDrop(t *testing.T) {
	prog := model.Program{
		Prefixes: []string{"203.0.113.0/24"},
		FPGA:     []model.FPGAEntry{{Table: "scrub_meter", Action: model.ActionDrop, RuleID: "fdrop", Match: model.Match{Proto: "udp"}}},
		ZC:       []model.ZCEntry{{Cluster: "zc:a", Action: model.ActionDrop, RuleID: "zdrop", Match: model.Match{Proto: "tcp"}}},
	}
	p := New(prog)
	if d := p.Decide(model.Flow{SrcIP: "192.0.2.5", DstIP: "203.0.113.9", Proto: "udp", PPS: 1}); d.Action != model.ActionDrop || d.Stage != model.StageFPGA {
		t.Fatalf("expected an FPGA drop, got %+v", d)
	}
	if d := p.Decide(model.Flow{SrcIP: "192.0.2.5", DstIP: "203.0.113.9", Proto: "tcp", PPS: 1}); d.Action != model.ActionDrop || d.Stage != model.StageZC {
		t.Fatalf("expected a ZC drop, got %+v", d)
	}
}

// The ZC cap is packets per second. It used to accumulate for the lifetime of the
// process, so any long-lived source eventually tripped a cap it never exceeded.
func TestZCCapIsARateNotALifetimeTotal(t *testing.T) {
	prog := model.Program{
		Prefixes: []string{"203.0.113.0/24"},
		ZC:       []model.ZCEntry{{Cluster: "zc:a", Action: model.ActionInspect, PPS: 100, RuleID: "zc", Match: model.Match{Proto: "tcp"}}},
	}
	p := New(prog)
	clock := time.Now()
	p.now = func() time.Time { return clock }

	flow := model.Flow{SrcIP: "192.0.2.5", DstIP: "203.0.113.9", Proto: "tcp", DPort: 443, PPS: 10}
	// Ten observations per second for an hour: 10 pps against a 100 pps cap.
	for i := 0; i < 3600; i++ {
		for j := 0; j < 10; j++ {
			if d := p.Decide(flow); d.Action != model.ActionPermit {
				t.Fatalf("second %d: a 100 pps flow was dropped by a 100 pps cap: %+v", i, d)
			}
		}
		clock = clock.Add(time.Second)
	}
}

func TestZCCapDropsASourceOverTheRate(t *testing.T) {
	prog := model.Program{
		Prefixes: []string{"203.0.113.0/24"},
		ZC:       []model.ZCEntry{{Cluster: "zc:a", Action: model.ActionInspect, PPS: 100, RuleID: "zc", Match: model.Match{Proto: "tcp"}}},
	}
	p := New(prog)
	clock := time.Now()
	p.now = func() time.Time { return clock }

	flow := model.Flow{SrcIP: "192.0.2.5", DstIP: "203.0.113.9", Proto: "tcp", DPort: 443, PPS: 60}
	if d := p.Decide(flow); d.Action != model.ActionPermit {
		t.Fatalf("60 pps is under the cap: %+v", d)
	}
	// 120 pps inside the same second is over the cap.
	if d := p.Decide(flow); d.Action != model.ActionDrop || d.Stage != model.StageZC {
		t.Fatalf("expected a ZC cap drop at 120 pps, got %+v", d)
	}
	// The next window starts clean.
	clock = clock.Add(time.Second)
	if d := p.Decide(flow); d.Action != model.ActionPermit {
		t.Fatalf("expected the cap to reset in a new window, got %+v", d)
	}
}

// The node agent reloads its program every couple of seconds. Reloading an
// unchanged program used to wipe the rate-limit counters, so a per-second cap
// could never be reached.
func TestLoadKeepsRateStateForSurvivingRules(t *testing.T) {
	prog := model.Program{
		Prefixes: []string{"203.0.113.0/24"},
		ZC:       []model.ZCEntry{{Cluster: "zc:a", Action: model.ActionInspect, PPS: 100, RuleID: "zc", Match: model.Match{Proto: "tcp"}}},
	}
	p := New(prog)
	clock := time.Now()
	p.now = func() time.Time { return clock }

	flow := model.Flow{SrcIP: "192.0.2.5", DstIP: "203.0.113.9", Proto: "tcp", DPort: 443, PPS: 60}
	p.Decide(flow)
	p.Load(prog) // identical program, as the agent polls it
	if d := p.Decide(flow); d.Action != model.ActionDrop {
		t.Fatalf("reloading an unchanged program reset the ZC counters: %+v", d)
	}
}

// State for a rule that is gone must not be kept around.
func TestLoadDropsRateStateForRemovedRules(t *testing.T) {
	prog := model.Program{
		Prefixes: []string{"203.0.113.0/24"},
		ZC:       []model.ZCEntry{{Cluster: "zc:a", Action: model.ActionInspect, PPS: 100, RuleID: "zc", Match: model.Match{Proto: "tcp"}}},
	}
	p := New(prog)
	p.Decide(model.Flow{SrcIP: "192.0.2.5", DstIP: "203.0.113.9", Proto: "tcp", DPort: 443, PPS: 60})
	if len(p.buckets) != 1 {
		t.Fatalf("expected one tracked source, got %d", len(p.buckets))
	}
	replacement := prog
	replacement.ZC = []model.ZCEntry{{Cluster: "zc:a", Action: model.ActionInspect, PPS: 100, RuleID: "other", Match: model.Match{Proto: "tcp"}}}
	p.Load(replacement)
	if len(p.buckets) != 0 {
		t.Fatalf("expected state for the removed rule to be dropped, got %d entries", len(p.buckets))
	}
}

// A spoofed flood presents unbounded source addresses. The per-source table has
// to stay bounded or the scrubbing node is itself the casualty.
func TestRateTableStaysBounded(t *testing.T) {
	prog := model.Program{
		Prefixes: []string{"203.0.113.0/24"},
		ZC:       []model.ZCEntry{{Cluster: "zc:a", Action: model.ActionInspect, PPS: 1000000, RuleID: "zc", Match: model.Match{Proto: "tcp"}}},
	}
	p := New(prog)
	clock := time.Now()
	p.now = func() time.Time { return clock }

	for i := 0; i < maxBuckets*3; i++ {
		src := netip.AddrFrom4([4]byte{10, byte(i >> 16), byte(i >> 8), byte(i)})
		p.Decide(model.Flow{SrcIP: src.String(), DstIP: "203.0.113.9", Proto: "tcp", DPort: 443, PPS: 1})
		if len(p.buckets) > maxBuckets {
			t.Fatalf("rate table grew past the bound: %d entries after %d sources", len(p.buckets), i+1)
		}
	}
}

// Expired windows must be reclaimed so a burst of one-off sources does not pin
// the table at its limit forever.
func TestExpiredRateStateIsReclaimed(t *testing.T) {
	prog := model.Program{
		Prefixes: []string{"203.0.113.0/24"},
		ZC:       []model.ZCEntry{{Cluster: "zc:a", Action: model.ActionInspect, PPS: 1000000, RuleID: "zc", Match: model.Match{Proto: "tcp"}}},
	}
	p := New(prog)
	clock := time.Now()
	p.now = func() time.Time { return clock }

	for i := 0; i < maxBuckets; i++ {
		src := netip.AddrFrom4([4]byte{10, byte(i >> 16), byte(i >> 8), byte(i)})
		p.Decide(model.Flow{SrcIP: src.String(), DstIP: "203.0.113.9", Proto: "tcp", DPort: 443, PPS: 1})
	}
	clock = clock.Add(2 * time.Second)
	// A new source now forces a sweep of the stale windows.
	p.Decide(model.Flow{SrcIP: "198.51.100.1", DstIP: "203.0.113.9", Proto: "tcp", DPort: 443, PPS: 1})
	if len(p.buckets) > 2 {
		t.Fatalf("expected the stale windows to be reclaimed, got %d entries", len(p.buckets))
	}
}

// A node that owns no prefixes must not enforce drops on everyone's traffic.
func TestNodeWithNoPrefixesEnforcesNothing(t *testing.T) {
	prog := model.Program{
		PolicyID: "pol-1",
		Prefixes: []string{},
		ASIC:     []model.ACLEntry{{Priority: 1, Action: model.ActionDrop, RuleID: "denyall", Match: model.Match{Proto: "tcp"}}},
	}
	p := New(prog)
	d := p.Decide(model.Flow{SrcIP: "192.0.2.5", DstIP: "203.0.113.9", Proto: "tcp", DPort: 443, PPS: 1})
	if d.Action != model.ActionPermit {
		t.Fatalf("a node holding no prefix assignment must not drop: %+v", d)
	}
}

func TestTrafficForAnotherNodesPrefixIsLeftAlone(t *testing.T) {
	prog := model.Program{
		Prefixes: []string{"203.0.113.0/24"},
		ASIC:     []model.ACLEntry{{Priority: 1, Action: model.ActionDrop, RuleID: "denyall", Match: model.Match{Proto: "tcp"}}},
	}
	p := New(prog)
	d := p.Decide(model.Flow{SrcIP: "192.0.2.5", DstIP: "198.18.0.1", Proto: "tcp", DPort: 443, PPS: 1})
	if d.Action != model.ActionPermit {
		t.Fatalf("expected traffic outside this node's prefixes to pass: %+v", d)
	}
}

// The ML stage must not act on a model that failed to load.
func TestZCInspectPassesWhenModelIsNotReady(t *testing.T) {
	prog := model.Program{
		Prefixes: []string{"203.0.113.0/24"},
		ZC:       []model.ZCEntry{{Cluster: "zc:a", Action: model.ActionInspect, RuleID: "zc", Match: model.Match{Proto: "tcp"}}},
	}
	p := New(prog)
	p.SetModel(ml.Model{})
	d := p.Decide(model.Flow{SrcIP: "192.0.2.5", DstIP: "203.0.113.9", Proto: "tcp", DPort: 443, PPS: 500000})
	if d.Action != model.ActionPermit || d.Reason != "PF_RING ZC inspect pass" {
		t.Fatalf("expected the inspect path to pass without a model, got %+v", d)
	}
}

func TestConcurrentDecideIsRaceFree(t *testing.T) {
	prog := model.Program{
		Prefixes: []string{"203.0.113.0/24"},
		ZC:       []model.ZCEntry{{Cluster: "zc:a", Action: model.ActionInspect, PPS: 100, RuleID: "zc", Match: model.Match{Proto: "tcp"}}},
	}
	p := New(prog)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				src := netip.AddrFrom4([4]byte{192, 0, 2, byte(i)})
				p.Decide(model.Flow{SrcIP: src.String(), DstIP: "203.0.113.9", Proto: "tcp", DPort: 443, PPS: 1})
				if j%50 == 0 {
					p.Load(prog)
					p.SetModel(ml.Model{})
				}
			}
		}(i)
	}
	wg.Wait()
}

// A Pipeline built without New must not panic: a nil clock or bucket map in a
// scrubbing node's hot path would be a crash under load.
func TestZeroValuePipelineDoesNotPanic(t *testing.T) {
	var p Pipeline
	p.Load(model.Program{
		Prefixes: []string{"203.0.113.0/24"},
		ZC:       []model.ZCEntry{{Cluster: "zc:a", Action: model.ActionInspect, PPS: 10, RuleID: "zc", Match: model.Match{Proto: "tcp"}}},
	})
	if d := p.Decide(model.Flow{SrcIP: "192.0.2.1", DstIP: "203.0.113.9", Proto: "tcp", DPort: 443, PPS: 1}); d.Action != model.ActionPermit {
		t.Fatalf("expected a permit, got %+v", d)
	}
}

// A count rule is observe-only. The meter and the behavioral cap used to apply
// to any action that reached them, so adding a rule to measure an attack
// started dropping it.
func TestCountRulesDoNotDrop(t *testing.T) {
	prog := model.Program{
		Prefixes: []string{"203.0.113.0/24"},
		FPGA:     []model.FPGAEntry{{Table: "scrub_meter", Action: model.ActionCount, Meter: 100, RuleID: "fcount", Match: model.Match{Proto: "udp"}}},
		ZC:       []model.ZCEntry{{Cluster: "zc:a", Action: model.ActionCount, PPS: 100, RuleID: "zcount", Match: model.Match{Proto: "tcp"}}},
	}
	p := New(prog)
	// Both flows are far over the rule's number, which an observe-only rule
	// must not act on.
	if d := p.Decide(model.Flow{SrcIP: "192.0.2.5", DstIP: "203.0.113.9", Proto: "udp", PPS: 50000}); d.Action != model.ActionPermit {
		t.Fatalf("an FPGA count rule dropped traffic: %+v", d)
	}
	if d := p.Decide(model.Flow{SrcIP: "192.0.2.5", DstIP: "203.0.113.9", Proto: "tcp", PPS: 50000}); d.Action != model.ActionPermit {
		t.Fatalf("a ZC count rule dropped traffic: %+v", d)
	}
}

// A count rule must not swallow the verdict either: a later rule still decides.
func TestCountRuleFallsThroughToTheNextRule(t *testing.T) {
	prog := model.Program{
		Prefixes: []string{"203.0.113.0/24"},
		ZC: []model.ZCEntry{
			{Cluster: "zc:a", Action: model.ActionCount, PPS: 1, RuleID: "zcount", Match: model.Match{Proto: "tcp"}},
			{Cluster: "zc:a", Action: model.ActionDrop, RuleID: "zdrop", Match: model.Match{Proto: "tcp", DPort: 443}},
		},
	}
	p := New(prog)
	d := p.Decide(model.Flow{SrcIP: "192.0.2.5", DstIP: "203.0.113.9", Proto: "tcp", DPort: 443, PPS: 10})
	if d.Action != model.ActionDrop || d.RuleID != "zdrop" {
		t.Fatalf("expected the drop rule behind the count rule to decide, got %+v", d)
	}
}

// Matches are compiled once at Load. A CIDR that does not parse has to keep
// failing closed the way the per-flow parse did: the rule never fires.
func TestUnparseableMatchCIDRNeverMatches(t *testing.T) {
	prog := model.Program{
		Prefixes: []string{"203.0.113.0/24"},
		ASIC:     []model.ACLEntry{{Priority: 1, Action: model.ActionDrop, RuleID: "bad", Match: model.Match{SrcCIDR: "not-a-cidr"}}},
	}
	p := New(prog)
	if d := p.Decide(model.Flow{SrcIP: "192.0.2.5", DstIP: "203.0.113.9", Proto: "tcp", PPS: 1}); d.Action != model.ActionPermit {
		t.Fatalf("a rule with an unparseable CIDR must never match, got %+v", d)
	}
}

// An unparseable protected prefix must not make the node claim everything.
func TestUnparseablePrefixDoesNotWidenOwnership(t *testing.T) {
	prog := model.Program{
		Prefixes: []string{"garbage"},
		ASIC:     []model.ACLEntry{{Priority: 1, Action: model.ActionDrop, RuleID: "denyall", Match: model.Match{Proto: "tcp"}}},
	}
	p := New(prog)
	if d := p.Decide(model.Flow{SrcIP: "192.0.2.5", DstIP: "203.0.113.9", Proto: "tcp", PPS: 1}); d.Reason != "prefix not assigned to this node" {
		t.Fatalf("expected the node to own nothing, got %+v", d)
	}
}

// Program identity has to include CompiledAt: a recompile can reassign
// prefixes without bumping the policy version, and a caller that skips the
// reload on an unchanged version would keep scrubbing the wrong prefixes.
func TestProgramIdentityTracksRecompiles(t *testing.T) {
	first := model.Program{PolicyID: "pol-1", Version: 1, CompiledAt: time.Unix(100, 0), Prefixes: []string{"203.0.113.0/24"}}
	p := New(first)
	id, version, compiled := p.Program()
	if id != "pol-1" || version != 1 || !compiled.Equal(first.CompiledAt) {
		t.Fatalf("unexpected program identity %s/%d/%v", id, version, compiled)
	}
	second := first
	second.CompiledAt = time.Unix(200, 0)
	second.Prefixes = []string{"198.51.100.0/24"}
	p.Load(second)
	if _, _, compiled := p.Program(); !compiled.Equal(second.CompiledAt) {
		t.Fatalf("expected the recompile to be visible, got %v", compiled)
	}
}

// BenchmarkDecide guards the hot path. Matching used to parse each rule's CIDR
// text for every flow, which cost about four times the comparison itself.
func BenchmarkDecide(b *testing.B) {
	prog := model.Program{NodeID: "n1", Prefixes: []string{"203.0.113.0/24"}}
	for i := 0; i < 20; i++ {
		prog.ASIC = append(prog.ASIC, model.ACLEntry{
			Action: model.ActionDrop,
			RuleID: fmt.Sprintf("acl-%d", i),
			Match:  model.Match{SrcCIDR: "198.51.100.0/24", DstCIDR: "203.0.113.0/24", Proto: "udp", DPort: 53},
		})
	}
	p := New(prog)
	f := model.Flow{SrcIP: "192.0.2.9", DstIP: "203.0.113.5", Proto: "tcp", DPort: 443, PPS: 10}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = p.Decide(f)
	}
}

func statsForRule(t *testing.T, s Stats, ruleID string) RuleStats {
	t.Helper()
	for _, r := range s.Rules {
		if r.RuleID == ruleID {
			return r
		}
	}
	t.Fatalf("no stats for rule %q in %+v", ruleID, s.Rules)
	return RuleStats{}
}

func stageOf(t *testing.T, s Stats, stage model.Stage) StageStats {
	t.Helper()
	for _, st := range s.Stages {
		if st.Stage == stage {
			return st
		}
	}
	t.Fatalf("no stats for stage %q", stage)
	return StageStats{}
}

// Counters are what tell an operator whether mitigation is working and which
// rule is doing the work.
func TestCountersAttributeDropsToTheDecidingRule(t *testing.T) {
	prog := model.Program{
		Prefixes: []string{"203.0.113.0/24"},
		ASIC:     []model.ACLEntry{{Priority: 1, Action: model.ActionDrop, RuleID: "tcam", Match: model.Match{Proto: "udp"}}},
		ZC:       []model.ZCEntry{{Cluster: "zc:a", Action: model.ActionInspect, RuleID: "zc", Match: model.Match{Proto: "tcp"}}},
	}
	p := New(prog)
	for i := 0; i < 3; i++ {
		p.Decide(model.Flow{SrcIP: "198.51.100.1", DstIP: "203.0.113.9", Proto: "udp", PPS: 1000})
	}
	p.Decide(model.Flow{SrcIP: "192.0.2.1", DstIP: "203.0.113.9", Proto: "tcp", DPort: 443, PPS: 20})
	// Traffic for a prefix this node does not hold.
	p.Decide(model.Flow{SrcIP: "192.0.2.1", DstIP: "198.18.0.1", Proto: "tcp", PPS: 7})

	s := p.Stats()
	if s.Decisions != 5 {
		t.Fatalf("expected 5 decisions, got %d", s.Decisions)
	}
	if s.Unowned != 1 {
		t.Fatalf("expected 1 unowned flow, got %d", s.Unowned)
	}
	tcam := statsForRule(t, s, "tcam")
	if tcam.Matches != 3 || tcam.Drops != 3 {
		t.Fatalf("expected 3 matches and 3 drops on the TCAM rule, got %+v", tcam)
	}
	if tcam.PPSDropped != 3000 {
		t.Fatalf("expected 3000 pps dropped, got %d", tcam.PPSDropped)
	}
	if tcam.Stage != model.StageASIC {
		t.Fatalf("expected the TCAM rule on the asic stage, got %q", tcam.Stage)
	}
	asic := stageOf(t, s, model.StageASIC)
	if asic.Dropped != 3 || asic.PPSDropped != 3000 {
		t.Fatalf("unexpected asic stage counters %+v", asic)
	}
	zc := statsForRule(t, s, "zc")
	if zc.Matches != 1 || zc.Drops != 0 || zc.PPSSeen != 20 {
		t.Fatalf("unexpected zc rule counters %+v", zc)
	}
	// The unowned flow is counted but attributed to no stage verdict.
	if got := stageOf(t, s, model.StageASIC).Permitted; got != 0 {
		t.Fatalf("an unowned flow must not count as a stage permit, got %d", got)
	}
}

// An observe-only rule still has to show what it saw; that is the whole point
// of adding one during an incident.
func TestCountRuleRecordsMatchesWithoutDrops(t *testing.T) {
	prog := model.Program{
		Prefixes: []string{"203.0.113.0/24"},
		ZC: []model.ZCEntry{
			{Cluster: "zc:a", Action: model.ActionCount, RuleID: "watch", Match: model.Match{Proto: "tcp"}},
			{Cluster: "zc:a", Action: model.ActionDrop, RuleID: "block", Match: model.Match{Proto: "tcp", DPort: 443}},
		},
	}
	p := New(prog)
	p.Decide(model.Flow{SrcIP: "192.0.2.1", DstIP: "203.0.113.9", Proto: "tcp", DPort: 443, PPS: 100})

	s := p.Stats()
	watch := statsForRule(t, s, "watch")
	if watch.Matches != 1 {
		t.Fatalf("the count rule saw the flow and must say so: %+v", watch)
	}
	if watch.Drops != 0 || watch.PPSDropped != 0 {
		t.Fatalf("an observe-only rule must not be credited with drops: %+v", watch)
	}
	block := statsForRule(t, s, "block")
	if block.Drops != 1 || block.PPSDropped != 100 {
		t.Fatalf("the drop must be attributed to the rule that decided: %+v", block)
	}
}

// The agent re-polls every couple of seconds. Resetting counters on every
// reprogram would make the series useless.
func TestCountersSurviveAReprogram(t *testing.T) {
	prog := model.Program{
		Prefixes: []string{"203.0.113.0/24"},
		ASIC:     []model.ACLEntry{{Priority: 1, Action: model.ActionDrop, RuleID: "tcam", Match: model.Match{Proto: "udp"}}},
	}
	p := New(prog)
	p.Decide(model.Flow{SrcIP: "198.51.100.1", DstIP: "203.0.113.9", Proto: "udp", PPS: 10})

	// Same rule, recompiled with a different prefix set.
	next := prog
	next.Prefixes = []string{"203.0.113.0/24", "198.51.0.0/16"}
	p.Load(next)
	p.Decide(model.Flow{SrcIP: "198.51.100.1", DstIP: "203.0.113.9", Proto: "udp", PPS: 10})

	if got := statsForRule(t, p.Stats(), "tcam"); got.Drops != 2 {
		t.Fatalf("expected the counter to carry across the reprogram, got %+v", got)
	}

	// A rule that is gone takes its series with it.
	p.Load(model.Program{Prefixes: []string{"203.0.113.0/24"},
		ASIC: []model.ACLEntry{{Priority: 1, Action: model.ActionDrop, RuleID: "other", Match: model.Match{Proto: "udp"}}}})
	for _, r := range p.Stats().Rules {
		if r.RuleID == "tcam" {
			t.Fatalf("a removed rule kept reporting: %+v", r)
		}
	}
}

// A rule ID reused on a different stage is a different series.
func TestMovingARuleToAnotherStageResetsItsCounters(t *testing.T) {
	p := New(model.Program{
		Prefixes: []string{"203.0.113.0/24"},
		ASIC:     []model.ACLEntry{{Priority: 1, Action: model.ActionDrop, RuleID: "r", Match: model.Match{Proto: "udp"}}},
	})
	p.Decide(model.Flow{SrcIP: "198.51.100.1", DstIP: "203.0.113.9", Proto: "udp", PPS: 10})
	p.Load(model.Program{
		Prefixes: []string{"203.0.113.0/24"},
		ZC:       []model.ZCEntry{{Cluster: "zc:a", Action: model.ActionDrop, RuleID: "r", Match: model.Match{Proto: "udp"}}},
	})
	got := statsForRule(t, p.Stats(), "r")
	if got.Stage != model.StageZC || got.Drops != 0 {
		t.Fatalf("expected a fresh series on the new stage, got %+v", got)
	}
}

func TestMLCountersTrackTheClassifier(t *testing.T) {
	p := New(model.Program{
		Prefixes: []string{"203.0.113.0/24"},
		ZC:       []model.ZCEntry{{Cluster: "zc:a", Action: model.ActionInspect, RuleID: "zc", Match: model.Match{Proto: "tcp"}}},
	})
	// Weights are zero and the bias is high, so every scored flow is an attack.
	p.SetModel(ml.Model{Weights: make([]float64, ml.FeatureCount), Bias: 50, Threshold: 0.5, Ready: true})
	p.Decide(model.Flow{SrcIP: "192.0.2.1", DstIP: "203.0.113.9", Proto: "tcp", DPort: 443, PPS: 10})

	s := p.Stats()
	if !s.ML.Ready || s.ML.Scored != 1 || s.ML.Drops != 1 || s.ML.Passes != 0 {
		t.Fatalf("unexpected ml counters %+v", s.ML)
	}
	if got := statsForRule(t, s, "zc"); got.Drops != 1 {
		t.Fatalf("an ml drop is still the zc rule's drop: %+v", got)
	}
}

// A hand-built flow with a negative rate must not wrap a counter.
func TestNegativeRateDoesNotWrapCounters(t *testing.T) {
	p := New(model.Program{
		Prefixes: []string{"203.0.113.0/24"},
		ASIC:     []model.ACLEntry{{Priority: 1, Action: model.ActionDrop, RuleID: "tcam", Match: model.Match{Proto: "udp"}}},
	})
	p.Decide(model.Flow{SrcIP: "198.51.100.1", DstIP: "203.0.113.9", Proto: "udp", PPS: -5})
	if got := statsForRule(t, p.Stats(), "tcam"); got.PPSDropped != 0 {
		t.Fatalf("a negative rate wrapped the counter: %d", got.PPSDropped)
	}
}

// The rate table is bounded; sitting at the bound means the cap has stopped
// tracking every source, which an operator needs to see.
func TestStatsReportRateTableOccupancy(t *testing.T) {
	p := New(model.Program{
		Prefixes: []string{"203.0.113.0/24"},
		ZC:       []model.ZCEntry{{Cluster: "zc:a", Action: model.ActionInspect, PPS: 1000000, RuleID: "zc", Match: model.Match{Proto: "tcp"}}},
	})
	if got := p.Stats(); got.RateBuckets != 0 || got.RateBucketsMax != maxBuckets {
		t.Fatalf("unexpected initial occupancy %+v", got)
	}
	p.Decide(model.Flow{SrcIP: "192.0.2.1", DstIP: "203.0.113.9", Proto: "tcp", PPS: 1})
	if got := p.Stats().RateBuckets; got != 1 {
		t.Fatalf("expected one tracked source, got %d", got)
	}
}

// Steering reacts to a rate, not a total, so the load window has to decay.
func TestLoadWindowReportsARateNotATotal(t *testing.T) {
	p := New(model.Program{Prefixes: []string{"203.0.113.0/24"}})
	clock := time.Unix(1_700_000_000, 0)
	p.now = func() time.Time { return clock }

	// 1000 pps every second for the whole window.
	for i := 0; i < loadWindowSeconds; i++ {
		p.Decide(model.Flow{SrcIP: "192.0.2.1", DstIP: "203.0.113.9", Proto: "tcp", PPS: 1000})
		clock = clock.Add(time.Second)
	}
	// The averaging window has not advanced past the samples yet.
	clock = clock.Add(-time.Second)
	if got := p.Stats().OfferedPPS; got != 1000 {
		t.Fatalf("expected a 1000 pps average, got %d", got)
	}

	// Go quiet: the average has to fall away rather than hold its peak.
	clock = clock.Add(2 * loadWindowSeconds * time.Second)
	if got := p.Stats().OfferedPPS; got != 0 {
		t.Fatalf("expected the load average to decay once traffic stopped, got %d", got)
	}
}

func TestLoadWindowSeparatesDroppedFromOffered(t *testing.T) {
	prog := model.Program{
		Prefixes: []string{"203.0.113.0/24"},
		ASIC:     []model.ACLEntry{{Priority: 1, Action: model.ActionDrop, RuleID: "tcam", Match: model.Match{Proto: "udp"}}},
	}
	p := New(prog)
	clock := time.Unix(1_700_000_000, 0)
	p.now = func() time.Time { return clock }

	p.Decide(model.Flow{SrcIP: "198.51.100.1", DstIP: "203.0.113.9", Proto: "udp", PPS: 8000})
	p.Decide(model.Flow{SrcIP: "192.0.2.1", DstIP: "203.0.113.9", Proto: "tcp", PPS: 2000})

	s := p.Stats()
	if s.OfferedPPS != 1000 {
		t.Fatalf("expected 10000 pps over a %ds window, got %d", loadWindowSeconds, s.OfferedPPS)
	}
	if s.DroppedPPS != 800 {
		t.Fatalf("expected only the dropped flow counted as dropped load, got %d", s.DroppedPPS)
	}
	if s.LoadWindowSeconds != loadWindowSeconds {
		t.Fatalf("stats should report the window they were averaged over, got %d", s.LoadWindowSeconds)
	}
}

// Traffic for a prefix this node does not carry still arrives and still costs
// it capacity, so it counts toward offered load.
func TestUnownedTrafficCountsAsLoad(t *testing.T) {
	p := New(model.Program{Prefixes: []string{"203.0.113.0/24"}})
	clock := time.Unix(1_700_000_000, 0)
	p.now = func() time.Time { return clock }
	p.Decide(model.Flow{SrcIP: "192.0.2.1", DstIP: "198.18.0.1", Proto: "tcp", PPS: 5000})
	if got := p.Stats().OfferedPPS; got != 500 {
		t.Fatalf("expected unowned traffic to count as load, got %d", got)
	}
}

// A bucket left behind by a quiet period must not be counted again when the
// ring wraps back onto it.
func TestStaleWindowBucketsAreNotRecounted(t *testing.T) {
	p := New(model.Program{Prefixes: []string{"203.0.113.0/24"}})
	clock := time.Unix(1_700_000_000, 0)
	p.now = func() time.Time { return clock }

	p.Decide(model.Flow{SrcIP: "192.0.2.1", DstIP: "203.0.113.9", Proto: "tcp", PPS: 10000})
	// Wrap the ring exactly, landing on the same bucket a full window later.
	clock = clock.Add(loadWindowSeconds * time.Second)
	p.Decide(model.Flow{SrcIP: "192.0.2.1", DstIP: "203.0.113.9", Proto: "tcp", PPS: 1000})
	if got := p.Stats().OfferedPPS; got != 100 {
		t.Fatalf("a stale bucket was counted again: got %d, expected only the fresh 1000 pps", got)
	}
}

var bedrockMagic = []byte{0x00, 0xff, 0xff, 0x00, 0xfe, 0xfe, 0xfe, 0xfe, 0xfd, 0xfd, 0xfd, 0xfd, 0x12, 0x34, 0x56, 0x78}

func gameProgram(observe bool) model.Program {
	return model.Program{
		PolicyID: "pol-1", Version: 1,
		Prefixes: []string{"203.0.113.0/24"},
		Games: []model.GameFilter{{
			ID: "bedrock", DstCIDR: "203.0.113.0/24", Proto: "udp", DPort: 19132,
			Profile: "raknet", Observe: observe,
		}},
		ChallengeSecret: "0011223344556677",
		ZC: []model.ZCEntry{{Cluster: "zc:a", Action: model.ActionInspect, PPS: 1000000,
			RuleID: "zc", Match: model.Match{Proto: "udp"}}},
	}
}

func gameFlow(payload []byte) model.Flow {
	return model.Flow{
		SrcIP: "192.0.2.50", DstIP: "203.0.113.10", Proto: "udp", DPort: 19132,
		PPS: 500, Payload: payload,
	}
}

// A flood with the right port and nothing else right dies at the ZC stage,
// before it reaches the behavioural cap or the classifier.
func TestGameFilterDropsJunkOnTheGamePort(t *testing.T) {
	p := New(gameProgram(false))
	d := p.Decide(gameFlow(bytes.Repeat([]byte{0x41}, 1200)))
	if d.Action != model.ActionDrop || d.Stage != model.StageZC {
		t.Fatalf("expected a ZC drop, got %+v", d)
	}
	if d.Filter != "bedrock" {
		t.Fatalf("the decision should name the filter, got %+v", d)
	}

	s := p.Stats()
	if len(s.Games) != 1 || s.Games[0].Dropped != 1 || s.Games[0].Inspected != 1 {
		t.Fatalf("unexpected filter counters %+v", s.Games)
	}
	if s.Games[0].PPSDropped != 500 {
		t.Fatalf("expected the dropped rate counted, got %d", s.Games[0].PPSDropped)
	}
}

// Real protocol traffic gets through the filter and on to the normal ZC path.
func TestGameFilterAdmitsRealTraffic(t *testing.T) {
	p := New(gameProgram(false))
	if d := p.Decide(gameFlow(append([]byte{0x07}, bedrockMagic...))); d.Action != model.ActionPermit {
		t.Fatalf("expected the handshake to pass, got %+v", d)
	}
	d := p.Decide(gameFlow([]byte{0x84, 0x01, 0x02}))
	if d.Action != model.ActionPermit {
		t.Fatalf("expected a connected source to pass, got %+v", d)
	}
	// Having cleared the filter, the verdict came from the ZC rule behind it.
	if d.RuleID != "zc" {
		t.Fatalf("expected the ZC rule to decide once the filter passed, got %+v", d)
	}
}

// The filter only looks at the port it was bound to.
func TestGameFilterLeavesOtherPortsAlone(t *testing.T) {
	p := New(gameProgram(false))
	f := gameFlow(bytes.Repeat([]byte{0x41}, 1200))
	f.DPort = 443
	if d := p.Decide(f); d.Action != model.ActionPermit || d.Filter != "" {
		t.Fatalf("traffic on another port was judged by the game filter: %+v", d)
	}
}

// A record with no payload must not be dropped: the filter cannot judge what
// it was not given, and the control plane's own /decide sends none.
func TestGameFilterPassesRecordsWithNoPayload(t *testing.T) {
	p := New(gameProgram(false))
	d := p.Decide(model.Flow{SrcIP: "192.0.2.50", DstIP: "203.0.113.10", Proto: "udp", DPort: 19132, PPS: 10})
	if d.Action != model.ActionPermit {
		t.Fatalf("a payload-less record must not be dropped, got %+v", d)
	}
	if got := p.Stats().Games[0].Uninspectable; got != 1 {
		t.Fatalf("expected the uninspectable packet counted, got %d", got)
	}
}

func TestGameFilterObserveModeDoesNotDrop(t *testing.T) {
	p := New(gameProgram(true))
	if d := p.Decide(gameFlow(bytes.Repeat([]byte{0x41}, 1200))); d.Action == model.ActionDrop {
		t.Fatalf("observe mode must not drop, got %+v", d)
	}
}

// A challenged packet is dropped and carries the reply the datapath emits.
func TestGameFilterChallengeCarriesAReply(t *testing.T) {
	prog := gameProgram(false)
	prog.Games[0] = model.GameFilter{
		ID: "a2s", DstCIDR: "203.0.113.0/24", Proto: "udp", DPort: 27015, Profile: "a2s",
	}
	p := New(prog)
	f := gameFlow([]byte{0xFF, 0xFF, 0xFF, 0xFF, 'U'})
	f.DPort = 27015
	d := p.Decide(f)
	if d.Action != model.ActionChallenge {
		t.Fatalf("expected a challenge, got %+v", d)
	}
	if len(d.Reply) == 0 {
		t.Fatal("a challenge must carry the reply to emit")
	}
	if got := p.Stats().Games[0].Challenged; got != 1 {
		t.Fatalf("expected the challenge counted, got %d", got)
	}
	// A challenged packet never reaches the server, so it counts as dropped
	// at the stage that decided.
	if got := stageOf(t, p.Stats(), model.StageZC).Dropped; got != 1 {
		t.Fatalf("expected the challenge booked as a stage drop, got %d", got)
	}
}

// Counters and sessions survive a reprogram, which arrives every couple of
// seconds.
func TestGameFilterStateSurvivesAReprogram(t *testing.T) {
	prog := gameProgram(false)
	p := New(prog)
	p.Decide(gameFlow(append([]byte{0x07}, bedrockMagic...))) // this source completes the handshake
	// A different source that never connected: RakNet's framing is
	// permissive once connected, so the gate is what stops this, not the
	// signature.
	junk := gameFlow([]byte{0x84, 0x01, 0x02})
	junk.SrcIP = "198.51.100.9"
	if d := p.Decide(junk); d.Action != model.ActionDrop {
		t.Fatalf("expected an unconnected source to be dropped, got %+v", d)
	}

	next := prog
	next.CompiledAt = prog.CompiledAt.Add(time.Second)
	p.Load(next)

	if got := p.Stats().Games[0].Dropped; got != 1 {
		t.Fatalf("expected the filter counter to carry across a reprogram, got %d", got)
	}
	if d := p.Decide(gameFlow([]byte{0x84, 0x01})); d.Action != model.ActionPermit {
		t.Fatalf("a reprogram re-challenged a connected player: %+v", d)
	}
}

// A filter that cannot be compiled must not take the datapath down.
func TestUncompilableGameFilterLeavesTheDatapathRunning(t *testing.T) {
	prog := gameProgram(false)
	prog.Games[0].Profile = "no-such-game"
	p := New(prog)
	if d := p.Decide(gameFlow(bytes.Repeat([]byte{0x41}, 1200))); d.Action != model.ActionPermit {
		t.Fatalf("expected the datapath to keep running without the filter, got %+v", d)
	}
	if got := len(p.Stats().Games); got != 0 {
		t.Fatalf("expected no filter counters, got %d", got)
	}
}

// A custom signature covers a game the platform ships no profile for.
func TestCustomGameSignature(t *testing.T) {
	prog := gameProgram(false)
	prog.Games[0] = model.GameFilter{
		ID: "inhouse", DstCIDR: "203.0.113.0/24", Proto: "udp", DPort: 19132,
		Custom: &model.GameSignature{
			MinLen: 8, MaxLen: 512,
			Magic: []model.GameMagic{{Offset: 0, Hex: "deadbeef"}},
		},
	}
	p := New(prog)
	if d := p.Decide(gameFlow(append([]byte{0xde, 0xad, 0xbe, 0xef}, bytes.Repeat([]byte{0x01}, 8)...))); d.Action != model.ActionPermit {
		t.Fatalf("expected the custom protocol to pass, got %+v", d)
	}
	if d := p.Decide(gameFlow(bytes.Repeat([]byte{0x41}, 64))); d.Action != model.ActionDrop {
		t.Fatalf("expected junk to be dropped by the custom signature, got %+v", d)
	}
}

// BenchmarkDecideGameFiltered guards the cost of the game filter on the hot
// path, for a policy that binds one. BenchmarkDecide covers the common case
// of a policy that binds none.
func BenchmarkDecideGameFiltered(b *testing.B) {
	prog := gameProgram(false)
	// No behavioural cap: this measures the path an admitted player takes,
	// not the rate limiter's drop path, which formats a reason and is not
	// what the game filter costs.
	prog.ZC[0].PPS = 0
	for i := 0; i < 20; i++ {
		prog.ASIC = append(prog.ASIC, model.ACLEntry{
			Action: model.ActionDrop,
			RuleID: fmt.Sprintf("acl-%d", i),
			Match:  model.Match{SrcCIDR: "198.51.100.0/24", DstCIDR: "203.0.113.0/24", Proto: "tcp", DPort: 53},
		})
	}
	p := New(prog)
	// An admitted source sending gameplay: the path a real player takes.
	p.Decide(gameFlow(append([]byte{0x07}, bedrockMagic...)))
	f := gameFlow([]byte{0x84, 0x01, 0x02, 0x03})
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = p.Decide(f)
	}
}

// The fixed window let a source send its whole allowance at the end of one
// window and again at the start of the next: twice the cap, and exactly
// the shape a pulse attack sends.
func TestCapCannotBeDoubledAcrossAWindowBoundary(t *testing.T) {
	prog := model.Program{
		Prefixes: []string{"203.0.113.0/24"},
		ZC:       []model.ZCEntry{{Cluster: "zc:a", Action: model.ActionInspect, PPS: 100, RuleID: "zc", Match: model.Match{Proto: "tcp"}}},
	}
	p := New(prog)
	clock := time.Unix(1_700_000_000, 0)
	p.now = func() time.Time { return clock }

	flow := model.Flow{SrcIP: "192.0.2.5", DstIP: "203.0.113.9", Proto: "tcp", DPort: 443, PPS: 100}
	if d := p.Decide(flow); d.Action != model.ActionPermit {
		t.Fatalf("the first allowance is within the cap: %+v", d)
	}
	// Straddle the old window boundary: the whole allowance again, a moment
	// later. The trailing window still sees the first one.
	clock = clock.Add(rateWindow - rateSlotSpan/2)
	if d := p.Decide(flow); d.Action != model.ActionDrop {
		t.Fatalf("200 pps inside a trailing second must be dropped, got %+v", d)
	}
}

// A source genuinely under its cap stays under it, however the packets fall
// inside the second. This is what the usual weighted estimate gets wrong.
func TestASourceAtItsCapIsNotDropped(t *testing.T) {
	prog := model.Program{
		Prefixes: []string{"203.0.113.0/24"},
		ZC:       []model.ZCEntry{{Cluster: "zc:a", Action: model.ActionInspect, PPS: 100, RuleID: "zc", Match: model.Match{Proto: "tcp"}}},
	}
	p := New(prog)
	clock := time.Unix(1_700_000_000, 0)
	p.now = func() time.Time { return clock }

	flow := model.Flow{SrcIP: "192.0.2.5", DstIP: "203.0.113.9", Proto: "tcp", DPort: 443, PPS: 25}
	// 100 pps delivered as four bursts a second, for a minute.
	for second := 0; second < 60; second++ {
		for i := 0; i < 4; i++ {
			if d := p.Decide(flow); d.Action != model.ActionPermit {
				t.Fatalf("second %d: a 100 pps flow was dropped by a 100 pps cap: %+v", second, d)
			}
			clock = clock.Add(rateSlotSpan)
		}
	}
}

// The datapath measures pulses per protected prefix, at a resolution short
// enough to see a burst.
func TestPipelineRecognisesABurstTrain(t *testing.T) {
	prog := model.Program{
		Prefixes:      []string{"203.0.113.0/24"},
		PulseFloorPPS: 1000,
	}
	p := New(prog)
	clock := time.Unix(1_700_000_000, 0)
	p.now = func() time.Time { return clock }

	flow := model.Flow{SrcIP: "198.51.100.5", DstIP: "203.0.113.9", Proto: "udp", PPS: 400_000}
	for i := 0; i < 4; i++ {
		p.Decide(flow)
		clock = clock.Add(10 * time.Second)
	}

	s := p.Stats()
	if !s.Pulsing {
		t.Fatalf("expected a burst train recognised, got %+v", s.Pulse)
	}
	if s.PulsePeakPPS != 400_000 {
		t.Fatalf("expected the peak reported, got %d", s.PulsePeakPPS)
	}
	if len(s.Pulse) != 1 || s.Pulse[0].Prefix != "203.0.113.0/24" {
		t.Fatalf("expected the attacked prefix named, got %+v", s.Pulse)
	}
	// The mean is what a watermark would have seen, and it is nothing.
	if s.Pulse[0].MeanPPS*4 > s.Pulse[0].PeakPPS {
		t.Fatalf("this test is not exercising a low average: %+v", s.Pulse[0])
	}
}

// Steady traffic is not a pulse, so the flag does not stand for ordinary
// load.
func TestPipelineDoesNotFlagSteadyTraffic(t *testing.T) {
	p := New(model.Program{Prefixes: []string{"203.0.113.0/24"}, PulseFloorPPS: 1000})
	clock := time.Unix(1_700_000_000, 0)
	p.now = func() time.Time { return clock }

	flow := model.Flow{SrcIP: "192.0.2.5", DstIP: "203.0.113.9", Proto: "udp", PPS: 50_000}
	for i := 0; i < 240; i++ {
		p.Decide(flow)
		clock = clock.Add(250 * time.Millisecond)
	}
	if s := p.Stats(); s.Pulsing {
		t.Fatalf("steady traffic was flagged as a burst train: %+v", s.Pulse)
	}
}

// Prefixes the policy no longer protects are forgotten.
func TestPipelineForgetsPulsesForDroppedPrefixes(t *testing.T) {
	prog := model.Program{Prefixes: []string{"203.0.113.0/24"}, PulseFloorPPS: 1000}
	p := New(prog)
	p.Decide(model.Flow{SrcIP: "198.51.100.5", DstIP: "203.0.113.9", Proto: "udp", PPS: 5000})
	if len(p.Stats().Pulse) != 1 {
		t.Fatal("expected the prefix tracked")
	}
	next := prog
	next.Prefixes = []string{"198.18.0.0/24"}
	p.Load(next)
	if got := len(p.Stats().Pulse); got != 0 {
		t.Fatalf("expected the dropped prefix forgotten, got %d tracked", got)
	}
}
