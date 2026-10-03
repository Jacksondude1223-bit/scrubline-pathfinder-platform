package pipeline

import (
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
	nodes := []model.Node{{ID: "node-a", Name: "scrub-a", CapacityGbps: 100}}
	assigned := compiler.Assign(policy.Protected, nodes)
	progs := compiler.Compile(policy, nodes, assigned)
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

func TestAssignmentSpreads(t *testing.T) {
	nodes := []model.Node{
		{ID: "a", CapacityGbps: 10},
		{ID: "b", CapacityGbps: 10},
		{ID: "c", CapacityGbps: 10},
	}
	prefixes := []string{"203.0.113.0/24", "203.0.114.0/24", "203.0.115.0/24", "203.0.116.0/24", "198.51.100.0/24", "192.0.2.0/24"}
	got := compiler.Assign(prefixes, nodes)
	seen := map[string]bool{}
	for _, a := range got {
		seen[a.NodeID] = true
	}
	if len(seen) < 2 {
		t.Fatalf("expected prefixes across nodes, got %+v", got)
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
	if got := p.bucketCount(); got != 1 {
		t.Fatalf("expected one tracked source, got %d", got)
	}
	replacement := prog
	replacement.ZC = []model.ZCEntry{{Cluster: "zc:a", Action: model.ActionInspect, PPS: 100, RuleID: "other", Match: model.Match{Proto: "tcp"}}}
	p.Load(replacement)
	if got := p.bucketCount(); got != 0 {
		t.Fatalf("expected state for the removed rule to be dropped, got %d entries", got)
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
		if i%1000 == 0 {
			if got := p.bucketCount(); got > maxBuckets {
				t.Fatalf("rate table grew past the bound: %d entries after %d sources", got, i+1)
			}
		}
	}
}

// A shard that has hit its bound must start accepting sources again once its
// windows close. Reclamation is deliberately lazy - it only runs when a shard
// is actually full - so this fills one shard deterministically rather than
// assuming the whole table is swept.
func TestFullShardAcceptsSourcesAgainAfterItsWindowCloses(t *testing.T) {
	prog := model.Program{
		Prefixes: []string{"203.0.113.0/24"},
		ZC:       []model.ZCEntry{{Cluster: "zc:a", Action: model.ActionInspect, PPS: 1000000, RuleID: "zc", Match: model.Match{Proto: "tcp"}}},
	}
	p := New(prog)
	clock := time.Now()
	p.now = func() time.Time { return clock }

	// Collect enough sources that all hash to one shard to fill it exactly.
	target := shardIndex(rateKey{rule: "zc", src: "203.0.113.1"})
	var ips []string
	for i := 0; len(ips) < shardBuckets && i < 1<<22; i++ {
		ip := netip.AddrFrom4([4]byte{10, byte(i >> 16), byte(i >> 8), byte(i)}).String()
		if shardIndex(rateKey{rule: "zc", src: ip}) == target {
			ips = append(ips, ip)
		}
	}
	if len(ips) < shardBuckets {
		t.Fatalf("only found %d sources for shard %d", len(ips), target)
	}
	for _, ip := range ips {
		p.Decide(model.Flow{SrcIP: ip, DstIP: "203.0.113.9", Proto: "tcp", DPort: 443, PPS: 1})
	}
	sh := &p.shards[target]
	sh.mu.Lock()
	filled := len(sh.buckets)
	sh.mu.Unlock()
	if filled != shardBuckets {
		t.Fatalf("expected the shard at its bound, got %d of %d", filled, shardBuckets)
	}

	// Inside the same window the shard is full, so a new source goes untracked.
	fresh := ips[0]
	for i := 0; ; i++ {
		ip := netip.AddrFrom4([4]byte{172, byte(i >> 16), byte(i >> 8), byte(i)}).String()
		if shardIndex(rateKey{rule: "zc", src: ip}) == target {
			fresh = ip
			break
		}
	}
	p.Decide(model.Flow{SrcIP: fresh, DstIP: "203.0.113.9", Proto: "tcp", DPort: 443, PPS: 1})
	sh.mu.Lock()
	_, tracked := sh.buckets[rateKey{rule: "zc", src: fresh}]
	stillFull := len(sh.buckets)
	sh.mu.Unlock()
	if tracked {
		t.Fatal("a full shard must not admit another source inside the window")
	}
	if stillFull != shardBuckets {
		t.Fatalf("the bound must hold, got %d of %d", stillFull, shardBuckets)
	}

	// Once the windows close, the shard reclaims and takes the source.
	clock = clock.Add(2 * time.Second)
	p.Decide(model.Flow{SrcIP: fresh, DstIP: "203.0.113.9", Proto: "tcp", DPort: 443, PPS: 1})
	sh.mu.Lock()
	_, nowTracked := sh.buckets[rateKey{rule: "zc", src: fresh}]
	after := len(sh.buckets)
	sh.mu.Unlock()
	if !nowTracked {
		t.Fatal("expected the shard to accept the source after reclaiming closed windows")
	}
	if after > shardBuckets {
		t.Fatalf("shard grew past its bound: %d", after)
	}
	if after != 1 {
		t.Fatalf("expected the stale windows to be swept, leaving one entry, got %d", after)
	}
}

// reclaim drops closed windows and keeps open ones, and scans at most once per
// window so a full shard cannot be made to rescan per packet.
func TestShardReclaimSemantics(t *testing.T) {
	now := time.Now()
	sh := &rateShard{buckets: map[rateKey]*bucket{}}
	keyA := rateKey{rule: "zc", src: "a"}
	keyB := rateKey{rule: "zc", src: "b"}
	keyC := rateKey{rule: "zc", src: "c"}
	sh.buckets[keyA] = &bucket{windowStart: now.Add(-2 * time.Second)}
	sh.buckets[keyB] = &bucket{windowStart: now}
	if !sh.reclaim(now) {
		t.Fatal("expected room after reclaiming a closed window")
	}
	if _, stale := sh.buckets[keyA]; stale {
		t.Fatal("expected the closed window to be dropped")
	}
	if _, live := sh.buckets[keyB]; !live {
		t.Fatal("expected the open window to be kept")
	}
	// A second call inside the same window must not rescan.
	sh.buckets[keyC] = &bucket{windowStart: now.Add(-2 * time.Second)}
	sh.reclaim(now)
	if _, present := sh.buckets[keyC]; !present {
		t.Fatal("expected the throttle to skip a second sweep inside the same window")
	}
}

// Keys must land on a stable shard, or a source's counter would move between
// shards and its rate would never accumulate.
func TestShardIndexIsStableAndInRange(t *testing.T) {
	for i := 0; i < 2000; i++ {
		key := rateKey{rule: "zc", src: netip.AddrFrom4([4]byte{10, byte(i >> 16), byte(i >> 8), byte(i)}).String()}
		first := shardIndex(key)
		if first >= rateShards {
			t.Fatalf("shard %d out of range for %q", first, key)
		}
		if again := shardIndex(key); again != first {
			t.Fatalf("shard for %q moved: %d then %d", key, first, again)
		}
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
