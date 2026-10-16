package compiler

import (
	"fmt"
	"math"
	"reflect"
	"strings"
	"testing"

	"github.com/Jacksondude1223-bit/scrubline-cloud-scrub/internal/model"
)

func ready(id, name, region string, capacity float64) model.Node {
	return model.Node{ID: id, Name: name, Region: region, CapacityGbps: capacity, Status: model.NodeReady}
}

func policyFor(prefixes ...string) model.Policy {
	return model.Policy{ID: "pol-1", Version: 1, Protected: prefixes}
}

func rowFor(t *testing.T, plan []model.Announcement, prefix, nodeID string) model.Announcement {
	t.Helper()
	for _, a := range plan {
		if a.Prefix == prefix && a.NodeID == nodeID {
			return a
		}
	}
	t.Fatalf("no announcement for %s on %s in %+v", prefix, nodeID, plan)
	return model.Announcement{}
}

// The fabric is anycast: every eligible node announces every protected
// prefix, so an attack on one prefix is absorbed by the whole fabric instead
// of landing on whichever node happened to win a hash.
func TestEveryLiveNodeAnnouncesEveryPrefix(t *testing.T) {
	nodes := []model.Node{ready("node-a", "a", "iad", 100), ready("node-b", "b", "fra", 100), ready("node-c", "c", "sin", 100)}
	policy := policyFor("203.0.113.0/24", "198.51.100.0/24")

	plan := Plan(policy, nodes, nil)
	if len(plan) != len(policy.Protected)*len(nodes) {
		t.Fatalf("expected every node to announce every prefix, got %d rows", len(plan))
	}
	for _, prefix := range policy.Protected {
		for _, n := range nodes {
			if got := rowFor(t, plan, prefix, n.ID); got.State != model.StateAnnounce {
				t.Fatalf("%s on %s: expected an announcement, got %+v", prefix, n.ID, got)
			}
		}
	}
}

// Capacity is weighted with AS-path prepends rather than by picking a winner:
// the largest node announces unpadded and each halving costs one prepend.
func TestCapacityIsWeightedWithPrepends(t *testing.T) {
	nodes := []model.Node{
		ready("node-big", "big", "iad", 400),
		ready("node-half", "half", "fra", 200),
		ready("node-quarter", "quarter", "sin", 100),
	}
	plan := Plan(policyFor("203.0.113.0/24"), nodes, nil)
	for id, want := range map[string]int{"node-big": 0, "node-half": 1, "node-quarter": 2} {
		if got := rowFor(t, plan, "203.0.113.0/24", id).Prepends; got != want {
			t.Fatalf("%s: expected %d prepends, got %d", id, want, got)
		}
	}
}

// Padding is bounded: past a handful of prepends upstreams stop telling paths
// apart, and a very long path invites filtering.
func TestPrependsAreBounded(t *testing.T) {
	nodes := []model.Node{ready("node-big", "big", "iad", 1e9), ready("node-tiny", "tiny", "sin", 1)}
	got := rowFor(t, Plan(policyFor("203.0.113.0/24"), nodes, nil), "203.0.113.0/24", "node-tiny").Prepends
	if got != MaxPrepends {
		t.Fatalf("expected padding clamped to %d, got %d", MaxPrepends, got)
	}
}

// A capacity that cannot be compared must make a node less attractive, not
// the most attractive path in the fabric. Converting such a value straight
// into the arithmetic is how one node used to capture everything.
func TestBogusCapacityShedsTrafficRatherThanAttractingIt(t *testing.T) {
	for _, bogus := range []float64{-1, -1e9, math.NaN(), math.Inf(-1), math.Inf(1), 0} {
		nodes := []model.Node{
			ready("node-a", "a", "iad", 100),
			ready("node-evil", "evil", "sin", bogus),
		}
		plan := Plan(policyFor("203.0.113.0/24"), nodes, nil)
		evil := rowFor(t, plan, "203.0.113.0/24", "node-evil")
		good := rowFor(t, plan, "203.0.113.0/24", "node-a")
		if evil.Prepends <= good.Prepends {
			t.Fatalf("capacity %v was not padded away: evil=%d good=%d", bogus, evil.Prepends, good.Prepends)
		}
		if evil.Prepends != MaxPrepends {
			t.Fatalf("capacity %v should be padded to the maximum, got %d", bogus, evil.Prepends)
		}
	}
}

// A node past its heartbeat TTL is withdrawn. That withdrawal is the
// failover: its share of the traffic moves to the nodes still answering,
// without anything being reassigned.
func TestStaleNodesAreWithdrawn(t *testing.T) {
	nodes := []model.Node{
		ready("node-a", "a", "iad", 100),
		{ID: "node-dead", Name: "dead", Region: "sin", CapacityGbps: 100, Status: model.NodeStale},
	}
	plan := Plan(policyFor("203.0.113.0/24"), nodes, nil)

	dead := rowFor(t, plan, "203.0.113.0/24", "node-dead")
	if dead.State != model.StateWithdraw {
		t.Fatalf("expected the stale node withdrawn, got %+v", dead)
	}
	if dead.Reason == "" {
		t.Fatal("a withdrawal must say why")
	}
	if live := rowFor(t, plan, "203.0.113.0/24", "node-a"); live.State != model.StateAnnounce {
		t.Fatalf("the surviving node must keep announcing, got %+v", live)
	}
}

// Region pinning is a hard boundary: a node outside the listed regions
// neither announces the prefix nor enforces policy on it.
func TestRegionPinningExcludesNodesEntirely(t *testing.T) {
	nodes := []model.Node{ready("node-eu", "eu", "fra", 100), ready("node-us", "us", "iad", 100)}
	policy := policyFor("203.0.113.0/24", "198.51.100.0/24")
	policy.Steering = []model.Steering{{Prefix: "203.0.113.0/24", Regions: []string{"FRA"}}}

	plan := Plan(policy, nodes, nil)
	for _, a := range plan {
		if a.Prefix == "203.0.113.0/24" && a.NodeID == "node-us" {
			t.Fatalf("a pinned prefix was announced outside its regions: %+v", a)
		}
	}
	// Matching is case-insensitive, and the unpinned prefix is unaffected.
	rowFor(t, plan, "203.0.113.0/24", "node-eu")
	rowFor(t, plan, "198.51.100.0/24", "node-us")

	if got := EnforcedPrefixes(policy, nodes[1]); len(got) != 1 || got[0] != "198.51.100.0/24" {
		t.Fatalf("a node outside the pinned regions must not enforce the prefix, got %v", got)
	}
	if got := EnforcedPrefixes(policy, nodes[0]); len(got) != 2 {
		t.Fatalf("the pinned node should enforce both prefixes, got %v", got)
	}
}

// A withdrawn node still enforces: BGP takes time to converge, and traffic
// still arriving for a withdrawn prefix should be scrubbed, not waved through.
func TestWithdrawnNodesStillEnforce(t *testing.T) {
	dead := model.Node{ID: "node-dead", Name: "dead", Region: "sin", CapacityGbps: 100, Status: model.NodeStale}
	policy := policyFor("203.0.113.0/24")
	if got := rowFor(t, Plan(policy, []model.Node{dead}, nil), "203.0.113.0/24", "node-dead").State; got != model.StateWithdraw {
		t.Fatalf("expected a withdrawal, got %q", got)
	}
	if got := EnforcedPrefixes(policy, dead); len(got) != 1 {
		t.Fatalf("a withdrawing node must keep enforcing during convergence, got %v", got)
	}
}

func TestSteeringCommunitiesRideOnTheAnnouncement(t *testing.T) {
	nodes := []model.Node{ready("node-a", "a", "iad", 100)}
	policy := policyFor("203.0.113.0/24")
	policy.Steering = []model.Steering{{Prefix: "203.0.113.0/24", Communities: []string{"65000:100", "no-export"}}}
	got := rowFor(t, Plan(policy, nodes, nil), "203.0.113.0/24", "node-a")
	if !reflect.DeepEqual(got.Communities, []string{"65000:100", "no-export"}) {
		t.Fatalf("unexpected communities %v", got.Communities)
	}
}

// The next hop upstreams route to is the address the node advertised.
func TestNextHopComesFromTheAdvertisedAddress(t *testing.T) {
	n := ready("node-a", "a", "iad", 100)
	n.Advertise = "198.51.100.7:9091"
	if got := rowFor(t, Plan(policyFor("203.0.113.0/24"), []model.Node{n}, nil), "203.0.113.0/24", "node-a").NextHop; got != "198.51.100.7" {
		t.Fatalf("expected the advertised host as next hop, got %q", got)
	}
	bare := ready("node-b", "b", "iad", 100)
	if got := rowFor(t, Plan(policyFor("203.0.113.0/24"), []model.Node{bare}, nil), "203.0.113.0/24", "node-b").NextHop; got != "" {
		t.Fatalf("a node that advertised nothing should carry no next hop, got %q", got)
	}
}

func TestPlanIsDeterministic(t *testing.T) {
	nodes := []model.Node{ready("node-b", "b", "fra", 80), ready("node-a", "a", "iad", 100)}
	policy := policyFor("203.0.113.0/24", "198.51.100.0/24")
	first := Plan(policy, nodes, nil)
	for i := 0; i < 20; i++ {
		if got := Plan(policy, nodes, nil); !reflect.DeepEqual(got, first) {
			t.Fatalf("plan is not stable: %+v then %+v", first, got)
		}
	}
	// Sorted by prefix, then node.
	if first[0].Prefix != "198.51.100.0/24" || first[0].NodeID != "node-a" {
		t.Fatalf("expected the plan sorted by prefix then node, got %+v", first[0])
	}
}

func TestPlanWithNoNodes(t *testing.T) {
	if got := Plan(policyFor("203.0.113.0/24"), nil, nil); len(got) != 0 {
		t.Fatalf("expected an empty plan without nodes, got %+v", got)
	}
}

// A node holding no prefixes must serialize as an empty list, not null, so the
// agent can tell "assigned nothing" from "field absent".
func TestCompileEmitsEmptyPrefixListNotNil(t *testing.T) {
	policy := model.Policy{
		ID: "pol-1", Version: 1,
		Protected: []string{"203.0.113.0/24"},
		Rules:     []model.Rule{{ID: "r", Stage: model.StageASIC, Action: model.ActionDrop}},
	}
	nodes := []model.Node{{ID: "node-a", Name: "a", CapacityGbps: 10}, {ID: "node-b", Name: "b", CapacityGbps: 10}}
	assigned := Plan(policy, nodes, nil)
	progs := Compile(policy, nodes, assigned)
	if len(progs) != len(nodes) {
		t.Fatalf("expected a program per node, got %d", len(progs))
	}
	for id, prog := range progs {
		if prog.Prefixes == nil {
			t.Fatalf("node %s got a nil prefix list", id)
		}
	}
}

func TestCompileSortsACLByPriority(t *testing.T) {
	policy := model.Policy{
		ID: "pol-1", Version: 1,
		Protected: []string{"203.0.113.0/24"},
		Rules: []model.Rule{
			{ID: "low", Stage: model.StageASIC, Action: model.ActionDrop, Priority: 300},
			{ID: "high", Stage: model.StageASIC, Action: model.ActionDrop, Priority: 100},
			{ID: "mid", Stage: model.StageASIC, Action: model.ActionDrop, Priority: 200},
		},
	}
	nodes := []model.Node{{ID: "node-a", Name: "a", CapacityGbps: 10}}
	progs := Compile(policy, nodes, Plan(policy, nodes, nil))
	acl := progs["node-a"].ASIC
	for i := 1; i < len(acl); i++ {
		if acl[i-1].Priority > acl[i].Priority {
			t.Fatalf("ACL is not ordered by priority: %+v", acl)
		}
	}
}

func TestCompileRoutesRulesToTheirStage(t *testing.T) {
	policy := model.Policy{
		ID: "pol-1", Version: 2,
		Protected: []string{"203.0.113.0/24"},
		Rules: []model.Rule{
			{ID: "a", Stage: model.StageASIC, Action: model.ActionDrop},
			{ID: "f", Stage: model.StageFPGA, Action: model.ActionLimit, PPS: 1000},
			{ID: "z", Stage: model.StageZC, Action: model.ActionInspect, PPS: 500},
		},
	}
	nodes := []model.Node{{ID: "node-a", Name: "scrub-a", CapacityGbps: 10}}
	prog := Compile(policy, nodes, Plan(policy, nodes, nil))["node-a"]
	if len(prog.ASIC) != 1 || len(prog.FPGA) != 1 || len(prog.ZC) != 1 {
		t.Fatalf("expected one entry per stage, got asic=%d fpga=%d zc=%d", len(prog.ASIC), len(prog.FPGA), len(prog.ZC))
	}
	if prog.FPGA[0].Meter != 1000 {
		t.Fatalf("expected the FPGA meter to carry the rule pps, got %d", prog.FPGA[0].Meter)
	}
	if prog.ZC[0].Cluster != "zc:scrub-a" {
		t.Fatalf("expected the ZC cluster named after the node, got %q", prog.ZC[0].Cluster)
	}
	if prog.Version != 2 || prog.PolicyID != "pol-1" {
		t.Fatalf("program lost its policy identity: %+v", prog)
	}
}

// A node only installs the backends it advertised. Compiling TCAM entries onto
// a node with no switch ASIC reported it as programmed with rules it cannot
// enforce.
func TestCompileHonorsAdvertisedBackends(t *testing.T) {
	policy := model.Policy{
		ID: "pol-1", Version: 1, Protected: []string{"203.0.113.0/24"},
		Rules: []model.Rule{
			{ID: "a", Stage: model.StageASIC, Action: model.ActionDrop},
			{ID: "f", Stage: model.StageFPGA, Action: model.ActionLimit, PPS: 10},
			{ID: "z", Stage: model.StageZC, Action: model.ActionInspect},
		},
	}
	nodes := []model.Node{
		{ID: "zc-only", Name: "zc-only", Backends: []model.Stage{model.StageZC}},
		{ID: "full", Name: "full", Backends: []model.Stage{model.StageASIC, model.StageFPGA, model.StageZC}},
		{ID: "unset", Name: "unset"},
	}
	progs := Compile(policy, nodes, Plan(policy, nodes, nil))

	zcOnly := progs["zc-only"]
	if len(zcOnly.ASIC) != 0 || len(zcOnly.FPGA) != 0 {
		t.Fatalf("a zc-only node was handed asic=%d fpga=%d entries", len(zcOnly.ASIC), len(zcOnly.FPGA))
	}
	if len(zcOnly.ZC) != 1 {
		t.Fatalf("expected the zc rule, got %d", len(zcOnly.ZC))
	}
	for _, id := range []string{"full", "unset"} {
		// An unset backend list means full-stack, matching registration.
		p := progs[id]
		if len(p.ASIC) != 1 || len(p.FPGA) != 1 || len(p.ZC) != 1 {
			t.Fatalf("%s: expected one entry per stage, got asic=%d fpga=%d zc=%d", id, len(p.ASIC), len(p.FPGA), len(p.ZC))
		}
	}
}

// Every stage decides by first match, so Priority has to order every stage.
// It used to be applied to the ASIC only.
func TestCompileOrdersEveryStageByPriority(t *testing.T) {
	policy := model.Policy{
		ID: "pol-1", Version: 1, Protected: []string{"203.0.113.0/24"},
		Rules: []model.Rule{
			{ID: "f-late", Stage: model.StageFPGA, Action: model.ActionLimit, PPS: 10, Priority: 900},
			{ID: "f-early", Stage: model.StageFPGA, Action: model.ActionPermit, Priority: 100},
			{ID: "z-late", Stage: model.StageZC, Action: model.ActionInspect, Priority: 900},
			{ID: "z-early", Stage: model.StageZC, Action: model.ActionPermit, Priority: 100},
			{ID: "a-late", Stage: model.StageASIC, Action: model.ActionDrop, Priority: 900},
			{ID: "a-early", Stage: model.StageASIC, Action: model.ActionPermit, Priority: 100},
		},
	}
	nodes := []model.Node{{ID: "n", Name: "n"}}
	prog := Compile(policy, nodes, Plan(policy, nodes, nil))["n"]
	if prog.ASIC[0].RuleID != "a-early" {
		t.Fatalf("asic out of priority order: %s first", prog.ASIC[0].RuleID)
	}
	if prog.FPGA[0].RuleID != "f-early" {
		t.Fatalf("fpga out of priority order: %s first", prog.FPGA[0].RuleID)
	}
	if prog.ZC[0].RuleID != "z-early" {
		t.Fatalf("zc out of priority order: %s first", prog.ZC[0].RuleID)
	}
}

// Rules sharing a priority must keep policy order, and compile the same way on
// every node. An unstable sort made the first match nondeterministic.
func TestCompileIsStableForEqualPriorities(t *testing.T) {
	var rules []model.Rule
	for i := 0; i < 24; i++ {
		rules = append(rules,
			model.Rule{ID: fmt.Sprintf("a%d", i), Stage: model.StageASIC, Action: model.ActionCount, Priority: 10},
			model.Rule{ID: fmt.Sprintf("f%d", i), Stage: model.StageFPGA, Action: model.ActionCount, Priority: 10},
			model.Rule{ID: fmt.Sprintf("z%d", i), Stage: model.StageZC, Action: model.ActionCount, Priority: 10},
		)
	}
	policy := model.Policy{ID: "pol-1", Version: 1, Protected: []string{"203.0.113.0/24"}, Rules: rules}
	nodes := []model.Node{{ID: "n1", Name: "n1"}, {ID: "n2", Name: "n2"}}
	assigned := Plan(policy, nodes, nil)

	order := func(p *model.Program) []string {
		var ids []string
		for _, e := range p.ASIC {
			ids = append(ids, e.RuleID)
		}
		for _, e := range p.FPGA {
			ids = append(ids, e.RuleID)
		}
		for _, e := range p.ZC {
			ids = append(ids, e.RuleID)
		}
		return ids
	}

	first := Compile(policy, nodes, assigned)
	want := order(first["n1"])
	if got := order(first["n2"]); !reflect.DeepEqual(want, got) {
		t.Fatalf("two nodes compiled the same policy in different orders:\n%v\n%v", want, got)
	}
	for i := 0; i < 20; i++ {
		if got := order(Compile(policy, nodes, assigned)["n1"]); !reflect.DeepEqual(want, got) {
			t.Fatalf("recompiling the same policy changed rule order:\n%v\n%v", want, got)
		}
	}
	// Policy order is the tie-break.
	for i, id := range want[:24] {
		if id != fmt.Sprintf("a%d", i) {
			t.Fatalf("equal priorities did not keep policy order: position %d is %s", i, id)
		}
	}
}

// When the largest node dies the survivors re-weight against each other,
// rather than staying padded against capacity that is no longer announcing.
func TestSurvivorsReweightWhenTheLargestNodeGoesStale(t *testing.T) {
	big := ready("node-big", "big", "iad", 400)
	mid := ready("node-mid", "mid", "fra", 200)
	small := ready("node-small", "small", "sin", 100)
	policy := policyFor("203.0.113.0/24")

	full := Plan(policy, []model.Node{big, mid, small}, nil)
	if got := rowFor(t, full, "203.0.113.0/24", "node-mid").Prepends; got != 1 {
		t.Fatalf("with the big node up, mid should carry 1 prepend, got %d", got)
	}

	big.Status = model.NodeStale
	degraded := Plan(policy, []model.Node{big, mid, small}, nil)
	if got := rowFor(t, degraded, "203.0.113.0/24", "node-mid").Prepends; got != 0 {
		t.Fatalf("mid is now the largest announcing node and should be unpadded, got %d", got)
	}
	if got := rowFor(t, degraded, "203.0.113.0/24", "node-small").Prepends; got != 1 {
		t.Fatalf("small should be padded one behind mid, got %d", got)
	}
}

// Measured load pads a node on top of what its capacity already earns it.
func TestSheddingAddsToTheCapacityBaseline(t *testing.T) {
	nodes := []model.Node{ready("node-big", "big", "iad", 400), ready("node-small", "small", "sin", 100)}
	policy := policyFor("203.0.113.0/24")

	base := Plan(policy, nodes, nil)
	if got := rowFor(t, base, "203.0.113.0/24", "node-small").Prepends; got != 2 {
		t.Fatalf("capacity baseline should be 2, got %d", got)
	}

	shed := Plan(policy, nodes, map[string]int{"node-small": 2, "node-big": 1})
	if got := rowFor(t, shed, "203.0.113.0/24", "node-small").Prepends; got != 4 {
		t.Fatalf("expected baseline 2 plus 2 shedding, got %d", got)
	}
	big := rowFor(t, shed, "203.0.113.0/24", "node-big")
	if big.Prepends != 1 {
		t.Fatalf("expected the big node padded 1 for load alone, got %d", big.Prepends)
	}
	if !strings.Contains(big.Reason, "shedding") {
		t.Fatalf("the reason should say the padding came from load, got %q", big.Reason)
	}
}

// Total padding stays bounded however saturated a node is.
func TestSheddingCannotPushPaddingPastTheBound(t *testing.T) {
	nodes := []model.Node{ready("node-big", "big", "iad", 1e9), ready("node-tiny", "tiny", "sin", 1)}
	plan := Plan(policyFor("203.0.113.0/24"), nodes, map[string]int{"node-tiny": 99})
	if got := rowFor(t, plan, "203.0.113.0/24", "node-tiny").Prepends; got != MaxPrepends {
		t.Fatalf("expected padding clamped to %d, got %d", MaxPrepends, got)
	}
}

// Load pads; only liveness withdraws. Shedding a node entirely would dump its
// share on its neighbours and can cascade.
func TestSheddingNeverWithdrawsANode(t *testing.T) {
	nodes := []model.Node{ready("node-a", "a", "iad", 100)}
	plan := Plan(policyFor("203.0.113.0/24"), nodes, map[string]int{"node-a": 99})
	if got := rowFor(t, plan, "203.0.113.0/24", "node-a").State; got != model.StateAnnounce {
		t.Fatalf("load must never withdraw a node, got state %q", got)
	}
}

// A withdrawn node carries no padding: there is no announcement to pad.
func TestSheddingIsIgnoredForWithdrawnNodes(t *testing.T) {
	dead := model.Node{ID: "node-dead", Name: "dead", Region: "sin", CapacityGbps: 100, Status: model.NodeStale}
	plan := Plan(policyFor("203.0.113.0/24"), []model.Node{dead}, map[string]int{"node-dead": 3})
	got := rowFor(t, plan, "203.0.113.0/24", "node-dead")
	if got.State != model.StateWithdraw || got.Prepends != 0 {
		t.Fatalf("unexpected row for a stale node: %+v", got)
	}
}
