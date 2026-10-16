package compiler

import (
	"fmt"
	"math"
	"reflect"
	"testing"

	"github.com/Jacksondude1223-bit/scrubline-cloud-scrub/internal/model"
)

// Converting a negative float64 to uint64 is undefined in Go and produced a
// near-max score, letting one node with a bogus capacity win every prefix.
func TestBogusCapacityCannotCaptureTheFabric(t *testing.T) {
	for _, bogus := range []float64{-1, -1e9, math.NaN(), math.Inf(-1)} {
		nodes := []model.Node{
			{ID: "node-a", Name: "a", CapacityGbps: 100},
			{ID: "node-b", Name: "b", CapacityGbps: 100},
			{ID: "node-c", Name: "c", CapacityGbps: 100},
			{ID: "node-evil", Name: "evil", CapacityGbps: bogus},
		}
		prefixes := []string{
			"203.0.113.0/24", "203.0.114.0/24", "203.0.115.0/24", "203.0.116.0/24",
			"198.51.100.0/24", "192.0.2.0/24", "198.18.0.0/24", "198.19.0.0/24",
		}
		got := Assign(prefixes, nodes)
		captured := 0
		for _, a := range got {
			if a.NodeID == "node-evil" {
				captured++
			}
		}
		if captured == len(prefixes) {
			t.Fatalf("capacity %v captured every prefix: %+v", bogus, got)
		}
	}
}

// A very large capacity must not pin every prefix to one node either.
func TestHugeCapacityDoesNotPinEveryPrefix(t *testing.T) {
	nodes := []model.Node{
		{ID: "node-a", Name: "a", CapacityGbps: 10},
		{ID: "node-b", Name: "b", CapacityGbps: 10},
		{ID: "node-huge", Name: "huge", CapacityGbps: math.MaxFloat64},
	}
	prefixes := []string{"203.0.113.0/24", "203.0.114.0/24", "203.0.115.0/24", "203.0.116.0/24", "198.51.100.0/24", "192.0.2.0/24"}
	got := Assign(prefixes, nodes)
	seen := map[string]bool{}
	for _, a := range got {
		seen[a.NodeID] = true
	}
	if len(seen) < 2 {
		t.Fatalf("expected prefixes spread across nodes, got %+v", got)
	}
}

func TestAssignIsDeterministic(t *testing.T) {
	nodes := []model.Node{
		{ID: "node-a", Name: "a", CapacityGbps: 100},
		{ID: "node-b", Name: "b", CapacityGbps: 80},
	}
	prefixes := []string{"203.0.113.0/24", "198.51.100.0/24"}
	first := Assign(prefixes, nodes)
	for i := 0; i < 20; i++ {
		got := Assign(prefixes, nodes)
		for j := range got {
			if got[j] != first[j] {
				t.Fatalf("assignment is not stable: %+v then %+v", first, got)
			}
		}
	}
}

func TestAssignWithNoNodes(t *testing.T) {
	if got := Assign([]string{"203.0.113.0/24"}, nil); got != nil {
		t.Fatalf("expected no assignments without nodes, got %+v", got)
	}
}

// Every prefix must land somewhere; none may be dropped.
func TestEveryPrefixIsAssigned(t *testing.T) {
	nodes := []model.Node{{ID: "node-a", Name: "a", CapacityGbps: 10}, {ID: "node-b", Name: "b", CapacityGbps: 10}}
	prefixes := []string{"203.0.113.0/24", "198.51.100.0/24", "192.0.2.0/24"}
	got := Assign(prefixes, nodes)
	if len(got) != len(prefixes) {
		t.Fatalf("expected %d assignments, got %d", len(prefixes), len(got))
	}
	seen := map[string]bool{}
	for _, a := range got {
		seen[a.Prefix] = true
	}
	for _, p := range prefixes {
		if !seen[p] {
			t.Fatalf("prefix %s was not assigned", p)
		}
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
	assigned := Assign(policy.Protected, nodes)
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
	progs := Compile(policy, nodes, Assign(policy.Protected, nodes))
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
	prog := Compile(policy, nodes, Assign(policy.Protected, nodes))["node-a"]
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
	progs := Compile(policy, nodes, Assign(policy.Protected, nodes))

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
	prog := Compile(policy, nodes, Assign(policy.Protected, nodes))["n"]
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
	assigned := Assign(policy.Protected, nodes)

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
