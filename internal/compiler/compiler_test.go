package compiler

import (
	"math"
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
