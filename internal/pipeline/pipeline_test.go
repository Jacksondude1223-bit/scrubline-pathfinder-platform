package pipeline

import (
	"testing"

	"github.com/Jacksondude1223-bit/scrubline-cloud-scrub/internal/compiler"
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
