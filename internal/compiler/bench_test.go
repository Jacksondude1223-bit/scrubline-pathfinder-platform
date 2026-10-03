package compiler

import (
	"fmt"
	"net/netip"
	"testing"

	"github.com/Jacksondude1223-bit/scrubline-cloud-scrub/internal/model"
)

func benchNodes(n int) []model.Node {
	out := make([]model.Node, 0, n)
	for i := 0; i < n; i++ {
		out = append(out, model.Node{
			ID: fmt.Sprintf("node-%04d", i), Name: fmt.Sprintf("scrub-%04d", i),
			CapacityGbps: float64(10 + i%100),
		})
	}
	return out
}

func benchPrefixes(n int) []string {
	out := make([]string, 0, n)
	for i := 0; i < n; i++ {
		a := netip.AddrFrom4([4]byte{203, byte(i >> 8), byte(i), 0})
		out = append(out, a.String()+"/24")
	}
	return out
}

// Assign is O(prefixes * nodes); deploy calls it once per deploy.
func BenchmarkAssign(b *testing.B) {
	for _, tc := range []struct{ prefixes, nodes int }{
		{10, 3}, {100, 10}, {1000, 50}, {10000, 100},
	} {
		b.Run(fmt.Sprintf("prefixes=%d/nodes=%d", tc.prefixes, tc.nodes), func(b *testing.B) {
			prefixes, nodes := benchPrefixes(tc.prefixes), benchNodes(tc.nodes)
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				Assign(prefixes, nodes)
			}
		})
	}
}

// Compile builds one program per node, each carrying every rule.
func BenchmarkCompile(b *testing.B) {
	for _, tc := range []struct{ rules, nodes int }{
		{5, 3}, {100, 10}, {1000, 50},
	} {
		b.Run(fmt.Sprintf("rules=%d/nodes=%d", tc.rules, tc.nodes), func(b *testing.B) {
			policy := model.Policy{ID: "pol-1", Version: 1, Protected: benchPrefixes(tc.nodes * 2)}
			stages := []model.Stage{model.StageASIC, model.StageFPGA, model.StageZC}
			actions := []model.Action{model.ActionDrop, model.ActionLimit, model.ActionInspect}
			for i := 0; i < tc.rules; i++ {
				policy.Rules = append(policy.Rules, model.Rule{
					ID: fmt.Sprintf("r%d", i), Stage: stages[i%3], Action: actions[i%3],
					Priority: i, PPS: 1000,
					Match: model.Match{DstCIDR: "203.0.113.0/24", Proto: "tcp"},
				})
			}
			nodes := benchNodes(tc.nodes)
			assigned := Assign(policy.Protected, nodes)
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				Compile(policy, nodes, assigned)
			}
		})
	}
}
