package compiler

import (
	"fmt"
	"hash/fnv"
	"sort"
	"time"

	"github.com/Jacksondude1223-bit/scrubline-cloud-scrub/internal/model"
)

func Assign(prefixes []string, nodes []model.Node) []model.Assignment {
	if len(nodes) == 0 {
		return nil
	}
	out := make([]model.Assignment, 0, len(prefixes))
	for _, p := range prefixes {
		best := nodes[0]
		bestScore := score(p, nodes[0])
		for _, n := range nodes[1:] {
			if s := score(p, n); s > bestScore {
				best, bestScore = n, s
			}
		}
		out = append(out, model.Assignment{Prefix: p, NodeID: best.ID, Weight: best.CapacityGbps})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Prefix < out[j].Prefix })
	return out
}

func score(prefix string, n model.Node) uint64 {
	h := fnv.New64a()
	_, _ = h.Write([]byte(prefix + "|" + n.ID))
	// Capacity biases the rendezvous pick without pinning every prefix to the largest node.
	return h.Sum64()%1000 + uint64(n.CapacityGbps)
}

func Compile(policy model.Policy, nodes []model.Node, assigned []model.Assignment) map[string]*model.Program {
	byNode := map[string][]string{}
	for _, a := range assigned {
		byNode[a.NodeID] = append(byNode[a.NodeID], a.Prefix)
	}
	out := map[string]*model.Program{}
	now := time.Now().UTC()
	for _, n := range nodes {
		prog := &model.Program{
			NodeID:     n.ID,
			PolicyID:   policy.ID,
			Version:    policy.Version,
			Prefixes:   byNode[n.ID],
			CompiledAt: now,
		}
		for _, rule := range policy.Rules {
			switch rule.Stage {
			case model.StageASIC:
				prog.ASIC = append(prog.ASIC, model.ACLEntry{
					Priority: rule.Priority,
					Action:   rule.Action,
					Match:    rule.Match,
					RuleID:   rule.ID,
					TCAMKey:  tcamKey(rule),
				})
			case model.StageFPGA:
				prog.FPGA = append(prog.FPGA, model.FPGAEntry{
					Table:  "scrub_meter",
					Match:  rule.Match,
					Meter:  rule.PPS,
					Action: rule.Action,
					RuleID: rule.ID,
				})
			case model.StageZC:
				prog.ZC = append(prog.ZC, model.ZCEntry{
					Cluster: "zc:" + n.Name,
					Match:   rule.Match,
					Action:  rule.Action,
					PPS:     rule.PPS,
					RuleID:  rule.ID,
				})
			}
		}
		sort.Slice(prog.ASIC, func(i, j int) bool { return prog.ASIC[i].Priority < prog.ASIC[j].Priority })
		out[n.ID] = prog
	}
	return out
}

func tcamKey(rule model.Rule) string {
	return fmt.Sprintf("v4 src=%s dst=%s proto=%s dport=%d sport=%d pri=%d",
		orAny(rule.Match.SrcCIDR), orAny(rule.Match.DstCIDR), orAny(rule.Match.Proto),
		rule.Match.DPort, rule.Match.SPort, rule.Priority)
}

func orAny(s string) string {
	if s == "" {
		return "*"
	}
	return s
}
