package compiler

import (
	"fmt"
	"hash/fnv"
	"math"
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

// capacityBias caps how much capacity can tilt the rendezvous hash, so a single
// very large node cannot win every prefix.
const capacityBias = 500

func score(prefix string, n model.Node) uint64 {
	h := fnv.New64a()
	_, _ = h.Write([]byte(prefix + "|" + n.ID))
	// Capacity biases the rendezvous pick without pinning every prefix to the
	// largest node. Converting a negative or NaN float to uint64 is undefined in
	// Go and yielded a near-max value, which let one node with a bogus capacity
	// capture the whole fabric; clamp into range first.
	bias := n.CapacityGbps
	if math.IsNaN(bias) || bias < 0 {
		bias = 0
	}
	if bias > capacityBias {
		bias = capacityBias
	}
	return h.Sum64()%1000 + uint64(bias)
}

func Compile(policy model.Policy, nodes []model.Node, assigned []model.Assignment) map[string]*model.Program {
	byNode := map[string][]string{}
	for _, a := range assigned {
		byNode[a.NodeID] = append(byNode[a.NodeID], a.Prefix)
	}
	out := map[string]*model.Program{}
	now := time.Now().UTC()
	for _, n := range nodes {
		prefixes := byNode[n.ID]
		if prefixes == nil {
			prefixes = []string{}
		}
		stages := backendSet(n)
		prog := &model.Program{
			NodeID:     n.ID,
			PolicyID:   policy.ID,
			Version:    policy.Version,
			Prefixes:   prefixes,
			CompiledAt: now,
		}
		for _, rule := range policy.Rules {
			// A node only gets entries for the backends it advertised. Handing
			// TCAM entries to a node with no switch ASIC reported it as
			// programmed with rules it cannot install.
			if !stages[rule.Stage] {
				continue
			}
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
					Table:    "scrub_meter",
					Match:    rule.Match,
					Meter:    rule.PPS,
					Action:   rule.Action,
					RuleID:   rule.ID,
					Priority: rule.Priority,
				})
			case model.StageZC:
				prog.ZC = append(prog.ZC, model.ZCEntry{
					Cluster:  "zc:" + n.Name,
					Match:    rule.Match,
					Action:   rule.Action,
					PPS:      rule.PPS,
					RuleID:   rule.ID,
					Priority: rule.Priority,
				})
			}
		}
		// Every stage decides by first match, so every stage has to honour
		// Priority, not just the ASIC. The sort is stable so rules sharing a
		// priority keep policy order and compile identically on every node.
		sort.SliceStable(prog.ASIC, func(i, j int) bool { return prog.ASIC[i].Priority < prog.ASIC[j].Priority })
		sort.SliceStable(prog.FPGA, func(i, j int) bool { return prog.FPGA[i].Priority < prog.FPGA[j].Priority })
		sort.SliceStable(prog.ZC, func(i, j int) bool { return prog.ZC[i].Priority < prog.ZC[j].Priority })
		out[n.ID] = prog
	}
	return out
}

// backendSet reports which stages a node can install. A node that advertised no
// backends is treated as full-stack, matching the control plane's own default
// at registration.
func backendSet(n model.Node) map[model.Stage]bool {
	if len(n.Backends) == 0 {
		return map[model.Stage]bool{model.StageASIC: true, model.StageFPGA: true, model.StageZC: true}
	}
	set := make(map[model.Stage]bool, len(n.Backends))
	for _, b := range n.Backends {
		set[b] = true
	}
	return set
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
