package compiler

import (
	"fmt"
	"math"
	"net"
	"net/netip"
	"sort"
	"strings"
	"time"

	"github.com/Jacksondude1223-bit/scrubline-cloud-scrub/internal/model"
)

// MaxPrepends bounds AS-path padding. Past a handful of prepends upstreams
// stop distinguishing paths, and a very long path invites filtering.
const MaxPrepends = 5

// Plan computes the fabric's BGP posture: for every protected prefix, what
// each node advertises.
//
// The fabric is anycast, so every eligible node announces every prefix and no
// prefix is owned by one scrubber. Two things shape the plan:
//
//   - Capacity, as AS-path prepends. The largest node announces unpadded; each
//     halving of capacity relative to it costs one prepend, which makes a node
//     a less attractive path for sources that have a choice. This weights the
//     split without pinning a prefix anywhere.
//   - Liveness. A node past its heartbeat TTL is withdrawn, so its share of
//     the traffic moves to the nodes still answering. That withdrawal is the
//     failover: nothing has to be reassigned.
//
// shedding adds per-node padding on top of the capacity baseline, keyed by
// node ID. It is how measured load reaches the routing table; the decision to
// pad is made in internal/steering, which owns the hysteresis and the dwell.
// Only liveness can withdraw a node: load pads, it never removes.
func Plan(policy model.Policy, nodes []model.Node, shedding map[string]int) []model.Announcement {
	steering := steeringByPrefix(policy)
	// Padding is relative to the largest node that is actually announcing. A
	// node that has gone stale is not attracting traffic, so weighting the
	// survivors against it would leave the whole live fabric padded against
	// something that is not there.
	maxCapacity := 0.0
	for _, n := range nodes {
		if n.Status == model.NodeStale {
			continue
		}
		if c := capacityOf(n); c > maxCapacity {
			maxCapacity = c
		}
	}

	out := make([]model.Announcement, 0, len(policy.Protected)*len(nodes))
	for _, prefix := range policy.Protected {
		st := steering[prefix]
		for _, n := range nodes {
			if !eligible(n, st) {
				continue
			}
			a := model.Announcement{
				Prefix:      prefix,
				NodeID:      n.ID,
				NodeName:    n.Name,
				Region:      n.Region,
				Communities: append([]string(nil), st.Communities...),
				NextHop:     nextHop(n),
			}
			if n.Status == model.NodeStale {
				a.State = model.StateWithdraw
				a.Reason = "node has not heartbeated within its TTL"
			} else {
				base := prependsFor(n, maxCapacity)
				extra := shedding[n.ID]
				if extra < 0 {
					extra = 0
				}
				a.State = model.StateAnnounce
				a.Prepends = clampPrepends(base + extra)
				a.Reason = prependReason(a.Prepends, base, extra)
			}
			out = append(out, a)
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Prefix != out[j].Prefix {
			return out[i].Prefix < out[j].Prefix
		}
		return out[i].NodeID < out[j].NodeID
	})
	return out
}

func clampPrepends(p int) int {
	if p < 0 {
		return 0
	}
	if p > MaxPrepends {
		return MaxPrepends
	}
	return p
}

func prependReason(total, base, shedding int) string {
	switch {
	case total == 0:
		return "anycast member at full preference"
	case shedding == 0:
		return fmt.Sprintf("anycast member padded %d to weight for capacity", total)
	case base == 0:
		return fmt.Sprintf("anycast member padded %d, shedding measured load", total)
	}
	return fmt.Sprintf("anycast member padded %d: %d for capacity, %d shedding measured load", total, base, shedding)
}

// steeringByPrefix indexes a policy's steering overrides. A prefix with no
// override takes the default anycast posture.
func steeringByPrefix(policy model.Policy) map[string]model.Steering {
	out := make(map[string]model.Steering, len(policy.Steering))
	for _, st := range policy.Steering {
		out[st.Prefix] = st
	}
	return out
}

// eligible reports whether a node may carry a prefix at all. Region pinning is
// a hard boundary, not a preference: a node outside the listed regions neither
// announces the prefix nor enforces policy on it.
func eligible(n model.Node, st model.Steering) bool {
	if len(st.Regions) == 0 {
		return true
	}
	for _, r := range st.Regions {
		if strings.EqualFold(r, n.Region) {
			return true
		}
	}
	return false
}

// capacityOf reads a node's capacity defensively. A NaN or negative value must
// not reach the prepend arithmetic, where it would silently make one node the
// most attractive path in the fabric.
func capacityOf(n model.Node) float64 {
	c := n.CapacityGbps
	if math.IsNaN(c) || math.IsInf(c, 0) || c < 0 {
		return 0
	}
	return c
}

// prependsFor weights a node against the largest one in the fabric. A node
// with no usable capacity is padded to the maximum rather than treated as
// infinite, so a bad registration sheds traffic instead of attracting it.
func prependsFor(n model.Node, maxCapacity float64) int {
	c := capacityOf(n)
	if c <= 0 {
		return MaxPrepends
	}
	if maxCapacity <= 0 || c >= maxCapacity {
		return 0
	}
	p := int(math.Round(math.Log2(maxCapacity / c)))
	if p < 0 {
		return 0
	}
	if p > MaxPrepends {
		return MaxPrepends
	}
	return p
}

// nextHop is the address upstreams route the prefix to. The agent advertises
// it at registration; a node that did not gets an empty next hop and the
// speaker falls back to its own session address.
func nextHop(n model.Node) string {
	if n.Advertise == "" {
		return ""
	}
	if host, _, err := net.SplitHostPort(n.Advertise); err == nil {
		return host
	}
	return n.Advertise
}

// EnforcedPrefixes lists the prefixes a node applies policy to. That is every
// prefix it is eligible for, including ones it is currently withdrawing: BGP
// takes time to converge, and traffic still arriving for a withdrawn prefix
// should be scrubbed rather than waved through. Only a region boundary keeps a
// prefix off a node entirely.
func EnforcedPrefixes(policy model.Policy, n model.Node) []string {
	steering := steeringByPrefix(policy)
	out := []string{}
	for _, prefix := range policy.Protected {
		if eligible(n, steering[prefix]) {
			out = append(out, prefix)
		}
	}
	return out
}

func Compile(policy model.Policy, nodes []model.Node, plan []model.Announcement) map[string]*model.Program {
	byNode := map[string][]model.Announcement{}
	for _, a := range plan {
		byNode[a.NodeID] = append(byNode[a.NodeID], a)
	}
	out := map[string]*model.Program{}
	now := time.Now().UTC()
	for _, n := range nodes {
		prefixes := EnforcedPrefixes(policy, n)
		announcements := byNode[n.ID]
		if announcements == nil {
			announcements = []model.Announcement{}
		}
		stages := backendSet(n)
		prog := &model.Program{
			NodeID:        n.ID,
			PolicyID:      policy.ID,
			Version:       policy.Version,
			Prefixes:      prefixes,
			Announcements: announcements,
			// Only filters for addresses this node actually carries, and
			// only when it has a ZC stage to run them on: payload
			// inspection is a userspace job, the TCAM and the FPGA cannot
			// do it.
			Games:           gamesFor(policy, prefixes, stages[model.StageZC]),
			ChallengeSecret: policy.ChallengeSecret,
			PulseFloorPPS:   policy.PulseFloorPPS,
			CompiledAt:      now,
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

// gamesFor picks the game filters that belong on a node: those whose
// address falls inside a prefix the node enforces. A filter with no address
// applies wherever the policy does.
func gamesFor(policy model.Policy, prefixes []string, hasZC bool) []model.GameFilter {
	if !hasZC || len(policy.Games) == 0 {
		return nil
	}
	enforced := make([]netip.Prefix, 0, len(prefixes))
	for _, cidr := range prefixes {
		if p, err := netip.ParsePrefix(cidr); err == nil {
			enforced = append(enforced, p)
		}
	}
	out := make([]model.GameFilter, 0, len(policy.Games))
	for _, g := range policy.Games {
		if g.DstCIDR == "" {
			out = append(out, g)
			continue
		}
		target, err := netip.ParsePrefix(g.DstCIDR)
		if err != nil {
			continue
		}
		for _, p := range enforced {
			if p.Overlaps(target) {
				out = append(out, g)
				break
			}
		}
	}
	if len(out) == 0 {
		return nil
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
