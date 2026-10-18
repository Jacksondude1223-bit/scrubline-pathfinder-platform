package compiler

import (
	"sort"

	"github.com/Jacksondude1223-bit/scrubline-cloud-scrub/internal/bgp"
	"github.com/Jacksondude1223-bit/scrubline-cloud-scrub/internal/model"
	"github.com/Jacksondude1223-bit/scrubline-cloud-scrub/internal/tunnel"
)

// TunnelHealth is what each node last reported about its own return tunnels,
// keyed by node ID and then by tunnel ID. A node or tunnel that is absent has
// reported nothing, which is not the same as having reported a failure.
type TunnelHealth map[string]map[string]string

// State reads one node's report for one tunnel.
func (h TunnelHealth) State(nodeID, tunnelID string) string {
	if h == nil {
		return model.TunnelUnknown
	}
	byTunnel, ok := h[nodeID]
	if !ok {
		return model.TunnelUnknown
	}
	state, ok := byTunnel[tunnelID]
	if !ok {
		return model.TunnelUnknown
	}
	return state
}

// tunnelForPrefix finds the return path a prefix is delivered over. A prefix
// belongs to at most one tunnel — the policy is validated for that — so there
// is never a question of which return path is authoritative.
func tunnelForPrefix(policy model.Policy, prefix string) (model.Tunnel, bool) {
	for _, t := range policy.Tunnels {
		for _, p := range t.Prefixes {
			if p == prefix {
				return t, true
			}
		}
	}
	return model.Tunnel{}, false
}

// deliverable reports whether a node should be announcing a prefix at all,
// given where that prefix's scrubbed traffic has to go.
//
// A node that announces a prefix it cannot deliver is worse than one that
// never announced it: BGP sends it the customer's traffic and it drops the
// lot. So the return path is a precondition for the announcement, not a
// separate concern that happens to run alongside it.
func deliverable(policy model.Policy, n model.Node, prefix string, health TunnelHealth) (bool, string) {
	t, ok := tunnelForPrefix(policy, prefix)
	if !ok {
		// No return path declared. The operator is delivering this prefix
		// some other way — a cross-connect, a shared fabric, an L2 path —
		// and it is not this compiler's business to guess.
		return true, ""
	}
	if n.TunnelSrc == "" {
		return false, "node has no tunnel_src, so it cannot build the return path for this prefix"
	}
	nt := model.NodeTunnel{ID: t.ID, Required: t.Required}
	return tunnel.Deliverable(nt, health.State(n.ID, t.ID))
}

// TunnelsFor builds the return tunnels one node needs: one per customer
// endpoint whose prefixes this node carries.
//
// The fabric is anycast, so this is a fan-out rather than an assignment —
// every node carrying a customer's prefixes builds its own tunnel to the same
// customer endpoint, from its own address. Ten scrubbers protecting one
// customer means ten tunnels, which is the cost of not pinning a prefix to
// one box.
func TunnelsFor(policy model.Policy, n model.Node, enforced []string) []model.NodeTunnel {
	if n.TunnelSrc == "" {
		return nil
	}
	carries := make(map[string]bool, len(enforced))
	for _, prefix := range enforced {
		carries[prefix] = true
	}

	out := make([]model.NodeTunnel, 0, len(policy.Tunnels))
	for _, t := range policy.Tunnels {
		mine := make([]string, 0, len(t.Prefixes))
		for _, prefix := range t.Prefixes {
			if carries[prefix] {
				mine = append(mine, prefix)
			}
		}
		if len(mine) == 0 {
			// This node carries none of the tunnel's prefixes, so it has no
			// reason to hold the tunnel open.
			continue
		}
		nt, err := tunnel.ForNode(t, n, mine)
		if err != nil {
			// The policy is validated before it is saved, so reaching here
			// means the node changed under a compiled policy. Leaving the
			// tunnel out is what makes deliverable() withdraw the prefixes
			// rather than announcing traffic with nowhere to go.
			continue
		}
		out = append(out, nt)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// SessionsFor is the customer peerings a node terminates.
func SessionsFor(policy model.Policy, n model.Node) []model.Session {
	out := make([]model.Session, 0, len(policy.Sessions))
	for _, s := range policy.Sessions {
		if !bgp.TerminatesOn(s, n) {
			continue
		}
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}
