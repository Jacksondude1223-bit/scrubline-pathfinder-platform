// Package telemetry carries datapath counters from scrubbing nodes to the
// control plane, and renders them in one metric vocabulary. A node exposes its
// own report and the control plane exposes every report it has collected, so a
// dashboard written against one works against the other.
package telemetry

import (
	"time"

	"github.com/Jacksondude1223-bit/scrubline-cloud-scrub/internal/metrics"
	"github.com/Jacksondude1223-bit/scrubline-cloud-scrub/internal/model"
	"github.com/Jacksondude1223-bit/scrubline-cloud-scrub/internal/pipeline"
)

// Report is one node's datapath counters at a point in time. Nodes attach it
// to their heartbeat, which is the only call they already make on every poll.
type Report struct {
	NodeID     string         `json:"node_id"`
	Name       string         `json:"name"`
	Region     string         `json:"region"`
	Stats      pipeline.Stats `json:"stats"`
	ReportedAt time.Time      `json:"reported_at"`
}

// identity is the label set every one of a node's series carries.
func (r Report) identity() []metrics.Label {
	return []metrics.Label{
		{Name: "node", Value: r.NodeID},
		{Name: "name", Value: r.Name},
		{Name: "region", Value: r.Region},
	}
}

func with(base []metrics.Label, extra ...metrics.Label) []metrics.Label {
	out := make([]metrics.Label, 0, len(base)+len(extra))
	out = append(out, base...)
	out = append(out, extra...)
	return out
}

func boolValue(b bool) float64 {
	if b {
		return 1
	}
	return 0
}

// Families renders reports as metric families. now is used to age each report;
// pass the zero time to leave the age series out, which is what a node does
// when reporting its own live counters.
func Families(reports []Report, now time.Time) []metrics.Family {
	decisions := metrics.Family{
		Name: "scrubline_decisions_total", Type: metrics.Counter,
		Help: "Flow decisions made by a node's datapath.",
	}
	unowned := metrics.Family{
		Name: "scrubline_unowned_flows_total", Type: metrics.Counter,
		Help: "Flows whose destination is not a prefix assigned to this node. A rising value means the steering layer and the fabric disagree about who scrubs what.",
	}
	stageDropped := metrics.Family{
		Name: "scrubline_stage_dropped_total", Type: metrics.Counter,
		Help: "Flows dropped, by the stage that decided.",
	}
	stagePermitted := metrics.Family{
		Name: "scrubline_stage_permitted_total", Type: metrics.Counter,
		Help: "Flows permitted, by the stage that decided.",
	}
	stageDroppedPPS := metrics.Family{
		Name: "scrubline_stage_dropped_pps_total", Type: metrics.Counter,
		Help: "Sum of the per-flow rates reported on flows dropped at this stage. A volume weighting of the drop count, not a packet counter.",
	}
	stagePermittedPPS := metrics.Family{
		Name: "scrubline_stage_permitted_pps_total", Type: metrics.Counter,
		Help: "Sum of the per-flow rates reported on flows permitted at this stage. A volume weighting of the permit count, not a packet counter.",
	}
	ruleMatches := metrics.Family{
		Name: "scrubline_rule_matches_total", Type: metrics.Counter,
		Help: "Flows matched by a rule, including rules that left the verdict to a later rule.",
	}
	ruleDrops := metrics.Family{
		Name: "scrubline_rule_drops_total", Type: metrics.Counter,
		Help: "Flows dropped by the rule that decided them. A rule with matches and no drops is seeing traffic it is not acting on.",
	}
	ruleSeenPPS := metrics.Family{
		Name: "scrubline_rule_seen_pps_total", Type: metrics.Counter,
		Help: "Sum of the per-flow rates reported on flows a rule matched.",
	}
	ruleDroppedPPS := metrics.Family{
		Name: "scrubline_rule_dropped_pps_total", Type: metrics.Counter,
		Help: "Sum of the per-flow rates reported on flows a rule dropped.",
	}
	mlScored := metrics.Family{
		Name: "scrubline_ml_scored_total", Type: metrics.Counter,
		Help: "Flows scored by the ZC classifier.",
	}
	mlDrops := metrics.Family{
		Name: "scrubline_ml_drops_total", Type: metrics.Counter,
		Help: "Flows dropped because the classifier scored them at or above the threshold.",
	}
	mlPasses := metrics.Family{
		Name: "scrubline_ml_passes_total", Type: metrics.Counter,
		Help: "Flows the classifier scored below the threshold.",
	}
	mlReady := metrics.Family{
		Name: "scrubline_ml_model_ready", Type: metrics.Gauge,
		Help: "1 when a fitted classifier is installed on this node's ZC path.",
	}
	buckets := metrics.Family{
		Name: "scrubline_rate_buckets", Type: metrics.Gauge,
		Help: "Sources currently tracked by the ZC behavioral cap.",
	}
	bucketsMax := metrics.Family{
		Name: "scrubline_rate_buckets_max", Type: metrics.Gauge,
		Help: "Bound on the per-source rate table. At the bound, new sources go untracked and the cap is no longer measuring every source.",
	}
	offeredPPS := metrics.Family{
		Name: "scrubline_offered_pps", Type: metrics.Gauge,
		Help: "Packet rate currently offered to a node, averaged over its load window. This is the number load-driven steering reacts to.",
	}
	droppedPPSRate := metrics.Family{
		Name: "scrubline_dropped_pps", Type: metrics.Gauge,
		Help: "Packet rate a node is currently dropping, averaged over its load window.",
	}
	gameInspected := metrics.Family{
		Name: "scrubline_game_inspected_total", Type: metrics.Counter,
		Help: "Packets a game filter looked at.",
	}
	gameDropped := metrics.Family{
		Name: "scrubline_game_dropped_total", Type: metrics.Counter,
		Help: "Packets dropped because they are not the protocol their port speaks.",
	}
	gameChallenged := metrics.Family{
		Name: "scrubline_game_challenged_total", Type: metrics.Counter,
		Help: "Sources sent the protocol's own challenge because they had not cleared the gate.",
	}
	gameUninspectable := metrics.Family{
		Name: "scrubline_game_uninspectable_total", Type: metrics.Counter,
		Help: "Packets a game filter was given no payload for. The filter never drops on these, so a rising value means the datapath is not supplying payloads and the filter is doing nothing.",
	}
	gameDroppedPPS := metrics.Family{
		Name: "scrubline_game_dropped_pps_total", Type: metrics.Counter,
		Help: "Sum of the per-flow rates reported on packets a game filter dropped.",
	}
	gameSessions := metrics.Family{
		Name: "scrubline_game_sessions", Type: metrics.Gauge,
		Help: "Sources the game filter is tracking through a gate.",
	}
	gameSessionsMax := metrics.Family{
		Name: "scrubline_game_sessions_max", Type: metrics.Gauge,
		Help: "Bound on the game filter's session table. At the bound it admits without tracking rather than evicting connected players.",
	}
	pulsing := metrics.Family{
		Name: "scrubline_pulse_active", Type: metrics.Gauge,
		Help: "1 while a protected prefix is under a recognised burst train, including through the quiet stretches between bursts.",
	}
	pulsePeak := metrics.Family{
		Name: "scrubline_pulse_peak_pps", Type: metrics.Gauge,
		Help: "Heaviest burst measured against a prefix, at sub-second resolution. This is the number a mean hides: a pulse attack keeps its average under the watermark on purpose.",
	}
	pulseMean := metrics.Family{
		Name: "scrubline_pulse_mean_pps", Type: metrics.Gauge,
		Help: "Mean rate against a prefix over the pulse horizon. Compare with the peak: a wide gap is the attack.",
	}
	pulseCrest := metrics.Family{
		Name: "scrubline_pulse_crest", Type: metrics.Gauge,
		Help: "Peak-to-mean ratio of traffic to a prefix. Steady traffic sits near one however heavy it is.",
	}
	pulseDuty := metrics.Family{
		Name: "scrubline_pulse_duty_cycle", Type: metrics.Gauge,
		Help: "Share of the pulse horizon a prefix saw any traffic at all. A burst train is quiet most of the time.",
	}
	pulseBursts := metrics.Family{
		Name: "scrubline_pulse_bursts", Type: metrics.Gauge,
		Help: "Distinct bursts counted against a prefix in the horizon.",
	}
	pulseHold := metrics.Family{
		Name: "scrubline_pulse_hold_seconds", Type: metrics.Gauge,
		Help: "How much longer the pulse flag stands without another burst. While this is above zero, mitigation does not disengage.",
	}
	prefixOfferedPPS := metrics.Family{
		Name: "scrubline_prefix_offered_pps", Type: metrics.Gauge,
		Help: "Packet rate arriving for one protected prefix at this node, averaged over the load window. The node-wide rate cannot answer this: a scrubber carries many prefixes at once.",
	}
	prefixDroppedPPS := metrics.Family{
		Name: "scrubline_prefix_dropped_pps", Type: metrics.Gauge,
		Help: "Packet rate being scrubbed for one protected prefix at this node, averaged over the load window.",
	}
	prefixFlows := metrics.Family{
		Name: "scrubline_prefix_flows_total", Type: metrics.Counter,
		Help: "Flows decided for one protected prefix.",
	}
	prefixFlowsDropped := metrics.Family{
		Name: "scrubline_prefix_flows_dropped_total", Type: metrics.Counter,
		Help: "Flows dropped or challenged for one protected prefix.",
	}
	prefixOffered := metrics.Family{
		Name: "scrubline_prefix_offered_total", Type: metrics.Counter,
		Help: "Sum of the per-flow rates reported on flows arriving for one protected prefix. A volume weighting of the flow count, not a packet counter.",
	}
	prefixDropped := metrics.Family{
		Name: "scrubline_prefix_dropped_total", Type: metrics.Counter,
		Help: "Sum of the per-flow rates reported on flows scrubbed for one protected prefix.",
	}
	age := metrics.Family{
		Name: "scrubline_report_age_seconds", Type: metrics.Gauge,
		Help: "Seconds since this node last reported its counters.",
	}

	for _, r := range reports {
		id := r.identity()
		s := r.Stats
		decisions.Samples = append(decisions.Samples, metrics.Sample{Labels: id, Value: float64(s.Decisions)})
		unowned.Samples = append(unowned.Samples, metrics.Sample{Labels: id, Value: float64(s.Unowned)})
		mlScored.Samples = append(mlScored.Samples, metrics.Sample{Labels: id, Value: float64(s.ML.Scored)})
		mlDrops.Samples = append(mlDrops.Samples, metrics.Sample{Labels: id, Value: float64(s.ML.Drops)})
		mlPasses.Samples = append(mlPasses.Samples, metrics.Sample{Labels: id, Value: float64(s.ML.Passes)})
		mlReady.Samples = append(mlReady.Samples, metrics.Sample{Labels: id, Value: boolValue(s.ML.Ready)})
		buckets.Samples = append(buckets.Samples, metrics.Sample{Labels: id, Value: float64(s.RateBuckets)})
		offeredPPS.Samples = append(offeredPPS.Samples, metrics.Sample{Labels: id, Value: float64(s.OfferedPPS)})
		droppedPPSRate.Samples = append(droppedPPSRate.Samples, metrics.Sample{Labels: id, Value: float64(s.DroppedPPS)})
		bucketsMax.Samples = append(bucketsMax.Samples, metrics.Sample{Labels: id, Value: float64(s.RateBucketsMax)})

		for _, st := range s.Stages {
			labels := with(id, metrics.Label{Name: "stage", Value: string(st.Stage)})
			stageDropped.Samples = append(stageDropped.Samples, metrics.Sample{Labels: labels, Value: float64(st.Dropped)})
			stagePermitted.Samples = append(stagePermitted.Samples, metrics.Sample{Labels: labels, Value: float64(st.Permitted)})
			stageDroppedPPS.Samples = append(stageDroppedPPS.Samples, metrics.Sample{Labels: labels, Value: float64(st.PPSDropped)})
			stagePermittedPPS.Samples = append(stagePermittedPPS.Samples, metrics.Sample{Labels: labels, Value: float64(st.PPSPermitted)})
		}
		gameSessions.Samples = append(gameSessions.Samples, metrics.Sample{Labels: id, Value: float64(s.GameSessions)})
		gameSessionsMax.Samples = append(gameSessionsMax.Samples, metrics.Sample{Labels: id, Value: float64(s.GameSessionsMax)})
		for _, ps := range s.Prefixes {
			labels := with(id, metrics.Label{Name: "prefix", Value: ps.Prefix})
			prefixOfferedPPS.Samples = append(prefixOfferedPPS.Samples, metrics.Sample{Labels: labels, Value: float64(ps.OfferedPPS)})
			prefixDroppedPPS.Samples = append(prefixDroppedPPS.Samples, metrics.Sample{Labels: labels, Value: float64(ps.DroppedPPS)})
			prefixFlows.Samples = append(prefixFlows.Samples, metrics.Sample{Labels: labels, Value: float64(ps.Flows)})
			prefixFlowsDropped.Samples = append(prefixFlowsDropped.Samples, metrics.Sample{Labels: labels, Value: float64(ps.FlowsDropped)})
			prefixOffered.Samples = append(prefixOffered.Samples, metrics.Sample{Labels: labels, Value: float64(ps.Offered)})
			prefixDropped.Samples = append(prefixDropped.Samples, metrics.Sample{Labels: labels, Value: float64(ps.Dropped)})
			pulsing.Samples = append(pulsing.Samples, metrics.Sample{Labels: labels, Value: boolValue(ps.Pulsing)})
			pulsePeak.Samples = append(pulsePeak.Samples, metrics.Sample{Labels: labels, Value: float64(ps.PeakPPS)})
			pulseMean.Samples = append(pulseMean.Samples, metrics.Sample{Labels: labels, Value: float64(ps.MeanPPS)})
			pulseCrest.Samples = append(pulseCrest.Samples, metrics.Sample{Labels: labels, Value: ps.Crest})
			pulseDuty.Samples = append(pulseDuty.Samples, metrics.Sample{Labels: labels, Value: ps.DutyCycle})
			pulseBursts.Samples = append(pulseBursts.Samples, metrics.Sample{Labels: labels, Value: float64(ps.Bursts)})
			pulseHold.Samples = append(pulseHold.Samples, metrics.Sample{Labels: labels, Value: ps.HeldFor})
		}
		for _, g := range s.Games {
			labels := with(id,
				metrics.Label{Name: "filter", Value: g.FilterID},
				metrics.Label{Name: "profile", Value: g.Profile})
			gameInspected.Samples = append(gameInspected.Samples, metrics.Sample{Labels: labels, Value: float64(g.Inspected)})
			gameDropped.Samples = append(gameDropped.Samples, metrics.Sample{Labels: labels, Value: float64(g.Dropped)})
			gameChallenged.Samples = append(gameChallenged.Samples, metrics.Sample{Labels: labels, Value: float64(g.Challenged)})
			gameUninspectable.Samples = append(gameUninspectable.Samples, metrics.Sample{Labels: labels, Value: float64(g.Uninspectable)})
			gameDroppedPPS.Samples = append(gameDroppedPPS.Samples, metrics.Sample{Labels: labels, Value: float64(g.PPSDropped)})
		}
		for _, rule := range s.Rules {
			labels := with(id,
				metrics.Label{Name: "stage", Value: string(rule.Stage)},
				metrics.Label{Name: "rule", Value: rule.RuleID})
			ruleMatches.Samples = append(ruleMatches.Samples, metrics.Sample{Labels: labels, Value: float64(rule.Matches)})
			ruleDrops.Samples = append(ruleDrops.Samples, metrics.Sample{Labels: labels, Value: float64(rule.Drops)})
			ruleSeenPPS.Samples = append(ruleSeenPPS.Samples, metrics.Sample{Labels: labels, Value: float64(rule.PPSSeen)})
			ruleDroppedPPS.Samples = append(ruleDroppedPPS.Samples, metrics.Sample{Labels: labels, Value: float64(rule.PPSDropped)})
		}
		if !now.IsZero() && !r.ReportedAt.IsZero() {
			seconds := now.Sub(r.ReportedAt).Seconds()
			if seconds < 0 {
				seconds = 0
			}
			age.Samples = append(age.Samples, metrics.Sample{Labels: id, Value: seconds})
		}
	}

	return []metrics.Family{
		decisions, unowned,
		stageDropped, stagePermitted, stageDroppedPPS, stagePermittedPPS,
		ruleMatches, ruleDrops, ruleSeenPPS, ruleDroppedPPS,
		mlScored, mlDrops, mlPasses, mlReady,
		buckets, bucketsMax, offeredPPS, droppedPPSRate,
		gameInspected, gameDropped, gameChallenged, gameUninspectable, gameDroppedPPS,
		gameSessions, gameSessionsMax,
		prefixOfferedPPS, prefixDroppedPPS,
		prefixFlows, prefixFlowsDropped, prefixOffered, prefixDropped,
		pulsing, pulsePeak, pulseMean, pulseCrest, pulseDuty, pulseBursts, pulseHold,
		age,
	}
}

// AnnouncementFamilies renders a BGP announcement plan as metrics. A node
// passes its own rows and the control plane passes the whole fabric's, so the
// same series answer "where is this prefix being announced from, and how hard
// is each node leaning away from it".
func AnnouncementFamilies(plan []model.Announcement) []metrics.Family {
	announced := metrics.Family{
		Name: "scrubline_bgp_announced", Type: metrics.Gauge,
		Help: "1 when a node is advertising a protected prefix, 0 when it is withdrawn. A prefix with no node at 1 is attracting no traffic to the fabric.",
	}
	prepends := metrics.Family{
		Name: "scrubline_bgp_prepends", Type: metrics.Gauge,
		Help: "AS-path padding on a node's announcement. Higher means the node is a less attractive path and takes less of the prefix's traffic.",
	}
	for _, a := range plan {
		labels := []metrics.Label{
			{Name: "node", Value: a.NodeID},
			{Name: "name", Value: a.NodeName},
			{Name: "region", Value: a.Region},
			{Name: "prefix", Value: a.Prefix},
		}
		up := a.State == model.StateAnnounce
		announced.Samples = append(announced.Samples, metrics.Sample{Labels: labels, Value: boolValue(up)})
		if up {
			prepends.Samples = append(prepends.Samples, metrics.Sample{Labels: labels, Value: float64(a.Prepends)})
		}
	}
	return []metrics.Family{announced, prepends}
}

// TunnelFamilies renders a node's return paths as metrics.
//
// The state series is the one that matters operationally. A node announcing a
// prefix whose return tunnel is down attracts the customer's traffic and
// drops all of it, which looks like a successful scrub from every other
// angle: the datapath counters are healthy, the announcements are up, and the
// customer is offline. This is where that shows.
func TunnelFamilies(nodeID, name, region string, tunnels []model.NodeTunnel, reported []model.TunnelStatus) []metrics.Family {
	state := make(map[string]string, len(reported))
	for _, r := range reported {
		state[r.TunnelID] = r.State
	}

	up := metrics.Family{
		Name: "scrubline_tunnel_up", Type: metrics.Gauge,
		Help: "1 when a return tunnel is reported carrying traffic, 0 when it is reported down. A tunnel that has never reported is absent from this series rather than reading 0, because no news is not the same as bad news.",
	}
	required := metrics.Family{
		Name: "scrubline_tunnel_required", Type: metrics.Gauge,
		Help: "1 when a return tunnel must be confirmed up before its prefixes are announced from this node.",
	}
	reportedAt := metrics.Family{
		Name: "scrubline_tunnel_reported", Type: metrics.Gauge,
		Help: "1 when the local provisioner has said anything at all about this tunnel. Zero across the fleet means nothing is reporting, so the control plane cannot tell a healthy return path from a dead one.",
	}
	mtu := metrics.Family{
		Name: "scrubline_tunnel_mtu_bytes", Type: metrics.Gauge,
		Help: "The tunnel's MTU, after the encapsulation's overhead is taken off the path.",
	}
	clamp := metrics.Family{
		Name: "scrubline_tunnel_mss_clamp_bytes", Type: metrics.Gauge,
		Help: "The TCP MSS traffic into this tunnel is clamped to. Without it, a customer whose path drops the ICMP that path-MTU discovery needs sees TCP hang on anything larger than a handshake.",
	}
	prefixes := metrics.Family{
		Name: "scrubline_tunnel_prefixes", Type: metrics.Gauge,
		Help: "Protected prefixes delivered over this tunnel from this node.",
	}

	for _, t := range tunnels {
		labels := []metrics.Label{
			{Name: "node", Value: nodeID},
			{Name: "name", Value: name},
			{Name: "region", Value: region},
			{Name: "tunnel", Value: t.ID},
			{Name: "remote", Value: t.Remote},
		}
		switch state[t.ID] {
		case model.TunnelUp:
			up.Samples = append(up.Samples, metrics.Sample{Labels: labels, Value: 1})
			reportedAt.Samples = append(reportedAt.Samples, metrics.Sample{Labels: labels, Value: 1})
		case model.TunnelDown:
			up.Samples = append(up.Samples, metrics.Sample{Labels: labels, Value: 0})
			reportedAt.Samples = append(reportedAt.Samples, metrics.Sample{Labels: labels, Value: 1})
		default:
			// Deliberately no scrubline_tunnel_up sample. Publishing 0 here
			// would be indistinguishable from a confirmed failure, and an
			// alert on it would fire across any fleet that has not wired a
			// provisioner up yet.
			reportedAt.Samples = append(reportedAt.Samples, metrics.Sample{Labels: labels, Value: 0})
		}
		required.Samples = append(required.Samples, metrics.Sample{Labels: labels, Value: boolValue(t.Required)})
		mtu.Samples = append(mtu.Samples, metrics.Sample{Labels: labels, Value: float64(t.MTU)})
		clamp.Samples = append(clamp.Samples, metrics.Sample{Labels: labels, Value: float64(t.MSSClamp)})
		prefixes.Samples = append(prefixes.Samples, metrics.Sample{Labels: labels, Value: float64(len(t.Prefixes))})
	}
	return []metrics.Family{up, required, reportedAt, mtu, clamp, prefixes}
}
