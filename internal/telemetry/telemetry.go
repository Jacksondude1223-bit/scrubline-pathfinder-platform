// Package telemetry carries datapath counters from scrubbing nodes to the
// control plane, and renders them in one metric vocabulary. A node exposes its
// own report and the control plane exposes every report it has collected, so a
// dashboard written against one works against the other.
package telemetry

import (
	"time"

	"github.com/Jacksondude1223-bit/scrubline-cloud-scrub/internal/metrics"
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
		bucketsMax.Samples = append(bucketsMax.Samples, metrics.Sample{Labels: id, Value: float64(s.RateBucketsMax)})

		for _, st := range s.Stages {
			labels := with(id, metrics.Label{Name: "stage", Value: string(st.Stage)})
			stageDropped.Samples = append(stageDropped.Samples, metrics.Sample{Labels: labels, Value: float64(st.Dropped)})
			stagePermitted.Samples = append(stagePermitted.Samples, metrics.Sample{Labels: labels, Value: float64(st.Permitted)})
			stageDroppedPPS.Samples = append(stageDroppedPPS.Samples, metrics.Sample{Labels: labels, Value: float64(st.PPSDropped)})
			stagePermittedPPS.Samples = append(stagePermittedPPS.Samples, metrics.Sample{Labels: labels, Value: float64(st.PPSPermitted)})
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
		buckets, bucketsMax, age,
	}
}
