package telemetry

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/Jacksondude1223-bit/scrubline-cloud-scrub/internal/metrics"
	"github.com/Jacksondude1223-bit/scrubline-cloud-scrub/internal/model"
	"github.com/Jacksondude1223-bit/scrubline-cloud-scrub/internal/pipeline"
)

func sampleReport() Report {
	return Report{
		NodeID: "node-a1", Name: "scrub-a", Region: "iad",
		ReportedAt: time.Unix(1000, 0).UTC(),
		Stats: pipeline.Stats{
			Decisions: 40, Unowned: 2, RateBuckets: 11, RateBucketsMax: 65536,
			Stages: []pipeline.StageStats{
				{Stage: model.StageASIC, Dropped: 10, Permitted: 1, PPSDropped: 5000, PPSPermitted: 20},
				{Stage: model.StageZC, Dropped: 3, Permitted: 24, PPSDropped: 900, PPSPermitted: 600},
			},
			Rules: []pipeline.RuleStats{
				{RuleID: "tcam-bogon", Stage: model.StageASIC, Matches: 10, Drops: 10, PPSSeen: 5000, PPSDropped: 5000},
				{RuleID: "zc-inspect", Stage: model.StageZC, Matches: 27, Drops: 3, PPSSeen: 1500, PPSDropped: 900},
			},
			ML: pipeline.MLStats{Ready: true, Scored: 27, Drops: 3, Passes: 24},
		},
	}
}

func render(t *testing.T, reports []Report, now time.Time) string {
	t.Helper()
	var buf bytes.Buffer
	if err := metrics.Write(&buf, Families(reports, now)); err != nil {
		t.Fatalf("Write: %v", err)
	}
	return buf.String()
}

func mustContain(t *testing.T, out string, lines ...string) {
	t.Helper()
	for _, want := range lines {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in:\n%s", want, out)
		}
	}
}

func TestFamiliesRenderNodeAndRuleCounters(t *testing.T) {
	out := render(t, []Report{sampleReport()}, time.Time{})
	mustContain(t, out,
		`scrubline_decisions_total{node="node-a1",name="scrub-a",region="iad"} 40`,
		`scrubline_unowned_flows_total{node="node-a1",name="scrub-a",region="iad"} 2`,
		`scrubline_stage_dropped_total{node="node-a1",name="scrub-a",region="iad",stage="asic"} 10`,
		`scrubline_stage_dropped_pps_total{node="node-a1",name="scrub-a",region="iad",stage="zc"} 900`,
		`scrubline_rule_drops_total{node="node-a1",name="scrub-a",region="iad",stage="asic",rule="tcam-bogon"} 10`,
		`scrubline_rule_matches_total{node="node-a1",name="scrub-a",region="iad",stage="zc",rule="zc-inspect"} 27`,
		`scrubline_ml_model_ready{node="node-a1",name="scrub-a",region="iad"} 1`,
		`scrubline_rate_buckets{node="node-a1",name="scrub-a",region="iad"} 11`,
	)
}

// A node rendering its own live counters has nothing to age.
func TestReportAgeIsOmittedWithoutAClock(t *testing.T) {
	out := render(t, []Report{sampleReport()}, time.Time{})
	if strings.Contains(out, "scrubline_report_age_seconds") {
		t.Fatalf("a node's own scrape must not carry a report age:\n%s", out)
	}
}

// The control plane serves counters it was told about, so how stale they are
// is part of the answer.
func TestReportAgeIsExposedWithAClock(t *testing.T) {
	out := render(t, []Report{sampleReport()}, time.Unix(1030, 0).UTC())
	mustContain(t, out, `scrubline_report_age_seconds{node="node-a1",name="scrub-a",region="iad"} 30`)
}

// A clock behind a node's report must not produce a negative age.
func TestReportAgeIsNeverNegative(t *testing.T) {
	out := render(t, []Report{sampleReport()}, time.Unix(900, 0).UTC())
	mustContain(t, out, `scrubline_report_age_seconds{node="node-a1",name="scrub-a",region="iad"} 0`)
}

// The fleet view is the same vocabulary, one series per node.
func TestFleetRendersOneSeriesPerNode(t *testing.T) {
	a := sampleReport()
	b := sampleReport()
	b.NodeID, b.Name, b.Region = "node-b2", "scrub-b", "fra"
	b.Stats.Decisions = 7
	out := render(t, []Report{a, b}, time.Time{})
	mustContain(t, out,
		`scrubline_decisions_total{node="node-a1",name="scrub-a",region="iad"} 40`,
		`scrubline_decisions_total{node="node-b2",name="scrub-b",region="fra"} 7`,
	)
	// One HELP/TYPE block per family, however many nodes report.
	if got := strings.Count(out, "# TYPE scrubline_decisions_total"); got != 1 {
		t.Fatalf("expected one TYPE line for the family, got %d:\n%s", got, out)
	}
}

func TestEmptyFleetRendersNothing(t *testing.T) {
	if out := render(t, nil, time.Now()); out != "" {
		t.Fatalf("expected no output for an empty fleet, got %q", out)
	}
}

// A rule ID comes from a policy, so it reaches the exposition as untrusted
// text and must not be able to break out of its label.
func TestRuleIDsAreEscapedInLabels(t *testing.T) {
	r := sampleReport()
	r.Stats.Rules = []pipeline.RuleStats{{RuleID: `ev"il`, Stage: model.StageZC, Matches: 1}}
	out := render(t, []Report{r}, time.Time{})
	mustContain(t, out, `rule="ev\"il"`)
}
