package metrics

import (
	"bytes"
	"math"
	"strings"
	"testing"
)

func render(t *testing.T, families []Family) string {
	t.Helper()
	var buf bytes.Buffer
	if err := Write(&buf, families); err != nil {
		t.Fatalf("Write: %v", err)
	}
	return buf.String()
}

func TestWriteRendersHelpTypeAndSamples(t *testing.T) {
	got := render(t, []Family{{
		Name: "scrubline_decisions_total",
		Help: "Flow decisions by stage and action.",
		Type: Counter,
		Samples: []Sample{
			{Labels: []Label{{"stage", "zc"}, {"action", "drop"}}, Value: 7},
			{Labels: []Label{{"stage", "asic"}, {"action", "drop"}}, Value: 3},
		},
	}})
	want := `# HELP scrubline_decisions_total Flow decisions by stage and action.
# TYPE scrubline_decisions_total counter
scrubline_decisions_total{stage="asic",action="drop"} 3
scrubline_decisions_total{stage="zc",action="drop"} 7
`
	if got != want {
		t.Fatalf("unexpected exposition:\n%s\nwant:\n%s", got, want)
	}
}

// A scrape has to be byte-stable, or every scrape looks like a change.
func TestWriteIsDeterministic(t *testing.T) {
	fam := []Family{{
		Name: "scrubline_rule_matches_total", Type: Counter, Help: "h",
		Samples: []Sample{
			{Labels: []Label{{"rule", "z"}}, Value: 1},
			{Labels: []Label{{"rule", "a"}}, Value: 2},
			{Labels: []Label{{"rule", "m"}}, Value: 3},
		},
	}}
	first := render(t, fam)
	for i := 0; i < 20; i++ {
		if got := render(t, fam); got != first {
			t.Fatalf("output changed between renders:\n%s\n%s", first, got)
		}
	}
}

// Rule IDs and node names come out of a policy, so a label value cannot be
// assumed safe to paste into the format.
func TestLabelValuesAreEscaped(t *testing.T) {
	got := render(t, []Family{{
		Name: "scrubline_rule_matches_total", Type: Counter, Help: "h",
		Samples: []Sample{{Labels: []Label{{"rule", `we"ird\rule` + "\nsecond"}}, Value: 1}},
	}})
	if !strings.Contains(got, `rule="we\"ird\\rule\nsecond"`) {
		t.Fatalf("label value was not escaped: %s", got)
	}
	// The escaped form must not introduce a stray newline into the sample line.
	for _, line := range strings.Split(strings.TrimSpace(got), "\n") {
		if strings.HasPrefix(line, "#") {
			continue
		}
		if strings.Count(line, " ") < 1 || !strings.HasSuffix(line, " 1") {
			t.Fatalf("sample line is malformed: %q", line)
		}
	}
}

func TestHelpTextIsEscaped(t *testing.T) {
	got := render(t, []Family{{
		Name: "m", Type: Gauge, Help: "back\\slash and\nnewline",
		Samples: []Sample{{Value: 1}},
	}})
	if !strings.Contains(got, `# HELP m back\\slash and\nnewline`) {
		t.Fatalf("help text was not escaped: %q", got)
	}
	if strings.Count(got, "\n") != 3 {
		t.Fatalf("expected three lines, got %q", got)
	}
}

func TestUnlabeledSampleHasNoBraces(t *testing.T) {
	got := render(t, []Family{{Name: "m", Type: Gauge, Help: "h", Samples: []Sample{{Value: 42}}}})
	if !strings.Contains(got, "\nm 42\n") {
		t.Fatalf("expected a bare sample line, got %q", got)
	}
}

// A family with no samples would emit a HELP/TYPE pair describing nothing.
func TestEmptyFamiliesAreSkipped(t *testing.T) {
	got := render(t, []Family{
		{Name: "empty", Type: Counter, Help: "h"},
		{Name: "present", Type: Counter, Help: "h", Samples: []Sample{{Value: 1}}},
	})
	if strings.Contains(got, "empty") {
		t.Fatalf("an empty family was rendered: %q", got)
	}
	if !strings.Contains(got, "present 1") {
		t.Fatalf("expected the non-empty family: %q", got)
	}
}

// Two HELP/TYPE blocks for one name is a parse error at the scraper.
func TestDuplicateFamilyIsRejected(t *testing.T) {
	err := Write(&bytes.Buffer{}, []Family{
		{Name: "m", Type: Counter, Help: "h", Samples: []Sample{{Value: 1}}},
		{Name: "m", Type: Counter, Help: "h", Samples: []Sample{{Value: 2}}},
	})
	if err == nil {
		t.Fatal("expected a duplicate family to be rejected")
	}
}

func TestInvalidNamesAreRejected(t *testing.T) {
	for _, name := range []string{"", "1leading", "has-dash", "has space"} {
		err := Write(&bytes.Buffer{}, []Family{{Name: name, Type: Counter, Samples: []Sample{{Value: 1}}}})
		if err == nil {
			t.Fatalf("metric name %q should be rejected", name)
		}
	}
	for _, label := range []string{"", "1leading", "has-dash"} {
		err := Write(&bytes.Buffer{}, []Family{{
			Name: "m", Type: Counter,
			Samples: []Sample{{Labels: []Label{{label, "v"}}, Value: 1}},
		}})
		if err == nil {
			t.Fatalf("label name %q should be rejected", label)
		}
	}
}

func TestValueFormatting(t *testing.T) {
	for _, tc := range []struct {
		value float64
		want  string
	}{
		{0, "0"},
		{42, "42"},
		{-1, "-1"},
		{0.5, "0.5"},
		{1e21, "1e+21"},
		{math.Inf(1), "+Inf"},
		{math.Inf(-1), "-Inf"},
		{math.NaN(), "NaN"},
	} {
		if got := formatValue(tc.value); got != tc.want {
			t.Fatalf("formatValue(%v) = %q, want %q", tc.value, got, tc.want)
		}
	}
}

// Large counters must not be rendered in scientific notation with lost
// precision: a packet count has to survive the round trip.
func TestLargeCounterKeepsPrecision(t *testing.T) {
	const packets = 9007199254740992 // 2^53, the largest exactly-representable integer
	if got := formatValue(packets); got != "9.007199254740992e+15" {
		t.Fatalf("unexpected rendering %q", got)
	}
}
