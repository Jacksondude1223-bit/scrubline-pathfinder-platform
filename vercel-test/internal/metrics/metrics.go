// Package metrics renders Prometheus text exposition. The repository carries
// no third-party dependencies, and counters and gauges need little more than
// careful formatting, so the format is written here rather than pulled in.
package metrics

import (
	"bufio"
	"fmt"
	"io"
	"math"
	"sort"
	"strconv"
	"strings"
)

// ContentType is the exposition format this package writes.
const ContentType = "text/plain; version=0.0.4; charset=utf-8"

// Type is a metric family's type as Prometheus understands it.
type Type string

const (
	Counter Type = "counter"
	Gauge   Type = "gauge"
)

// Label is one dimension of a sample. Label order within a sample is kept as
// given, so a family's samples read consistently.
type Label struct {
	Name  string
	Value string
}

// Sample is one time series within a family.
type Sample struct {
	Labels []Label
	Value  float64
}

// Family is a metric name with its samples. Every sample in a family shares
// the name, help text, and type.
type Family struct {
	Name    string
	Help    string
	Type    Type
	Samples []Sample
}

// Write renders families in exposition format. Families are emitted in the
// order given, each preceded by its HELP and TYPE lines; a family with no
// samples is skipped, because a bare HELP/TYPE pair carries no information.
//
// Samples within a family are sorted by their label values so a scrape is
// byte-stable, which makes the output diffable and the tests deterministic.
func Write(w io.Writer, families []Family) error {
	bw := bufio.NewWriter(w)
	seen := make(map[string]bool, len(families))
	for _, f := range families {
		if len(f.Samples) == 0 {
			continue
		}
		if !validMetricName(f.Name) {
			return fmt.Errorf("metrics: invalid metric name %q", f.Name)
		}
		// A repeated family name would emit a second HELP/TYPE block, which
		// parsers reject.
		if seen[f.Name] {
			return fmt.Errorf("metrics: duplicate metric family %q", f.Name)
		}
		seen[f.Name] = true

		if f.Help != "" {
			fmt.Fprintf(bw, "# HELP %s %s\n", f.Name, escapeHelp(f.Help))
		}
		if f.Type != "" {
			fmt.Fprintf(bw, "# TYPE %s %s\n", f.Name, f.Type)
		}

		samples := make([]Sample, len(f.Samples))
		copy(samples, f.Samples)
		sort.SliceStable(samples, func(i, j int) bool {
			return labelKey(samples[i].Labels) < labelKey(samples[j].Labels)
		})
		for _, s := range samples {
			labels, err := formatLabels(s.Labels)
			if err != nil {
				return fmt.Errorf("metrics: %s: %w", f.Name, err)
			}
			if _, err := bw.WriteString(f.Name + labels + " " + formatValue(s.Value) + "\n"); err != nil {
				return err
			}
		}
	}
	return bw.Flush()
}

func labelKey(labels []Label) string {
	var b strings.Builder
	for _, l := range labels {
		b.WriteString(l.Name)
		b.WriteByte(0)
		b.WriteString(l.Value)
		b.WriteByte(0)
	}
	return b.String()
}

func formatLabels(labels []Label) (string, error) {
	if len(labels) == 0 {
		return "", nil
	}
	var b strings.Builder
	b.WriteByte('{')
	for i, l := range labels {
		if !validLabelName(l.Name) {
			return "", fmt.Errorf("invalid label name %q", l.Name)
		}
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(l.Name)
		b.WriteString(`="`)
		b.WriteString(escapeLabelValue(l.Value))
		b.WriteByte('"')
	}
	b.WriteByte('}')
	return b.String(), nil
}

// formatValue renders a float the way the exposition format expects, including
// its spellings for the non-finite values.
func formatValue(v float64) string {
	switch {
	case math.IsNaN(v):
		return "NaN"
	case math.IsInf(v, 1):
		return "+Inf"
	case math.IsInf(v, -1):
		return "-Inf"
	}
	return strconv.FormatFloat(v, 'g', -1, 64)
}

// escapeLabelValue escapes the three characters the format reserves inside a
// label value. A rule ID or node name reaches here from a policy, so it cannot
// be assumed safe.
func escapeLabelValue(s string) string {
	return strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`).Replace(s)
}

// escapeHelp escapes what HELP text reserves: a backslash and a newline. A
// quote needs no escaping there.
func escapeHelp(s string) string {
	return strings.NewReplacer(`\`, `\\`, "\n", `\n`).Replace(s)
}

func validMetricName(s string) bool {
	if s == "" {
		return false
	}
	for i, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r == '_', r == ':':
		case i > 0 && r >= '0' && r <= '9':
		default:
			return false
		}
	}
	return true
}

func validLabelName(s string) bool {
	if s == "" {
		return false
	}
	for i, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r == '_':
		case i > 0 && r >= '0' && r <= '9':
		default:
			return false
		}
	}
	return true
}
