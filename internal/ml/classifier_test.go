package ml

import (
	"math"
	"strings"
	"testing"

	"github.com/Jacksondude1223-bit/scrubline-cloud-scrub/internal/model"
)

func TestTrainSeparatesFloodFromPlay(t *testing.T) {
	var samples []Sample
	for i := 0; i < 20; i++ {
		samples = append(samples, Sample{Flow: model.Flow{Proto: "tcp", DPort: 443, SPort: 40000 + i, PPS: 40}, Label: 0})
		samples = append(samples, Sample{Flow: model.Flow{Proto: "tcp", Flags: "syn", DPort: 443, SPort: 1000 + i, PPS: 200000}, Label: 1})
	}
	m, err := Train(samples, 300, 0.2, 0.6)
	if err != nil {
		t.Fatalf("Train: %v", err)
	}
	if !m.Ready || m.Accuracy < 0.9 {
		t.Fatalf("expected a fitted model, got %+v", m)
	}
	if Predict(m, model.Flow{Proto: "tcp", DPort: 443, SPort: 41000, PPS: 30}) != 0 {
		t.Fatal("clean play flow scored as attack")
	}
	if Predict(m, model.Flow{Proto: "tcp", Flags: "syn", DPort: 443, SPort: 9, PPS: 250000}) != 1 {
		t.Fatal("syn flood flow was not scored as attack")
	}
}

// A negative pps used to put NaN into Log1p, which spread through every weight
// and then made the model unencodable as JSON.
func TestTrainRejectsOutOfRangeFlows(t *testing.T) {
	for _, tc := range []struct {
		name string
		flow model.Flow
	}{
		{"negative pps", model.Flow{Proto: "udp", PPS: -5}},
		{"negative dport", model.Flow{Proto: "udp", DPort: -1}},
		{"dport too large", model.Flow{Proto: "udp", DPort: 70000}},
		{"negative sport", model.Flow{Proto: "udp", SPort: -1}},
		{"sport too large", model.Flow{Proto: "udp", SPort: 99999}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			samples := []Sample{
				{Flow: model.Flow{Proto: "tcp", PPS: 10}, Label: 0},
				{Flow: tc.flow, Label: 1},
			}
			if _, err := Train(samples, 10, 0.2, 0.6); err == nil {
				t.Fatal("expected Train to reject the sample set")
			}
			if err := ValidateFlow(tc.flow); err == nil {
				t.Fatal("expected ValidateFlow to reject the flow")
			}
		})
	}
}

func TestTrainRejectsBadLabel(t *testing.T) {
	for _, label := range []int{-1, 2, 99} {
		samples := []Sample{
			{Flow: model.Flow{Proto: "tcp", PPS: 10}, Label: 0},
			{Flow: model.Flow{Proto: "udp", PPS: 20}, Label: label},
		}
		_, err := Train(samples, 10, 0.2, 0.6)
		if err == nil {
			t.Fatalf("label %d: expected Train to reject the sample set", label)
		}
		if !strings.Contains(err.Error(), "label") {
			t.Fatalf("label %d: expected a label error, got %v", label, err)
		}
	}
}

func TestTrainRejectsEmptySampleSet(t *testing.T) {
	if _, err := Train(nil, 10, 0.2, 0.6); err == nil {
		t.Fatal("expected an error for an empty sample set")
	}
}

// Features must stay finite whatever a caller passes, so a model can never
// reach the wire carrying NaN.
func TestFeaturesAlwaysFinite(t *testing.T) {
	for _, f := range []model.Flow{
		{PPS: -1},
		{PPS: math.MaxInt32, DPort: -7, SPort: 1 << 30},
		{Proto: "TCP", Flags: "SYN", PPS: 1000},
	} {
		for i, v := range Features(f) {
			if math.IsNaN(v) || math.IsInf(v, 0) {
				t.Fatalf("flow %+v: feature %d is %v", f, i, v)
			}
		}
	}
}

func TestFeatureVectorLengthMatchesWeights(t *testing.T) {
	if got := len(Features(model.Flow{})); got != FeatureCount {
		t.Fatalf("Features returned %d values, FeatureCount is %d", got, FeatureCount)
	}
}

// Score and Predict must not act on a model that was never fitted.
func TestUntrainedModelScoresZero(t *testing.T) {
	var m Model
	if got := Score(m, model.Flow{Proto: "tcp", PPS: 999999}); got != 0 {
		t.Fatalf("expected 0 from an unready model, got %v", got)
	}
	if got := Predict(m, model.Flow{Proto: "tcp", PPS: 999999}); got != 0 {
		t.Fatalf("expected label 0 from an unready model, got %d", got)
	}
}

// Zero weights and zero bias score exactly 0.5, so the threshold decides.
func TestPredictHonorsThreshold(t *testing.T) {
	flow := model.Flow{Proto: "tcp"}
	at := Model{Weights: make([]float64, FeatureCount), Threshold: 0.5, Ready: true}
	if got := Predict(at, flow); got != 1 {
		t.Fatalf("score 0.5 at threshold 0.5 should label 1, got %d", got)
	}
	above := Model{Weights: make([]float64, FeatureCount), Threshold: 0.9, Ready: true}
	if got := Predict(above, flow); got != 0 {
		t.Fatalf("score 0.5 at threshold 0.9 should label 0, got %d", got)
	}
}

func TestScoreRejectsWeightLengthMismatch(t *testing.T) {
	m := Model{Weights: []float64{1, 2}, Threshold: 0.5, Ready: true}
	if got := Score(m, model.Flow{Proto: "tcp", PPS: 100}); got != 0 {
		t.Fatalf("expected 0 for a model whose weight count does not match FeatureCount, got %v", got)
	}
}
