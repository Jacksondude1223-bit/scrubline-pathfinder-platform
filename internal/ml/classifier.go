package ml

import (
	"errors"
	"fmt"
	"math"
	"strings"

	"github.com/Jacksondude1223-bit/scrubline-cloud-scrub/internal/model"
)

const FeatureCount = 7

// minHoldout is the smallest sample set worth splitting. Below it a holdout is
// too small to say anything, so the fit uses every sample and reports its
// metrics as training metrics.
const minHoldout = 10

// holdoutFraction is the share of samples reserved for evaluation.
const holdoutFraction = 5 // one in five

// MaxPort is the largest port number a flow record can carry.
const MaxPort = 65535

type Sample struct {
	Flow  model.Flow `json:"flow"`
	Label int        `json:"label"`
}

type Model struct {
	Weights   []float64 `json:"weights"`
	Bias      float64   `json:"bias"`
	Threshold float64   `json:"threshold"`
	Epochs    int       `json:"epochs"`
	Loss      float64   `json:"loss"`
	Accuracy  float64   `json:"accuracy"`
	// Precision and Recall are the ones that matter operationally: a false
	// positive here is dropped customer traffic. On an imbalanced attack/clean
	// set, accuracy alone says very little.
	Precision float64 `json:"precision"`
	Recall    float64 `json:"recall"`
	// Validation is the number of samples held out of the fit and scored
	// against. Zero means the metrics are training metrics on too small a set
	// to split.
	Validation int  `json:"validation"`
	Samples    int  `json:"samples"`
	Ready      bool `json:"ready"`
	// Withdrawn marks a model the control plane has explicitly retired. A node
	// clears its installed copy when it sees this, which the zero model cannot
	// signal because it is indistinguishable from "never trained".
	Withdrawn bool `json:"withdrawn,omitempty"`
}

// ValidateFlow rejects flow records that cannot be turned into finite features.
// A single out-of-range field would otherwise poison training with NaN, so the
// control plane refuses the record instead of fitting on it.
func ValidateFlow(f model.Flow) error {
	if f.PPS < 0 {
		return fmt.Errorf("pps must not be negative, got %d", f.PPS)
	}
	if f.DPort < 0 || f.DPort > MaxPort {
		return fmt.Errorf("dport must be within 0..%d, got %d", MaxPort, f.DPort)
	}
	if f.SPort < 0 || f.SPort > MaxPort {
		return fmt.Errorf("sport must be within 0..%d, got %d", MaxPort, f.SPort)
	}
	return nil
}

// ValidateSample checks the label as well as the flow.
func ValidateSample(s Sample) error {
	if s.Label != 0 && s.Label != 1 {
		return fmt.Errorf("label must be 0 (clean) or 1 (attack), got %d", s.Label)
	}
	return ValidateFlow(s.Flow)
}

func Features(f model.Flow) []float64 {
	proto := strings.ToLower(f.Proto)
	syn := 0.0
	if strings.EqualFold(f.Flags, "syn") {
		syn = 1
	}
	// Clamp before the log: Log1p of anything below -1 is NaN, and a NaN here
	// spreads through every weight and then through every JSON response.
	pps := math.Log1p(float64(clampInt(f.PPS, 0, math.MaxInt32))) / 12
	return []float64{
		pps,
		boolFloat(proto == "tcp"),
		boolFloat(proto == "udp"),
		boolFloat(proto == "icmp"),
		syn,
		float64(clampInt(f.DPort, 0, MaxPort)) / MaxPort,
		float64(clampInt(f.SPort, 0, MaxPort)) / MaxPort,
	}
}

// Train fits the logistic model. It returns an error when the sample set cannot
// produce a usable model so the caller can report that instead of publishing a
// degenerate one.
//
// Samples are split into a fit set and a holdout, and the reported metrics are
// measured on the holdout. Scoring the fit on its own training data reported an
// accuracy that said nothing about unseen traffic.
func Train(samples []Sample, epochs int, lr, threshold float64) (Model, error) {
	if len(samples) == 0 {
		return Model{}, errors.New("no samples to train on")
	}
	for i, s := range samples {
		if err := ValidateSample(s); err != nil {
			return Model{}, fmt.Errorf("sample %d: %w", i, err)
		}
	}
	if epochs <= 0 {
		epochs = 200
	}
	if lr <= 0 {
		lr = 0.15
	}
	if threshold <= 0 {
		threshold = 0.7
	}

	fit, holdout := split(samples)
	w := make([]float64, FeatureCount)
	bias := 0.0
	loss := 0.0
	for ep := 0; ep < epochs; ep++ {
		loss = 0
		for _, s := range fit {
			x := Features(s.Flow)
			p := sigmoid(dot(w, x) + bias)
			y := float64(s.Label)
			err := p - y
			loss += -(y*math.Log(clamp(p)) + (1-y)*math.Log(clamp(1-p)))
			for i := range w {
				w[i] -= lr * err * x[i]
			}
			bias -= lr * err
		}
		loss /= float64(len(fit))
	}
	fitted := Model{
		Weights: w, Bias: bias, Threshold: threshold, Epochs: epochs,
		Loss: loss, Samples: len(samples), Validation: len(holdout), Ready: true,
	}
	// A divergent learning rate can still push the weights to Inf or NaN. Catch
	// that here rather than shipping a model that scores every flow as NaN.
	if err := checkFinite(fitted); err != nil {
		return Model{}, err
	}

	scored := holdout
	if len(scored) == 0 {
		scored = fit
	}
	fitted.Accuracy, fitted.Precision, fitted.Recall = evaluate(fitted, scored)
	return fitted, nil
}

// split reserves one sample in holdoutFraction for evaluation. The pick is
// deterministic so the same sample set always reports the same metrics, and
// it strides rather than cuts so an ordered set does not put every attack
// sample on one side.
func split(samples []Sample) (fit, holdout []Sample) {
	if len(samples) < minHoldout {
		return samples, nil
	}
	fit = make([]Sample, 0, len(samples))
	holdout = make([]Sample, 0, len(samples)/holdoutFraction+1)
	for i, s := range samples {
		if i%holdoutFraction == holdoutFraction-1 {
			holdout = append(holdout, s)
			continue
		}
		fit = append(fit, s)
	}
	if len(holdout) == 0 || len(fit) == 0 {
		return samples, nil
	}
	return fit, holdout
}

// evaluate scores a fitted model against a sample set. Precision and recall are
// reported for the attack class.
func evaluate(m Model, samples []Sample) (accuracy, precision, recall float64) {
	if len(samples) == 0 {
		return 0, 0, 0
	}
	var correct, truePos, falsePos, falseNeg int
	for _, s := range samples {
		predicted := Predict(m, s.Flow)
		if predicted == s.Label {
			correct++
		}
		switch {
		case predicted == 1 && s.Label == 1:
			truePos++
		case predicted == 1 && s.Label == 0:
			falsePos++
		case predicted == 0 && s.Label == 1:
			falseNeg++
		}
	}
	accuracy = float64(correct) / float64(len(samples))
	if truePos+falsePos > 0 {
		precision = float64(truePos) / float64(truePos+falsePos)
	}
	if truePos+falseNeg > 0 {
		recall = float64(truePos) / float64(truePos+falseNeg)
	}
	return accuracy, precision, recall
}

func checkFinite(m Model) error {
	for i, v := range m.Weights {
		if math.IsNaN(v) || math.IsInf(v, 0) {
			return fmt.Errorf("training diverged: weight %d is %v (try a smaller lr)", i, v)
		}
	}
	for name, v := range map[string]float64{"bias": m.Bias, "loss": m.Loss} {
		if math.IsNaN(v) || math.IsInf(v, 0) {
			return fmt.Errorf("training diverged: %s is %v (try a smaller lr)", name, v)
		}
	}
	return nil
}

func Score(m Model, f model.Flow) float64 {
	if !m.Ready || len(m.Weights) != FeatureCount {
		return 0
	}
	s := sigmoid(dot(m.Weights, Features(f)) + m.Bias)
	if math.IsNaN(s) {
		return 0
	}
	return s
}

func Predict(m Model, f model.Flow) int {
	if !m.Ready {
		return 0
	}
	if Score(m, f) >= m.Threshold {
		return 1
	}
	return 0
}

func dot(w, x []float64) float64 {
	n := 0.0
	for i := range w {
		if i >= len(x) {
			break
		}
		n += w[i] * x[i]
	}
	return n
}

func sigmoid(z float64) float64 {
	if z > 30 {
		return 1
	}
	if z < -30 {
		return 0
	}
	return 1 / (1 + math.Exp(-z))
}

func clamp(p float64) float64 {
	if p < 1e-9 {
		return 1e-9
	}
	if p > 1-1e-9 {
		return 1 - 1e-9
	}
	return p
}

func clampInt(v, lo, hi int) int {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

func boolFloat(v bool) float64 {
	if v {
		return 1
	}
	return 0
}
