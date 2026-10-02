package ml

import (
	"errors"
	"fmt"
	"math"
	"strings"

	"github.com/Jacksondude1223-bit/scrubline-cloud-scrub/internal/model"
)

const FeatureCount = 7

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
	Samples   int       `json:"samples"`
	Ready     bool      `json:"ready"`
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
	w := make([]float64, FeatureCount)
	bias := 0.0
	loss := 0.0
	for ep := 0; ep < epochs; ep++ {
		loss = 0
		for _, s := range samples {
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
		loss /= float64(len(samples))
	}
	fitted := Model{
		Weights: w, Bias: bias, Threshold: threshold, Epochs: epochs,
		Loss: loss, Samples: len(samples), Ready: true,
	}
	// A divergent learning rate can still push the weights to Inf or NaN. Catch
	// that here rather than shipping a model that scores every flow as NaN.
	if err := checkFinite(fitted); err != nil {
		return Model{}, err
	}
	correct := 0
	for _, s := range samples {
		if Predict(fitted, s.Flow) == s.Label {
			correct++
		}
	}
	fitted.Accuracy = float64(correct) / float64(len(samples))
	return fitted, nil
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
