package ml

import (
	"math"
	"strings"

	"github.com/Jacksondude1223-bit/scrubline-cloud-scrub/internal/model"
)

const FeatureCount = 7

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

func Features(f model.Flow) []float64 {
	proto := strings.ToLower(f.Proto)
	syn := 0.0
	if strings.EqualFold(f.Flags, "syn") {
		syn = 1
	}
	pps := math.Log1p(float64(f.PPS)) / 12
	return []float64{
		pps,
		boolFloat(proto == "tcp"),
		boolFloat(proto == "udp"),
		boolFloat(proto == "icmp"),
		syn,
		float64(f.DPort) / 65535,
		float64(f.SPort) / 65535,
	}
}

func Train(samples []Sample, epochs int, lr, threshold float64) Model {
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
			if y != 0 && y != 1 {
				y = 1
			}
			err := p - y
			loss += -(y*math.Log(clamp(p)) + (1-y)*math.Log(clamp(1-p)))
			for i := range w {
				w[i] -= lr * err * x[i]
			}
			bias -= lr * err
		}
		if len(samples) > 0 {
			loss /= float64(len(samples))
		}
	}
	correct := 0
	for _, s := range samples {
		y := s.Label
		if y != 0 {
			y = 1
		}
		if Predict(Model{Weights: w, Bias: bias, Threshold: threshold, Ready: true}, s.Flow) == y {
			correct++
		}
	}
	acc := 0.0
	if len(samples) > 0 {
		acc = float64(correct) / float64(len(samples))
	}
	return Model{
		Weights: w, Bias: bias, Threshold: threshold, Epochs: epochs,
		Loss: loss, Accuracy: acc, Samples: len(samples), Ready: len(samples) > 0,
	}
}

func Score(m Model, f model.Flow) float64 {
	if !m.Ready || len(m.Weights) != FeatureCount {
		return 0
	}
	return sigmoid(dot(m.Weights, Features(f)) + m.Bias)
}

func Predict(m Model, f model.Flow) int {
	if Score(m, f) >= m.Threshold {
		return 1
	}
	return 0
}

func dot(w, x []float64) float64 {
	n := 0.0
	for i := range w {
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

func boolFloat(v bool) float64 {
	if v {
		return 1
	}
	return 0
}
