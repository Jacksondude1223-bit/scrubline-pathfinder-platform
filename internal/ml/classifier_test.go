package ml

import (
	"testing"

	"github.com/Jacksondude1223-bit/scrubline-cloud-scrub/internal/model"
)

func TestTrainSeparatesFloodFromPlay(t *testing.T) {
	var samples []Sample
	for i := 0; i < 20; i++ {
		samples = append(samples, Sample{Flow: model.Flow{Proto: "tcp", DPort: 443, SPort: 40000 + i, PPS: 40}, Label: 0})
		samples = append(samples, Sample{Flow: model.Flow{Proto: "tcp", Flags: "syn", DPort: 443, SPort: 1000 + i, PPS: 200000}, Label: 1})
	}
	m := Train(samples, 300, 0.2, 0.6)
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
