package ml

import (
	"fmt"
	"testing"

	"github.com/Jacksondude1223-bit/scrubline-cloud-scrub/internal/model"
)

func benchSamples(n int) []Sample {
	out := make([]Sample, 0, n)
	for i := 0; i < n; i++ {
		if i%2 == 0 {
			out = append(out, Sample{Flow: model.Flow{Proto: "tcp", DPort: 443, SPort: 40000 + i%20000, PPS: 40}, Label: 0})
		} else {
			out = append(out, Sample{Flow: model.Flow{Proto: "tcp", Flags: "syn", DPort: 443, SPort: 1000 + i%60000, PPS: 200000}, Label: 1})
		}
	}
	return out
}

func BenchmarkFeatures(b *testing.B) {
	f := model.Flow{Proto: "tcp", Flags: "syn", DPort: 443, SPort: 51000, PPS: 200000}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Features(f)
	}
}

func BenchmarkScore(b *testing.B) {
	m, err := Train(benchSamples(40), 300, 0.2, 0.65)
	if err != nil {
		b.Fatal(err)
	}
	f := model.Flow{Proto: "tcp", Flags: "syn", DPort: 443, SPort: 51000, PPS: 200000}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Score(m, f)
	}
}

// Training is the control plane's heaviest operation. It scales with
// epochs * samples, and the store now runs it outside its lock.
func BenchmarkTrain(b *testing.B) {
	for _, tc := range []struct{ samples, epochs int }{
		{40, 300},
		{1000, 300},
		{10000, 300},
		{10000, 1000},
	} {
		b.Run(fmt.Sprintf("samples=%d/epochs=%d", tc.samples, tc.epochs), func(b *testing.B) {
			samples := benchSamples(tc.samples)
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if _, err := Train(samples, tc.epochs, 0.2, 0.65); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkValidateSample(b *testing.B) {
	s := Sample{Flow: model.Flow{Proto: "tcp", DPort: 443, SPort: 51000, PPS: 40}, Label: 0}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := ValidateSample(s); err != nil {
			b.Fatal(err)
		}
	}
}
