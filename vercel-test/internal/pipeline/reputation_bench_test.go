package pipeline

// Benchmarks for the two reputation tiers. They exist because the premise
// for the cache was that the behavioural cap was expensive, and it is not:
// measuring the path first moved the work to where it actually was.

import (
	"fmt"
	"testing"
	"time"

	"github.com/Jacksondude1223-bit/scrubline-cloud-scrub/internal/ml"
	"github.com/Jacksondude1223-bit/scrubline-cloud-scrub/internal/model"
)

func readyModel() ml.Model {
	return ml.Model{Ready: true, Threshold: 0.99,
		Weights: []float64{0.01, 0.01, 0.01, 0.01, 0.01, 0.01, 0.01}}
}

// loaded is a program with a realistic rule count in front of the ZC stage,
// so the benchmarks measure what a packet actually walks.
func loaded(prog model.Program) model.Program {
	for i := 0; i < 20; i++ {
		prog.ASIC = append(prog.ASIC, model.ACLEntry{
			Action: model.ActionDrop, RuleID: fmt.Sprintf("acl-%d", i),
			Match: model.Match{SrcCIDR: "198.51.100.0/24", DstCIDR: "203.0.113.0/24", Proto: "tcp", DPort: 53},
		})
	}
	return prog
}

// benchA2S measures a verified A2S client, with and without the fast path.
func benchA2S(b *testing.B, fastPass bool) {
	prog := loaded(a2sProgram(false))
	// No behavioural cap, and a frozen clock. The two pull against each
	// other: the rate window needs time to advance or the cap trips, and
	// trust needs time to stand still or it expires — and a run long enough
	// to matter cannot have both. An earlier version of this benchmark
	// advanced an hour of clock and was timing trust expiring and the
	// client being re-challenged, which is neither path. The cap's own cost
	// is measured separately and is a few nanoseconds.
	prog.ZC[0].PPS = 0
	if !fastPass {
		prog.Reputation = &model.ReputationPolicy{FastPass: "off"}
	}
	p := New(prog)
	clock := time.Unix(1_700_000_000, 0)
	p.now = func() time.Time { return clock }
	p.SetModel(readyModel())

	query := a2sFlow("192.0.2.50", []byte{0xFF, 0xFF, 0xFF, 0xFF, 'T'})
	d := p.Decide(query)
	cookie := d.Reply[len(d.Reply)-4:]
	echo := a2sFlow("192.0.2.50", append([]byte{0xFF, 0xFF, 0xFF, 0xFF, 'T'}, cookie...))
	p.Decide(echo)
	if got := p.Decide(echo); got.Action != model.ActionPermit {
		b.Fatalf("expected an admitted client, got %+v", got)
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = p.Decide(echo)
	}
}

func BenchmarkVerifiedFastPath(b *testing.B) { benchA2S(b, true) }
func BenchmarkVerifiedFullPath(b *testing.B) { benchA2S(b, false) }

// benchOffender measures attack traffic from a source that keeps failing,
// with and without the penalty box. This is the load shedding: during an
// attack most of the packets are the attacker's.
func benchOffender(b *testing.B, box bool) {
	p := New(loaded(a2sProgram(box)))
	clock := time.Unix(1_700_000_000, 0)
	p.now = func() time.Time { return clock }
	p.SetModel(readyModel())

	junk := a2sFlow("198.51.100.9", []byte{0x00, 0x01, 0x02, 0x03, 0x04})
	for i := 0; i < 12; i++ {
		p.Decide(junk)
	}
	if got := p.Decide(junk); got.Action != model.ActionDrop {
		b.Fatalf("expected the junk dropped, got %+v", got)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = p.Decide(junk)
	}
}

func BenchmarkOffenderBoxed(b *testing.B)   { benchOffender(b, true) }
func BenchmarkOffenderUnboxed(b *testing.B) { benchOffender(b, false) }
