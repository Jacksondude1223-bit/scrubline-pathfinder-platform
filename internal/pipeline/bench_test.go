package pipeline

import (
	"fmt"
	"net/netip"
	"testing"
	"time"

	"github.com/Jacksondude1223-bit/scrubline-cloud-scrub/internal/ml"
	"github.com/Jacksondude1223-bit/scrubline-cloud-scrub/internal/model"
)

func benchProgram() model.Program {
	return model.Program{
		NodeID:   "node-a",
		PolicyID: "pol-1",
		Version:  1,
		Prefixes: []string{"203.0.113.0/24"},
		ASIC: []model.ACLEntry{
			{Priority: 100, Action: model.ActionDrop, RuleID: "tcam-bogon", Match: model.Match{SrcCIDR: "0.0.0.0/8", DstCIDR: "203.0.113.0/24"}},
			{Priority: 200, Action: model.ActionDrop, RuleID: "tcam-flood", Match: model.Match{SrcCIDR: "198.51.100.0/24", DstCIDR: "203.0.113.0/24", Proto: "udp", DPort: 19132}},
		},
		FPGA: []model.FPGAEntry{
			{Table: "scrub_meter", Action: model.ActionLimit, Meter: 50000, RuleID: "fpga-udp", Match: model.Match{DstCIDR: "203.0.113.0/24", Proto: "udp"}},
			{Table: "scrub_meter", Action: model.ActionLimit, Meter: 20000, RuleID: "fpga-syn", Match: model.Match{DstCIDR: "203.0.113.0/24", Proto: "tcp", TCPFlags: "syn"}},
		},
		ZC: []model.ZCEntry{
			{Cluster: "zc:scrub-a", Action: model.ActionInspect, PPS: 100000, RuleID: "zc-inspect", Match: model.Match{DstCIDR: "203.0.113.0/24", Proto: "tcp"}},
		},
	}
}

func trainedModel(b *testing.B) ml.Model {
	b.Helper()
	var samples []ml.Sample
	for i := 0; i < 20; i++ {
		samples = append(samples,
			ml.Sample{Flow: model.Flow{Proto: "tcp", DPort: 443, SPort: 40000 + i, PPS: 40}, Label: 0},
			ml.Sample{Flow: model.Flow{Proto: "tcp", Flags: "syn", DPort: 443, SPort: 1000 + i, PPS: 200000}, Label: 1})
	}
	m, err := ml.Train(samples, 300, 0.2, 0.65)
	if err != nil {
		b.Fatalf("Train: %v", err)
	}
	return m
}

// Terminal at the first stage: the cheapest decision in the pipeline.
func BenchmarkDecideASICDrop(b *testing.B) {
	p := New(benchProgram())
	f := model.Flow{SrcIP: "198.51.100.9", DstIP: "203.0.113.10", Proto: "udp", DPort: 19132, PPS: 10}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if p.Decide(f).Action != model.ActionDrop {
			b.Fatal("expected a drop")
		}
	}
}

// Walks the ASIC list, then drops on the FPGA meter.
func BenchmarkDecideFPGAMeter(b *testing.B) {
	p := New(benchProgram())
	f := model.Flow{SrcIP: "192.0.2.9", DstIP: "203.0.113.10", Proto: "udp", DPort: 80, PPS: 60000}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if p.Decide(f).Action != model.ActionDrop {
			b.Fatal("expected a drop")
		}
	}
}

// Full depth with no model: ASIC, FPGA, then the ZC rate window.
func BenchmarkDecideZCInspect(b *testing.B) {
	p := New(benchProgram())
	f := model.Flow{SrcIP: "192.0.2.9", DstIP: "203.0.113.10", Proto: "tcp", DPort: 443, PPS: 1}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		p.Decide(f)
	}
}

// Full depth including the logistic score: the most expensive path.
func BenchmarkDecideZCWithML(b *testing.B) {
	p := New(benchProgram())
	p.SetModel(trainedModel(b))
	f := model.Flow{SrcIP: "192.0.2.9", DstIP: "203.0.113.10", Proto: "tcp", DPort: 443, SPort: 51000, PPS: 1}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		p.Decide(f)
	}
}

// Traffic for a prefix this node does not hold: the early-out.
func BenchmarkDecideNotOwned(b *testing.B) {
	p := New(benchProgram())
	f := model.Flow{SrcIP: "192.0.2.9", DstIP: "198.18.0.1", Proto: "tcp", DPort: 443, PPS: 1}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		p.Decide(f)
	}
}

// How the ASIC walk scales with rule count, worst case: nothing matches until
// the pipeline has examined every entry.
func BenchmarkDecideACLScaling(b *testing.B) {
	for _, n := range []int{1, 10, 100, 1000} {
		b.Run(fmt.Sprintf("rules=%d", n), func(b *testing.B) {
			prog := model.Program{Prefixes: []string{"203.0.113.0/24"}}
			for i := 0; i < n; i++ {
				src := netip.AddrFrom4([4]byte{10, byte(i >> 16), byte(i >> 8), byte(i)})
				prog.ASIC = append(prog.ASIC, model.ACLEntry{
					Priority: i, Action: model.ActionDrop, RuleID: fmt.Sprintf("r%d", i),
					Match: model.Match{SrcCIDR: src.String() + "/32"},
				})
			}
			p := New(prog)
			f := model.Flow{SrcIP: "192.0.2.9", DstIP: "203.0.113.10", Proto: "tcp", DPort: 443, PPS: 1}
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				p.Decide(f)
			}
		})
	}
}

// Each packet comes from a new source, so every decision inserts into the rate
// table. This is the shape of a spoofed flood.
func BenchmarkDecideDistinctSources(b *testing.B) {
	p := New(benchProgram())
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		src := netip.AddrFrom4([4]byte{10, byte(i >> 16), byte(i >> 8), byte(i)})
		p.Decide(model.Flow{SrcIP: src.String(), DstIP: "203.0.113.10", Proto: "tcp", DPort: 443, PPS: 1})
	}
}

// The adversarial case: the rate table is already full of live windows and every
// packet is a fresh source, so no insert can succeed. Reclamation is throttled
// to once per window specifically so this stays flat instead of paying for a
// full table scan per packet.
func BenchmarkDecideFloodAgainstFullTable(b *testing.B) {
	p := New(benchProgram())
	clock := time.Now()
	p.now = func() time.Time { return clock }
	for i := 0; i < maxBuckets; i++ {
		src := netip.AddrFrom4([4]byte{10, byte(i >> 16), byte(i >> 8), byte(i)})
		p.Decide(model.Flow{SrcIP: src.String(), DstIP: "203.0.113.10", Proto: "tcp", DPort: 443, PPS: 1})
	}
	if got := p.bucketCount(); got == 0 {
		b.Fatalf("expected a populated table, got %d", got)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		src := netip.AddrFrom4([4]byte{172, 16, byte(i >> 8), byte(i)})
		p.Decide(model.Flow{SrcIP: src.String(), DstIP: "203.0.113.10", Proto: "tcp", DPort: 443, PPS: 1})
	}
}

// unthrottledReclaim is what the first version of the bounded table did: scan
// the whole shard whenever it is full and an insert is attempted. Kept here
// only to quantify what the throttle buys.
func (sh *rateShard) unthrottledReclaim(now time.Time) bool {
	for key, bkt := range sh.buckets {
		if now.Sub(bkt.windowStart) >= rateWindow {
			delete(sh.buckets, key)
		}
	}
	return len(sh.buckets) < shardBuckets
}

func BenchmarkFloodAgainstFullTableUnthrottled(b *testing.B) {
	now := time.Now()
	sh := &rateShard{buckets: make(map[rateKey]*bucket, shardBuckets)}
	for i := 0; i < shardBuckets; i++ {
		key := rateKey{rule: "zc", src: netip.AddrFrom4([4]byte{10, byte(i >> 16), byte(i >> 8), byte(i)}).String()}
		sh.buckets[key] = &bucket{windowStart: now}
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sh.mu.Lock()
		sh.unthrottledReclaim(now)
		sh.mu.Unlock()
	}
}

// The program and model are read through an atomic snapshot and the rate table
// is sharded, so this measures whether the datapath scales across cores.
func BenchmarkDecideParallel(b *testing.B) {
	p := New(benchProgram())
	p.SetModel(trainedModel(b))
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			i++
			src := netip.AddrFrom4([4]byte{192, 0, 2, byte(i)})
			p.Decide(model.Flow{SrcIP: src.String(), DstIP: "203.0.113.10", Proto: "tcp", DPort: 443, SPort: 51000, PPS: 1})
		}
	})
}

// The node agent calls Load every poll round.
func BenchmarkLoad(b *testing.B) {
	prog := benchProgram()
	p := New(prog)
	for i := 0; i < 1000; i++ {
		src := netip.AddrFrom4([4]byte{10, byte(i >> 8), byte(i), 1})
		p.Decide(model.Flow{SrcIP: src.String(), DstIP: "203.0.113.10", Proto: "tcp", DPort: 443, PPS: 1})
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		p.Load(prog)
	}
}

// The control plane's /v1/decide builds a Pipeline per request, so New is on
// that request path and now pays for compiling the program.
func BenchmarkNewWithExamplePolicySizedProgram(b *testing.B) {
	prog := benchProgram()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		New(prog)
	}
}

func BenchmarkNewLargeProgram(b *testing.B) {
	prog := benchProgram()
	for i := 0; i < 100; i++ {
		src := netip.AddrFrom4([4]byte{10, byte(i >> 8), byte(i), 0})
		prog.ASIC = append(prog.ASIC, model.ACLEntry{
			Priority: i, Action: model.ActionDrop, RuleID: fmt.Sprintf("r%d", i),
			Match: model.Match{SrcCIDR: src.String() + "/24"},
		})
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		New(prog)
	}
}
