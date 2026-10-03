package store

import (
	"fmt"
	"testing"

	"github.com/Jacksondude1223-bit/scrubline-cloud-scrub/internal/ml"
	"github.com/Jacksondude1223-bit/scrubline-cloud-scrub/internal/model"
)

func seeded(nodes int) (*Store, []string) {
	s := New()
	ids := make([]string, 0, nodes)
	for i := 0; i < nodes; i++ {
		n := s.UpsertNode(model.Node{Name: fmt.Sprintf("scrub-%04d", i), Region: "iad", CapacityGbps: 40})
		ids = append(ids, n.ID)
	}
	return s, ids
}

// Every node agent calls this every two seconds.
func BenchmarkHeartbeat(b *testing.B) {
	s, ids := seeded(100)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		s.Heartbeat(ids[i%len(ids)])
	}
}

// Nodes copies and sorts the whole set on every call, which GET /v1/nodes does
// per request.
func BenchmarkNodes(b *testing.B) {
	for _, n := range []int{3, 100, 1000} {
		b.Run(fmt.Sprintf("nodes=%d", n), func(b *testing.B) {
			s, _ := seeded(n)
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				s.Nodes()
			}
		})
	}
}

func BenchmarkLiveNodes(b *testing.B) {
	s, _ := seeded(100)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		s.LiveNodes()
	}
}

// The node agent fetches its program every poll round.
func BenchmarkProgram(b *testing.B) {
	s, ids := seeded(100)
	progs := map[string]*model.Program{}
	for _, id := range ids {
		progs[id] = &model.Program{NodeID: id, PolicyID: "pol-1", Version: 1, Prefixes: []string{"203.0.113.0/24"}}
	}
	s.PutDeploy(nil, progs)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		s.Program(ids[i%len(ids)])
	}
}

func BenchmarkAddSamples(b *testing.B) {
	batch := make([]ml.Sample, 100)
	for i := range batch {
		batch[i] = ml.Sample{Flow: model.Flow{Proto: "tcp", PPS: 40, DPort: 443}, Label: 0}
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		s := New()
		if _, err := s.AddSamples(batch); err != nil {
			b.Fatal(err)
		}
	}
}

// Samples copies the whole set; Train takes that copy outside the lock.
func BenchmarkSamplesSnapshot(b *testing.B) {
	s := New()
	batch := make([]ml.Sample, 10000)
	for i := range batch {
		batch[i] = ml.Sample{Flow: model.Flow{Proto: "tcp", PPS: 40, DPort: 443}, Label: 0}
	}
	if _, err := s.AddSamples(batch); err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		s.Samples()
	}
}

// The train handler checks this before fitting. It used to read len() off a
// full copy of the sample set.
func BenchmarkSampleCount(b *testing.B) {
	s := New()
	batch := make([]ml.Sample, 10000)
	for i := range batch {
		batch[i] = ml.Sample{Flow: model.Flow{Proto: "tcp", PPS: 40, DPort: 443}, Label: 0}
	}
	if _, err := s.AddSamples(batch); err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		s.SampleCount()
	}
}

// Heartbeats contending against readers, which is the real control-plane mix.
func BenchmarkHeartbeatParallel(b *testing.B) {
	s, ids := seeded(100)
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			i++
			if i%8 == 0 {
				s.LiveNodes()
			} else {
				s.Heartbeat(ids[i%len(ids)])
			}
		}
	})
}

// The real control-plane mix is read-heavy: every agent polls its program and
// the model each round, and only heartbeats write.
func BenchmarkControlPlaneMixParallel(b *testing.B) {
	s, ids := seeded(100)
	progs := map[string]*model.Program{}
	for _, id := range ids {
		progs[id] = &model.Program{NodeID: id, PolicyID: "pol-1", Version: 1, Prefixes: []string{"203.0.113.0/24"}}
	}
	s.PutDeploy(nil, progs)
	s.SavePolicy(model.Policy{Name: "p", Protected: []string{"203.0.113.0/24"}})
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			i++
			switch i % 10 {
			case 0: // one write in ten
				s.Heartbeat(ids[i%len(ids)])
			case 1:
				s.LiveNodes()
			case 2:
				s.Policies()
			default:
				s.Program(ids[i%len(ids)])
				s.Model()
			}
		}
	})
}

func BenchmarkProgramParallel(b *testing.B) {
	s, ids := seeded(100)
	progs := map[string]*model.Program{}
	for _, id := range ids {
		progs[id] = &model.Program{NodeID: id, PolicyID: "pol-1", Version: 1, Prefixes: []string{"203.0.113.0/24"}}
	}
	s.PutDeploy(nil, progs)
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			i++
			s.Program(ids[i%len(ids)])
		}
	})
}

// A long read (copy plus sort of 1000 nodes) is where overlapping readers could
// actually pay for the read-lock bookkeeping, unlike Program() which is a map
// hit measured in tens of nanoseconds.
func BenchmarkNodesParallelLongRead(b *testing.B) {
	s, _ := seeded(1000)
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			s.Nodes()
		}
	})
}

func BenchmarkSamplesParallelLongRead(b *testing.B) {
	s := New()
	batch := make([]ml.Sample, 10000)
	for i := range batch {
		batch[i] = ml.Sample{Flow: model.Flow{Proto: "tcp", PPS: 40, DPort: 443}, Label: 0}
	}
	if _, err := s.AddSamples(batch); err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			s.Samples()
		}
	})
}
