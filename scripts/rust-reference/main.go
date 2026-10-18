// Emits compatibility fixtures from the Go implementation during the Rust migration.
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/Jacksondude1223-bit/scrubline-cloud-scrub/internal/bgp"
	"github.com/Jacksondude1223-bit/scrubline-cloud-scrub/internal/compiler"
	"github.com/Jacksondude1223-bit/scrubline-cloud-scrub/internal/metrics"
	"github.com/Jacksondude1223-bit/scrubline-cloud-scrub/internal/ml"
	"github.com/Jacksondude1223-bit/scrubline-cloud-scrub/internal/model"
	"github.com/Jacksondude1223-bit/scrubline-cloud-scrub/internal/steering"
	"github.com/Jacksondude1223-bit/scrubline-cloud-scrub/internal/tunnel"
)

func main() {
	var policy model.Policy
	must(json.Unmarshal(read("configs/policy.demo.json"), &policy))
	policy.ID = "pol-reference"
	policy.Version = 7
	policy.ChallengeSecret = "reference-secret"
	policy.Steering = []model.Steering{{Prefix: policy.Protected[0], Regions: []string{"US", "de"}, Communities: []string{"64512:100", "64512:1:2"}}}
	policy.Sessions = []model.Session{{ID: "cust-test", PeerIP: "192.0.2.9", PeerAS: 64513, Prefixes: []string{policy.Protected[0]}, Password: "safeMD5", Comment: "Test \"description\";\n", Nodes: []string{"node-a"}}}
	nodes := []model.Node{
		{ID: "node-a", Name: "alpha", Region: "us", CapacityGbps: 100, Status: model.NodeReady, TunnelSrc: "192.0.2.1", Advertise: "192.0.2.1:9091"},
		{ID: "node-b", Name: "beta", Region: "de", CapacityGbps: 25, Status: model.NodeReady, TunnelSrc: "192.0.2.2", Backends: []model.Stage{model.StageFPGA, model.StageZC}},
		{ID: "node-c", Name: "gamma", Region: "sg", CapacityGbps: 0, Status: model.NodeReady, Backends: []model.Stage{model.StageASIC}},
	}
	type testCase struct {
		Policy   model.Policy              `json:"policy"`
		Nodes    []model.Node              `json:"nodes"`
		Shedding map[string]int            `json:"shedding"`
		Health   compiler.TunnelHealth     `json:"health"`
		Plan     []model.Announcement      `json:"plan"`
		Programs map[string]*model.Program `json:"programs"`
		Commands []string                  `json:"commands"`
		Tunnels  map[string][]string       `json:"tunnels"`
		Sessions map[string][]string       `json:"sessions"`
	}
	cases := []testCase{}
	for i := 0; i < 24; i++ {
		p := policy
		ns := append([]model.Node(nil), nodes...)
		if i%2 == 1 {
			ns[1].Status = model.NodeStale
		}
		if i%3 == 1 {
			ns[0].TunnelSrc = ""
		}
		if i%4 == 1 {
			ns[0].CapacityGbps = -1
		}
		if i%4 == 2 {
			ns[0].CapacityGbps = 200
		}
		if i%6 == 0 {
			p.Steering = nil
		}
		if i%6 == 2 {
			p.Tunnels = nil
		}
		if i%6 == 3 {
			p.Games = nil
		}
		health := compiler.TunnelHealth{}
		for _, n := range ns {
			health[n.ID] = map[string]string{}
			for _, t := range p.Tunnels {
				health[n.ID][t.ID] = []string{model.TunnelUp, model.TunnelDown, model.TunnelUnknown}[i%3]
			}
		}
		shedding := map[string]int{"node-a": i%5 - 1, "node-b": i % 3}
		plan := compiler.Plan(p, ns, shedding, health)
		programs := compiler.Compile(p, ns, plan)
		commands, err := bgp.Commands(plan, 64512)
		must(err)
		tcommands := map[string][]string{}
		sessions := map[string][]string{}
		for _, n := range ns {
			prog := programs[n.ID]
			prog.CompiledAt = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
			tc, err := tunnel.Commands(prog.Tunnels)
			must(err)
			tcommands[n.ID] = tc
			if n.TunnelSrc != "" {
				sc, err := bgp.SessionConfig(prog.Sessions, n, 64512)
				must(err)
				sessions[n.ID] = sc
			}
		}
		cases = append(cases, testCase{p, ns, shedding, health, plan, programs, commands, tcommands, sessions})
	}
	var batch struct {
		Samples []ml.Sample `json:"samples"`
	}
	must(json.Unmarshal(read("configs/ml.samples.json"), &batch))
	samples := batch.Samples
	m, err := ml.Train(samples, 300, 0.2, 0.65)
	must(err)
	flows := []model.Flow{{Proto: "TCP", Flags: "SyN", PPS: 10000, DPort: 443, SPort: 12345}, {Proto: "udp", PPS: 12, DPort: 19132, SPort: 1024, Payload: []byte{0, 1, 2, 255}}, {Proto: "icmp", PPS: -5, DPort: -1, SPort: 90000}, {PPS: 1 << 40}}
	features := [][]float64{}
	scores := []float64{}
	for _, f := range flows {
		features = append(features, ml.Features(f))
		scores = append(scores, ml.Score(m, f))
	}
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	controller := steering.New()
	controller.SetClock(func() time.Time { return now })
	type round struct {
		At       time.Time                 `json:"at"`
		Offered  uint64                    `json:"offered"`
		Peak     uint64                    `json:"peak"`
		Pulsing  bool                      `json:"pulsing"`
		Fresh    bool                      `json:"fresh"`
		Capacity int64                     `json:"capacity"`
		Levels   map[string]steering.Level `json:"levels"`
	}
	rounds := []round{}
	for i, pps := range []uint64{900, 900, 900, 100, 100, 100, 100, 900, 100} {
		now = now.Add(10 * time.Second)
		pulsing := i == 3 || i == 4
		fresh := i != 6
		controller.Observe([]steering.Sample{{NodeID: "n", OfferedPPS: pps, PeakPPS: 1200, Pulsing: pulsing, CapacityPPS: 1000, Fresh: fresh}})
		rounds = append(rounds, round{now, pps, 1200, pulsing, fresh, 1000, controller.Levels()})
	}
	families := []metrics.Family{{Name: "scrub_count", Help: "line\\quote\nnext", Type: metrics.Counter, Samples: []metrics.Sample{{Labels: []metrics.Label{{Name: "node", Value: "z\"\\\nx"}}, Value: 42}, {Labels: []metrics.Label{{Name: "node", Value: "a"}}, Value: 3}}}}
	var metricBuf stringWriter
	must(metrics.Write(&metricBuf, families))
	data := map[string]any{"cases": cases, "samples": samples, "model": m, "flows": flows, "features": features, "scores": scores, "rounds": rounds, "metrics": string(metricBuf)}
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	must(encoder.Encode(data))
}

type stringWriter string

func (s *stringWriter) Write(b []byte) (int, error) { *s += stringWriter(b); return len(b), nil }
func must(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
func read(path string) []byte { b, e := os.ReadFile(path); must(e); return b }
