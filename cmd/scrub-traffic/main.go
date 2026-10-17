// Command scrub-traffic drives synthetic flows through node agents so a demo
// environment has something to show.
//
// It is a demo tool, not part of the datapath. A fabric with no traffic
// reports zeros everywhere, which is indistinguishable from a fabric that is
// broken — so trying the analytics API against an idle stack teaches nothing.
// This posts flow records to each node's /decide, which runs them through the
// real pipeline; the counters that produces ride the heartbeat the agent
// already sends, and come out of the analytics API as a customer would see
// them.
//
// The mix is deliberate. Steady legitimate traffic gives the mitigated share
// something to be a share of; periodic floods open and close attack events;
// and a burst train exercises the pulse detector, whose whole point is that
// its mean stays under any watermark.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"math/rand"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/Jacksondude1223-bit/scrubline-cloud-scrub/internal/model"
	"github.com/Jacksondude1223-bit/scrubline-cloud-scrub/internal/transport"
)

func main() {
	nodes := flag.String("nodes", "http://127.0.0.1:9091", "comma-separated node agent base URLs")
	caFile := flag.String("ca", "", "PEM bundle to verify the agents against; empty uses the system roots")
	protected := flag.String("protected", "203.0.113.0/24", "prefix the legitimate traffic and the floods are aimed at")
	quiet := flag.String("quiet", "198.51.100.0/24", "a second protected prefix that only ever sees ordinary traffic, for contrast")
	gamePort := flag.Int("game-port", 19132, "UDP port the game filter guards on the protected prefix")
	rate := flag.Duration("interval", 200*time.Millisecond, "how often each node is sent a round of baseline flows")
	attackEvery := flag.Duration("attack-every", 4*time.Minute, "how often a flood starts")
	attackFor := flag.Duration("attack-for", 90*time.Second, "how long a flood lasts")
	burstEvery := flag.Duration("burst-every", 7*time.Minute, "how often a burst train starts")
	burstFor := flag.Duration("burst-for", 3*time.Minute, "how long a burst train lasts")
	seed := flag.Int64("seed", 0, "random seed; 0 picks one from the clock")
	flag.Parse()

	token := os.Getenv("SCRUBLINE_NODE_API_TOKEN")
	if token == "" {
		log.Fatal("SCRUBLINE_NODE_API_TOKEN is required: /decide on an agent takes that agent's local credential")
	}
	client, err := transport.Client(transport.ClientConfig{CAFile: *caFile, Timeout: 5 * time.Second})
	if err != nil {
		log.Fatalf("configuring the agent client: %v", err)
	}
	targets := strings.Split(*nodes, ",")
	for i := range targets {
		targets[i] = strings.TrimRight(strings.TrimSpace(targets[i]), "/")
	}
	if *seed == 0 {
		*seed = time.Now().UnixNano()
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	g := &generator{
		client:    client,
		token:     token,
		targets:   targets,
		protected: *protected,
		quiet:     *quiet,
		gamePort:  *gamePort,
	}
	log.Printf("scrub-traffic: %d node(s), baseline every %s, flood every %s for %s, burst train every %s for %s",
		len(targets), *rate, *attackEvery, *attackFor, *burstEvery, *burstFor)

	var wg sync.WaitGroup
	wg.Add(3)
	go func() { defer wg.Done(); g.baseline(ctx, *rate, *seed) }()
	go func() { defer wg.Done(); g.floods(ctx, *attackEvery, *attackFor, *seed+1) }()
	go func() { defer wg.Done(); g.bursts(ctx, *burstEvery, *burstFor, *seed+2) }()
	wg.Wait()
	log.Print("scrub-traffic: stopped")
}

type generator struct {
	client    *http.Client
	token     string
	targets   []string
	protected string
	quiet     string
	gamePort  int
}

// send posts one flow to one agent. Failures are logged at most occasionally
// and never fatal: an agent restarting mid-run should not take the generator
// with it.
func (g *generator) send(ctx context.Context, target string, f model.Flow) {
	body, err := json.Marshal(f)
	if err != nil {
		return
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target+"/decide", bytes.NewReader(body))
	if err != nil {
		return
	}
	req.Header.Set("Authorization", "Bearer "+g.token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := g.client.Do(req)
	if err != nil {
		return
	}
	resp.Body.Close()
}

// fanout sends the same shape of traffic to every node, which is what anycast
// does: a distributed attack lands on the whole fabric at once.
func (g *generator) fanout(ctx context.Context, build func(target string) []model.Flow) {
	for _, target := range g.targets {
		for _, f := range build(target) {
			g.send(ctx, target, f)
		}
	}
}

// hostIn picks a host address inside a /24, which is all the demo prefixes are.
func hostIn(prefix string, r *rand.Rand) string {
	base := strings.SplitN(prefix, "/", 2)[0]
	octets := strings.Split(base, ".")
	if len(octets) != 4 {
		return base
	}
	return fmt.Sprintf("%s.%s.%s.%d", octets[0], octets[1], octets[2], 1+r.Intn(254))
}

func source(r *rand.Rand) string {
	return fmt.Sprintf("%d.%d.%d.%d", 1+r.Intn(223), r.Intn(256), r.Intn(256), 1+r.Intn(254))
}

// baseline is the traffic a protected service carries when nobody is
// attacking it: players on the game port, web requests at the other customer.
func (g *generator) baseline(ctx context.Context, every time.Duration, seed int64) {
	r := rand.New(rand.NewSource(seed))
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			g.fanout(ctx, func(string) []model.Flow {
				return []model.Flow{
					{
						SrcIP: source(r), DstIP: hostIn(g.protected, r), Proto: "udp",
						SPort: 1024 + r.Intn(60000), DPort: g.gamePort,
						PPS: 40 + r.Intn(120),
						// A RakNet unconnected ping, so the game filter sees
						// something it recognises rather than junk.
						Payload: []byte{0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
					},
					{
						SrcIP: source(r), DstIP: hostIn(g.protected, r), Proto: "tcp",
						SPort: 1024 + r.Intn(60000), DPort: 443, Flags: "ack",
						PPS: 20 + r.Intn(80),
					},
					{
						SrcIP: source(r), DstIP: hostIn(g.quiet, r), Proto: "tcp",
						SPort: 1024 + r.Intn(60000), DPort: 443, Flags: "ack",
						PPS: 10 + r.Intn(50),
					},
				}
			})
		}
	}
}

// floods are the ordinary volumetric case: heavy, steady, and obvious. They
// run long enough to open an attack event and stop long enough to close it.
func (g *generator) floods(ctx context.Context, every, duration time.Duration, seed int64) {
	r := rand.New(rand.NewSource(seed))
	// Start the first one promptly: somebody bringing the stack up to look at
	// the analytics should not have to wait out a whole quiet interval.
	timer := time.NewTimer(20 * time.Second)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		}
		log.Printf("scrub-traffic: flood at %s for %s", g.protected, duration)
		deadline := time.Now().Add(duration)
		tick := time.NewTicker(250 * time.Millisecond)
		for time.Now().Before(deadline) {
			select {
			case <-ctx.Done():
				tick.Stop()
				return
			case <-tick.C:
			}
			g.fanout(ctx, func(string) []model.Flow {
				return []model.Flow{
					// Reflected DNS: the source port is what gives it away,
					// and the demo policy drops it in the TCAM.
					{
						SrcIP: source(r), DstIP: hostIn(g.protected, r), Proto: "udp",
						SPort: 53, DPort: 1024 + r.Intn(60000),
						PPS: 180_000 + r.Intn(120_000),
					},
					// Junk aimed at the game port, which is not the protocol
					// that port speaks.
					{
						SrcIP: source(r), DstIP: hostIn(g.protected, r), Proto: "udp",
						SPort: 1024 + r.Intn(60000), DPort: g.gamePort,
						PPS: 60_000 + r.Intn(40_000), Payload: []byte{0xff, 0xff, 0xff, 0xff},
					},
				}
			})
		}
		tick.Stop()
		log.Printf("scrub-traffic: flood over")
		timer.Reset(every)
	}
}

// bursts are the case a mean cannot see: short, very heavy, widely spaced. The
// detector is meant to latch on the shape and hold mitigation through the
// quiet stretches, so the gaps here are longer than any averaging window.
func (g *generator) bursts(ctx context.Context, every, duration time.Duration, seed int64) {
	r := rand.New(rand.NewSource(seed))
	timer := time.NewTimer(2 * time.Minute)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		}
		log.Printf("scrub-traffic: burst train at %s for %s", g.protected, duration)
		deadline := time.Now().Add(duration)
		for time.Now().Before(deadline) {
			// One short, very heavy burst.
			for i := 0; i < 4; i++ {
				g.fanout(ctx, func(string) []model.Flow {
					return []model.Flow{{
						SrcIP: source(r), DstIP: hostIn(g.protected, r), Proto: "udp",
						SPort: 1024 + r.Intn(60000), DPort: g.gamePort,
						PPS: 400_000 + r.Intn(200_000), Payload: []byte{0x00},
					}}
				})
				select {
				case <-ctx.Done():
					return
				case <-time.After(250 * time.Millisecond):
				}
			}
			// Then a long gap, which is the whole point.
			select {
			case <-ctx.Done():
				return
			case <-time.After(18 * time.Second):
			}
		}
		log.Printf("scrub-traffic: burst train over")
		timer.Reset(every)
	}
}
