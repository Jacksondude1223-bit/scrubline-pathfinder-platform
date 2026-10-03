// Command scrub-loadgen drives load at the control API and reports throughput
// and latency percentiles per endpoint. It counts a 200 with an empty body as an
// error, which is how an unencodable response presents to a client.
package main

import (
	"bytes"
	"flag"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type target struct {
	name   string
	method string
	url    string
	body   string
}

func main() {
	api := flag.String("api", "http://127.0.0.1:8080", "control API")
	token := flag.String("token", "", "bearer token")
	conns := flag.Int("c", 32, "concurrent connections")
	dur := flag.Duration("d", 5*time.Second, "duration per target")
	nodeID := flag.String("node", "", "node id for /v1/decide")
	only := flag.String("only", "", "run only targets whose name contains this")
	flag.Parse()

	flow := `{"src_ip":"192.0.2.9","dst_ip":"203.0.113.10","proto":"tcp","sport":51000,"dport":443,"pps":10}`
	targets := []target{
		{"GET /health", "GET", *api + "/health", ""},
		{"GET /v1/nodes", "GET", *api + "/v1/nodes", ""},
		{"GET /v1/fabric", "GET", *api + "/v1/fabric", ""},
		{"GET /v1/ml/model", "GET", *api + "/v1/ml/model", ""},
		{"POST /v1/ml/score", "POST", *api + "/v1/ml/score", flow},
		{"POST /v1/decide", "POST", *api + "/v1/decide",
			fmt.Sprintf(`{"node_id":%q,"flow":%s}`, *nodeID, flow)},
		{"POST /v1/nodes/{id}/heartbeat", "POST", *api + "/v1/nodes/" + *nodeID + "/heartbeat", ""},
	}

	fmt.Printf("%-30s %10s %10s %9s %9s %9s %9s %7s\n",
		"target", "req/s", "requests", "p50", "p90", "p99", "max", "errors")
	for _, t := range targets {
		if *only != "" && !strings.Contains(t.name, *only) {
			continue
		}
		run(t, *token, *conns, *dur)
	}
}

func run(t target, token string, conns int, dur time.Duration) {
	// One client per worker: a shared transport with enough idle conns keeps the
	// driver from becoming the bottleneck.
	tr := &http.Transport{MaxIdleConns: conns * 2, MaxIdleConnsPerHost: conns * 2}
	client := &http.Client{Transport: tr, Timeout: 10 * time.Second}

	var (
		wg       sync.WaitGroup
		mu       sync.Mutex
		lat      []time.Duration
		errs     atomic.Int64
		statuses sync.Map
	)
	deadline := time.Now().Add(dur)
	start := time.Now()
	for i := 0; i < conns; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			local := make([]time.Duration, 0, 4096)
			for time.Now().Before(deadline) {
				var rdr io.Reader
				if t.body != "" {
					rdr = bytes.NewReader([]byte(t.body))
				}
				req, err := http.NewRequest(t.method, t.url, rdr)
				if err != nil {
					errs.Add(1)
					continue
				}
				if token != "" {
					req.Header.Set("Authorization", "Bearer "+token)
				}
				if t.body != "" {
					req.Header.Set("Content-Type", "application/json")
				}
				t0 := time.Now()
				resp, err := client.Do(req)
				if err != nil {
					errs.Add(1)
					continue
				}
				n, _ := io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
				local = append(local, time.Since(t0))
				v, _ := statuses.LoadOrStore(resp.StatusCode, new(atomic.Int64))
				v.(*atomic.Int64).Add(1)
				// A 200 with an empty body is counted as an error: that is exactly
				// how the NaN-model bug presented, and it is invisible to a
				// status-code-only check.
				if resp.StatusCode == http.StatusOK && n == 0 {
					errs.Add(1)
				}
			}
			mu.Lock()
			lat = append(lat, local...)
			mu.Unlock()
		}()
	}
	wg.Wait()
	elapsed := time.Since(start)

	sort.Slice(lat, func(i, j int) bool { return lat[i] < lat[j] })
	if len(lat) == 0 {
		fmt.Printf("%-30s %10s %10d %9s %9s %9s %9s %7d\n", t.name, "-", 0, "-", "-", "-", "-", errs.Load())
		return
	}
	pct := func(p float64) time.Duration {
		i := int(float64(len(lat)-1) * p)
		return lat[i]
	}
	fmt.Printf("%-30s %10.0f %10d %9s %9s %9s %9s %7d",
		t.name, float64(len(lat))/elapsed.Seconds(), len(lat),
		pct(0.50).Round(time.Microsecond), pct(0.90).Round(time.Microsecond),
		pct(0.99).Round(time.Microsecond), lat[len(lat)-1].Round(time.Microsecond),
		errs.Load())
	var codes []string
	statuses.Range(func(k, v any) bool {
		codes = append(codes, fmt.Sprintf("%d:%d", k.(int), v.(*atomic.Int64).Load()))
		return true
	})
	sort.Strings(codes)
	fmt.Printf("  %v\n", codes)
}
