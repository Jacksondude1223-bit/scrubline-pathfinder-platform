package main

import (
	"bytes"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/Jacksondude1223-bit/scrubline-cloud-scrub/internal/metrics"
	"github.com/Jacksondude1223-bit/scrubline-cloud-scrub/internal/ml"
	"github.com/Jacksondude1223-bit/scrubline-cloud-scrub/internal/model"
	"github.com/Jacksondude1223-bit/scrubline-cloud-scrub/internal/pipeline"
	"github.com/Jacksondude1223-bit/scrubline-cloud-scrub/internal/telemetry"
)

const (
	pollInterval = 2 * time.Second
	// registerAttempts covers the control plane not being up yet, which is the
	// normal case under docker compose: depends_on waits for the container to
	// start, not for the API to listen.
	registerAttempts = 30
)

var client = &http.Client{Timeout: 5 * time.Second}

func main() {
	apiURL := flag.String("api", "http://127.0.0.1:8080", "control API base URL")
	name := flag.String("name", "scrub-a", "node name")
	region := flag.String("region", "iad", "node region")
	capacity := flag.Float64("capacity", 40, "scrub capacity in Gbps")
	listen := flag.String("listen", "127.0.0.1:9091", "local decide/metrics address")
	advertise := flag.String("advertise", "", "address other components use to reach this node (default: -listen, or hostname:port when -listen is a wildcard)")
	flag.Parse()
	token := os.Getenv("SCRUBLINE_API_TOKEN")
	if token == "" {
		log.Fatal("SCRUBLINE_API_TOKEN is required")
	}
	if *capacity < 0 {
		log.Fatalf("-capacity must not be negative, got %v", *capacity)
	}

	// Registering the listen address advertised "0.0.0.0:9091" to the control
	// plane, which no peer can dial.
	advertised, certain := advertiseAddr(*advertise, *listen)
	if !certain {
		log.Printf("warning: -listen %s is a wildcard; advertising %s. Set -advertise to the address peers should dial.", *listen, advertised)
	}

	desired := model.Node{
		Name: *name, Region: *region, CapacityGbps: *capacity, Advertise: advertised,
		Backends: []model.Stage{model.StageASIC, model.StageFPGA, model.StageZC},
	}

	var node model.Node
	var err error
	for attempt := 1; ; attempt++ {
		node, err = register(*apiURL, token, desired)
		if err == nil {
			break
		}
		if attempt >= registerAttempts {
			log.Fatalf("registering with %s failed after %d attempts: %v", *apiURL, attempt, err)
		}
		backoff := time.Duration(attempt) * 500 * time.Millisecond
		if backoff > 5*time.Second {
			backoff = 5 * time.Second
		}
		log.Printf("registering with %s failed (attempt %d/%d): %v; retrying in %s", *apiURL, attempt, registerAttempts, err, backoff)
		time.Sleep(backoff)
	}
	log.Printf("registered %s as %s backends=asic,fpga,zc", node.Name, node.ID)

	pipe := pipeline.New(model.Program{NodeID: node.ID})
	go poll(*apiURL, token, node, desired, pipe)

	mux := http.NewServeMux()
	// /health stays open for liveness probes; it carries no policy detail.
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"node": node.ID, "name": node.Name, "datapath": "asic-tcam+fpga+pfring-zc"})
	})
	// /metrics carries rule IDs and traffic volumes, so it takes the same
	// bearer token as /decide. Point the scraper at it with that token.
	mux.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
		if !authorized(r, token) {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "missing or invalid bearer token"})
			return
		}
		if r.Method != http.MethodGet {
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "GET required"})
			return
		}
		var buf bytes.Buffer
		if err := metrics.Write(&buf, telemetry.Families([]telemetry.Report{report(node, pipe)}, time.Time{})); err != nil {
			log.Printf("rendering metrics: %v", err)
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to render metrics"})
			return
		}
		w.Header().Set("Content-Type", metrics.ContentType)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(buf.Bytes())
	})
	// /decide reveals what the policy does with a given flow, so it takes the
	// same bearer token as the control API.
	mux.HandleFunc("/decide", func(w http.ResponseWriter, r *http.Request) {
		if !authorized(r, token) {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "missing or invalid bearer token"})
			return
		}
		if r.Method != http.MethodPost {
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "POST required"})
			return
		}
		var f model.Flow
		if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&f); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		if err := ml.ValidateFlow(f); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		d := pipe.Decide(f)
		d.NodeID = node.ID
		writeJSON(w, http.StatusOK, d)
	})
	log.Printf("node dataplane listening on %s", *listen)
	log.Fatal(http.ListenAndServe(*listen, mux))
}

// advertiseAddr picks the address the control plane should record for this
// node. It reports false when it had to guess, so the operator can be told.
func advertiseAddr(explicit, listen string) (string, bool) {
	if explicit != "" {
		return explicit, true
	}
	host, port, err := net.SplitHostPort(listen)
	if err != nil {
		return listen, false
	}
	switch host {
	case "", "0.0.0.0", "::", "[::]":
		if h, hostErr := os.Hostname(); hostErr == nil && h != "" {
			return net.JoinHostPort(h, port), false
		}
		return listen, false
	}
	return listen, true
}

// report snapshots this node's datapath counters for the control plane and
// for its own /metrics.
func report(node model.Node, pipe *pipeline.Pipeline) telemetry.Report {
	return telemetry.Report{
		NodeID: node.ID, Name: node.Name, Region: node.Region,
		Stats: pipe.Stats(), ReportedAt: time.Now().UTC(),
	}
}

func poll(apiURL, token string, node model.Node, desired model.Node, pipe *pipeline.Pipeline) {
	id := node.ID
	var lastPolicy string
	var lastVersion int
	var lastCompiled time.Time
	var modelCleared bool
	for {
		// A control plane that restarted has no record of this node, so its
		// heartbeat 404s. Re-register instead of polling a program forever.
		// The heartbeat carries this node's counters. It is the one call the
		// agent already makes every poll, so the control plane gets a fleet
		// view without a second round trip.
		if err := heartbeat(apiURL, token, id, pipe.Stats()); err != nil {
			log.Printf("heartbeat: %v", err)
			if errors.Is(err, errUnknownNode) {
				if _, err := register(apiURL, token, desired); err != nil {
					log.Printf("re-registering: %v", err)
				} else {
					log.Printf("re-registered %s after the control plane lost it", id)
				}
			}
		}

		var prog model.Program
		if err := get(apiURL+"/v1/nodes/"+id+"/program", token, &prog); err != nil {
			if !errors.Is(err, errNotFound) {
				log.Printf("fetching program: %v", err)
			}
		} else if prog.PolicyID != lastPolicy || prog.Version != lastVersion || !prog.CompiledAt.Equal(lastCompiled) {
			// Only reload on a real change. Loading every poll took the
			// datapath lock and walked the whole rate table twice a second.
			pipe.Load(prog)
			lastPolicy, lastVersion, lastCompiled = prog.PolicyID, prog.Version, prog.CompiledAt
			log.Printf("programmed node %s policy=%s version=%d asic=%d fpga=%d zc=%d prefixes=%v",
				id, prog.PolicyID, prog.Version, len(prog.ASIC), len(prog.FPGA), len(prog.ZC), prog.Prefixes)
		}

		var trained ml.Model
		if err := get(apiURL+"/v1/ml/model", token, &trained); err != nil {
			log.Printf("fetching model: %v", err)
		} else if trained.Ready {
			pipe.SetModel(trained)
			modelCleared = false
		} else if trained.Withdrawn && !modelCleared {
			// An explicit withdrawal is the only way to retire a bad model
			// without restarting the fleet.
			pipe.SetModel(ml.Model{})
			modelCleared = true
			log.Printf("control plane withdrew the ZC model; classifier disabled on %s", id)
		}

		time.Sleep(pollInterval)
	}
}

var (
	errUnknownNode = errors.New("control plane does not know this node")
	errNotFound    = errors.New("not found")
)

func register(apiURL, token string, node model.Node) (model.Node, error) {
	raw, err := json.Marshal(node)
	if err != nil {
		return model.Node{}, err
	}
	var out model.Node
	if err := send(http.MethodPost, apiURL+"/v1/nodes/register", token, raw, &out); err != nil {
		return model.Node{}, err
	}
	return out, nil
}

func heartbeat(apiURL, token, id string, stats pipeline.Stats) error {
	body, err := json.Marshal(struct {
		Stats pipeline.Stats `json:"stats"`
	}{Stats: stats})
	if err != nil {
		return err
	}
	err = send(http.MethodPost, apiURL+"/v1/nodes/"+id+"/heartbeat", token, body, nil)
	if errors.Is(err, errNotFound) {
		return errUnknownNode
	}
	return err
}

func get(url, token string, out any) error {
	return send(http.MethodGet, url, token, nil, out)
}

// send performs one request and always drains and closes the response body.
// Leaving the body open leaked a connection on every poll round.
func send(method, url, token string, body []byte, out any) error {
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	req, err := http.NewRequest(method, url, reader)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer func() {
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}()
	if resp.StatusCode == http.StatusNotFound {
		return errNotFound
	}
	if resp.StatusCode >= 300 {
		snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("%s %s: %s: %s", method, url, resp.Status, strings.TrimSpace(string(snippet)))
	}
	if out == nil {
		return nil
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 8<<20)).Decode(out)
}

func authorized(r *http.Request, token string) bool {
	scheme, got, found := strings.Cut(r.Header.Get("Authorization"), " ")
	if !found || !strings.EqualFold(scheme, "Bearer") {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(got), []byte(token)) == 1
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(v); err != nil {
		log.Printf("node: encoding %T response failed: %v", v, err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error":"failed to encode response"}` + "\n"))
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_, _ = w.Write(buf.Bytes())
}
