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
	"net/netip"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Jacksondude1223-bit/scrubline-cloud-scrub/internal/bgp"
	"github.com/Jacksondude1223-bit/scrubline-cloud-scrub/internal/metrics"
	"github.com/Jacksondude1223-bit/scrubline-cloud-scrub/internal/ml"
	"github.com/Jacksondude1223-bit/scrubline-cloud-scrub/internal/model"
	"github.com/Jacksondude1223-bit/scrubline-cloud-scrub/internal/pipeline"
	"github.com/Jacksondude1223-bit/scrubline-cloud-scrub/internal/telemetry"
	"github.com/Jacksondude1223-bit/scrubline-cloud-scrub/internal/transport"
	"github.com/Jacksondude1223-bit/scrubline-cloud-scrub/internal/tunnel"
)

const (
	pollInterval = 2 * time.Second
	// registerAttempts covers the control plane not being up yet, which is the
	// normal case under docker compose: depends_on waits for the container to
	// start, not for the API to listen.
	registerAttempts = 30
)

// client reaches the control plane. It is replaced at startup once the CA
// bundle is known; certificate verification is never turned off.
var client = &http.Client{Timeout: 5 * time.Second}

func main() {
	apiURL := flag.String("api", "http://127.0.0.1:8080", "control API base URL")
	name := flag.String("name", "scrub-a", "node name")
	region := flag.String("region", "iad", "node region")
	capacity := flag.Float64("capacity", 40, "scrub capacity in Gbps")
	capacityPPS := flag.Int64("capacity-pps", 0, "packet-rate ceiling; load-driven steering is off for this node without it")
	listen := flag.String("listen", "127.0.0.1:9091", "local decide/metrics address")
	advertise := flag.String("advertise", "", "address other components use to reach this node (default: -listen, or hostname:port when -listen is a wildcard)")
	localAS := flag.Int("local-as", 0, "AS this node's BGP speaker announces from; required for AS-path prepends")
	bgpNextHop := flag.String("bgp-next-hop", "", "next hop to advertise with, when it differs from the address peers reach this node on")
	tunnelSrc := flag.String("tunnel-src", "", "local address this node builds customer return tunnels from, and peers customer BGP sessions from; without it this node cannot carry a tunnelled prefix")
	certFile := flag.String("tls-cert", "", "TLS certificate for this agent's local API")
	keyFile := flag.String("tls-key", "", "TLS key for this agent's local API")
	caFile := flag.String("ca", "", "PEM bundle to verify the control plane against; empty uses the system roots")
	insecure := flag.Bool("insecure", false, "serve a routable local API without TLS; credentials then cross the network in the clear")
	flag.Parse()
	httpClient, err := transport.Client(transport.ClientConfig{CAFile: *caFile, Timeout: 5 * time.Second})
	if err != nil {
		log.Fatalf("configuring the control-plane client: %v", err)
	}
	client = httpClient

	// Three credentials, three blast radii. The enrollment token only buys a
	// registration; the credential the control plane hands back is scoped to
	// this node alone; the local token guards this agent's own read-only
	// endpoints. The agent never holds the operator credential.
	enrollToken := os.Getenv("SCRUBLINE_ENROLL_TOKEN")
	if enrollToken == "" {
		log.Fatal("SCRUBLINE_ENROLL_TOKEN is required to enroll with the control plane")
	}
	localToken := os.Getenv("SCRUBLINE_NODE_API_TOKEN")
	if localToken == "" {
		log.Fatal("SCRUBLINE_NODE_API_TOKEN is required to guard this agent's /decide, /metrics, and /bgp")
	}
	if *capacity < 0 {
		log.Fatalf("-capacity must not be negative, got %v", *capacity)
	}
	if *capacityPPS < 0 {
		log.Fatalf("-capacity-pps must not be negative, got %d", *capacityPPS)
	}
	if *capacityPPS == 0 {
		log.Printf("warning: no -capacity-pps given, so this node is never padded for load; set it to the packet rate this node can scrub")
	}
	if *localAS < 0 || *localAS > 4294967295 {
		log.Fatalf("-local-as %d is out of range", *localAS)
	}
	if *bgpNextHop != "" {
		if _, err := netip.ParseAddr(*bgpNextHop); err != nil {
			log.Fatalf("-bgp-next-hop %q is not an IP address: %v", *bgpNextHop, err)
		}
	}

	// Registering the listen address advertised "0.0.0.0:9091" to the control
	// plane, which no peer can dial.
	advertised, certain := advertiseAddr(*advertise, *listen)
	if !certain {
		log.Printf("warning: -listen %s is a wildcard; advertising %s. Set -advertise to the address peers should dial.", *listen, advertised)
	}

	if *tunnelSrc != "" {
		if _, err := netip.ParseAddr(*tunnelSrc); err != nil {
			log.Fatalf("-tunnel-src %q is not an IP address: %v", *tunnelSrc, err)
		}
	}

	desired := model.Node{
		Name: *name, Region: *region, CapacityGbps: *capacity, CapacityPPS: *capacityPPS, Advertise: advertised,
		TunnelSrc: *tunnelSrc,
		Backends:  []model.Stage{model.StageASIC, model.StageFPGA, model.StageZC},
	}

	var node model.Node
	var nodeToken string
	for attempt := 1; ; attempt++ {
		node, nodeToken, err = register(*apiURL, enrollToken, desired)
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
	log.Printf("registered %s as %s backends=asic,fpga,zc (credential scoped to this node)", node.Name, node.ID)

	// creds holds the node credential, which rotates on every re-enrollment.
	creds := &credentials{}
	creds.set(nodeToken)

	pipe := pipeline.New(model.Program{NodeID: node.ID})
	// The steering plan is held separately from the datapath: /bgp and
	// /metrics serve it, and the speaker beside this agent consumes it.
	var steering atomic.Pointer[steeringPlan]
	steering.Store(&steeringPlan{})
	// Where this node sends what it has scrubbed, and who it peers with.
	// Held beside the steering plan for the same reason: the agent compiles
	// and serves it, something else on the box makes it so.
	var delivery atomic.Pointer[deliveryPlan]
	delivery.Store(&deliveryPlan{})
	// What the local provisioner says about those tunnels. It rides the
	// heartbeat, because a return path that went down is a prefix being
	// black-holed until the control plane hears about it.
	health := &tunnelHealth{}
	go poll(*apiURL, enrollToken, creds, node, desired, pipe, &steering, &delivery, health, *localAS, *bgpNextHop)

	mux := http.NewServeMux()
	// /health stays open for liveness probes; it carries no policy detail.
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"node": node.ID, "name": node.Name, "datapath": "asic-tcam+fpga+pfring-zc"})
	})
	// /metrics carries rule IDs and traffic volumes, so it takes the same
	// bearer token as /decide. Point the scraper at it with that token.
	mux.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
		if !authorized(r, localToken) {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "missing or invalid bearer token"})
			return
		}
		if r.Method != http.MethodGet {
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "GET required"})
			return
		}
		var buf bytes.Buffer
		families := telemetry.Families([]telemetry.Report{report(node, pipe)}, time.Time{})
		families = append(families, telemetry.AnnouncementFamilies(steering.Load().Announcements)...)
		families = append(families, telemetry.ReputationFamilies([]telemetry.Report{report(node, pipe)})...)
		families = append(families, telemetry.EgressFamilies([]telemetry.Report{report(node, pipe)})...)
		families = append(families, telemetry.TunnelFamilies(node.ID, node.Name, node.Region,
			delivery.Load().Tunnels, health.get())...)
		if err := metrics.Write(&buf, families); err != nil {
			log.Printf("rendering metrics: %v", err)
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to render metrics"})
			return
		}
		w.Header().Set("Content-Type", metrics.ContentType)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(buf.Bytes())
	})
	// /bgp is where a BGP speaker picks up what this node should advertise.
	// Scrubline does not speak BGP itself: it compiles the plan and serves it,
	// the way it serves the TCAM, FPGA, and ZC programs.
	mux.HandleFunc("/bgp", func(w http.ResponseWriter, r *http.Request) {
		if !authorized(r, localToken) {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "missing or invalid bearer token"})
			return
		}
		if r.Method != http.MethodGet {
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "GET required"})
			return
		}
		plan := steering.Load()
		if r.URL.Query().Get("format") == "exabgp" {
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.WriteHeader(http.StatusOK)
			for _, line := range plan.Commands {
				_, _ = io.WriteString(w, line+"\n")
			}
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"node":          node.ID,
			"local_as":      *localAS,
			"announcements": plan.Announcements,
			"exabgp":        plan.Commands,
			"error":         plan.Err,
		})
	})
	// /tunnels is where whatever provisions interfaces on this box picks up
	// the return paths it should be holding open. Scrubline does not create
	// interfaces, the same way it does not speak BGP: it compiles the
	// intent and serves it, so what the fabric wants can be read and diffed
	// rather than inferred from the state of a machine.
	mux.HandleFunc("/tunnels", func(w http.ResponseWriter, r *http.Request) {
		if !authorized(r, localToken) {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "missing or invalid bearer token"})
			return
		}
		switch r.Method {
		case http.MethodGet:
			plan := delivery.Load()
			if r.URL.Query().Get("format") == "iproute2" {
				w.Header().Set("Content-Type", "text/plain; charset=utf-8")
				w.WriteHeader(http.StatusOK)
				for _, line := range plan.Commands {
					_, _ = io.WriteString(w, line+"\n")
				}
				return
			}
			writeJSON(w, http.StatusOK, map[string]any{
				"node":     node.ID,
				"tunnels":  plan.Tunnels,
				"iproute2": plan.Commands,
				"status":   health.get(),
				"error":    plan.TunnelErr,
			})
		case http.MethodPost:
			// The provisioner reports what it actually managed to build. A
			// tunnel reported down withdraws its prefixes from this node,
			// so this is the one write the agent accepts.
			var body struct {
				Tunnels []model.TunnelStatus `json:"tunnels"`
			}
			if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&body); err != nil {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
				return
			}
			for i, st := range body.Tunnels {
				if st.TunnelID == "" {
					writeJSON(w, http.StatusBadRequest, map[string]string{"error": fmt.Sprintf("tunnels[%d]: tunnel_id required", i)})
					return
				}
				if err := tunnel.ValidateStatus(st.State); err != nil {
					writeJSON(w, http.StatusBadRequest, map[string]string{"error": fmt.Sprintf("tunnels[%d] (%s): %v", i, st.TunnelID, err)})
					return
				}
			}
			health.set(body.Tunnels)
			writeJSON(w, http.StatusOK, map[string]any{"accepted": len(body.Tunnels)})
		default:
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "GET or POST required"})
		}
	})
	// /sessions is the customer peerings this node terminates, for the BGP
	// daemon that runs them.
	mux.HandleFunc("/sessions", func(w http.ResponseWriter, r *http.Request) {
		if !authorized(r, localToken) {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "missing or invalid bearer token"})
			return
		}
		if r.Method != http.MethodGet {
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "GET required"})
			return
		}
		plan := delivery.Load()
		if r.URL.Query().Get("format") == "bird" {
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.WriteHeader(http.StatusOK)
			for _, line := range plan.SessionConfig {
				_, _ = io.WriteString(w, line+"\n")
			}
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"node":     node.ID,
			"sessions": plan.Sessions,
			"bird":     plan.SessionConfig,
			"error":    plan.SessionErr,
		})
	})
	// /egress is where the datapath reports what the protected service sent
	// back to a client.
	//
	// It is a separate endpoint from /decide because a reply is not being
	// judged — nothing about it is permitted or dropped. It is the one
	// piece of evidence this fabric has that an attacker cannot write
	// himself: the origin chose to answer that address.
	mux.HandleFunc("/egress", func(w http.ResponseWriter, r *http.Request) {
		if !authorized(r, localToken) {
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
		pipe.ObserveReturn(f)
		writeJSON(w, http.StatusOK, map[string]any{"observed": true})
	})
	// /reputation is what the datapath remembers about sources, and the way
	// back out of the penalty box.
	//
	// The box exists so repeat offenders are shed cheaply, and a source
	// cannot promote itself out of one — which is only defensible if an
	// operator can. A false positive nobody can clear is a customer off the
	// air for the length of the penalty.
	mux.HandleFunc("/reputation", func(w http.ResponseWriter, r *http.Request) {
		if !authorized(r, localToken) {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "missing or invalid bearer token"})
			return
		}
		switch r.Method {
		case http.MethodGet:
			limit := 100
			if raw := r.URL.Query().Get("limit"); raw != "" {
				n, err := strconv.Atoi(raw)
				if err != nil || n <= 0 {
					writeJSON(w, http.StatusBadRequest, map[string]string{"error": "limit must be a positive number"})
					return
				}
				limit = n
			}
			stats, sources := pipe.Reputation(limit)
			writeJSON(w, http.StatusOK, map[string]any{
				"node": node.ID, "stats": stats, "sources": sources,
			})
		case http.MethodPost:
			var body struct {
				Release []string `json:"release"`
			}
			if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&body); err != nil {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
				return
			}
			if len(body.Release) == 0 {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": "release requires at least one source address"})
				return
			}
			writeJSON(w, http.StatusOK, map[string]any{"released": pipe.Release(body.Release)})
		default:
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "GET or POST required"})
		}
	})
	// /decide reveals what the policy does with a given flow, so it takes the
	// same bearer token as the control API.
	mux.HandleFunc("/decide", func(w http.ResponseWriter, r *http.Request) {
		if !authorized(r, localToken) {
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
	scheme := "http"
	if *certFile != "" {
		scheme = "https"
	}
	log.Printf("node dataplane listening on %s://%s", scheme, *listen)
	log.Fatal(transport.Serve(transport.Config{
		Addr: *listen, CertFile: *certFile, KeyFile: *keyFile, Insecure: *insecure,
	}, mux))
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

// steeringPlan is the BGP posture this node currently holds, together with
// its rendered form. Err is set when the plan could not be rendered, which is
// surfaced rather than swallowed: a plan that cannot be pushed means this node
// is advertising something other than what the control plane decided.
type steeringPlan struct {
	Announcements []model.Announcement `json:"announcements"`
	Commands      []string             `json:"exabgp"`
	Err           string               `json:"error,omitempty"`
}

// deliveryPlan is where this node sends what it has scrubbed, and who it
// peers with, together with their rendered forms. The errors are surfaced
// rather than swallowed for the same reason the steering plan's is: a return
// path that could not be rendered means this node may be attracting traffic
// it cannot deliver.
type deliveryPlan struct {
	Tunnels       []model.NodeTunnel `json:"tunnels"`
	Commands      []string           `json:"iproute2"`
	TunnelErr     string             `json:"tunnel_error,omitempty"`
	Sessions      []model.Session    `json:"sessions"`
	SessionConfig []string           `json:"bird"`
	SessionErr    string             `json:"session_error,omitempty"`
}

// renderDelivery turns the program's tunnels and sessions into the config the
// things beside this agent consume.
func renderDelivery(prog model.Program, node model.Node, localAS int) *deliveryPlan {
	plan := &deliveryPlan{Tunnels: prog.Tunnels, Sessions: prog.Sessions}
	commands, err := tunnel.Commands(prog.Tunnels)
	if err != nil {
		plan.TunnelErr = err.Error()
	} else {
		plan.Commands = commands
	}
	if len(prog.Sessions) > 0 {
		config, err := bgp.SessionConfig(prog.Sessions, node, localAS)
		if err != nil {
			plan.SessionErr = err.Error()
		} else {
			plan.SessionConfig = config
		}
	}
	return plan
}

// tunnelHealth is what the local provisioner last reported about this node's
// return paths. It is read on every heartbeat and written by whatever builds
// the tunnels, so it is guarded rather than swapped: the set is small and a
// partial report is worse than a slightly stale one.
type tunnelHealth struct {
	mu       sync.RWMutex
	reported []model.TunnelStatus
}

func (h *tunnelHealth) get() []model.TunnelStatus {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return append([]model.TunnelStatus(nil), h.reported...)
}

func (h *tunnelHealth) set(statuses []model.TunnelStatus) {
	cp := append([]model.TunnelStatus(nil), statuses...)
	sort.Slice(cp, func(i, j int) bool { return cp[i].TunnelID < cp[j].TunnelID })
	h.mu.Lock()
	h.reported = cp
	h.mu.Unlock()
}

// renderSteering turns the program's announcements into speaker commands,
// substituting the operator's next hop when one was given.
func renderSteering(prog model.Program, localAS int, nextHop string) *steeringPlan {
	rows := make([]model.Announcement, len(prog.Announcements))
	copy(rows, prog.Announcements)
	if nextHop != "" {
		for i := range rows {
			rows[i].NextHop = nextHop
		}
	}
	plan := &steeringPlan{Announcements: rows}
	commands, err := bgp.Commands(rows, localAS)
	if err != nil {
		plan.Err = err.Error()
		return plan
	}
	plan.Commands = commands
	return plan
}

// credentials holds the node credential the control plane issued. It is
// replaced wholesale on re-enrollment rather than mutated, so a poll in
// flight never reads a half-written token.
type credentials struct {
	mu    sync.RWMutex
	token string
}

func (c *credentials) get() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.token
}

func (c *credentials) set(token string) {
	c.mu.Lock()
	c.token = token
	c.mu.Unlock()
}

func poll(apiURL, enrollToken string, creds *credentials, node model.Node, desired model.Node, pipe *pipeline.Pipeline, steering *atomic.Pointer[steeringPlan], delivery *atomic.Pointer[deliveryPlan], health *tunnelHealth, localAS int, nextHop string) {
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
		if err := heartbeat(apiURL, creds.get(), id, pipe.Stats(), health.get()); err != nil {
			log.Printf("heartbeat: %v", err)
			// A control plane that restarted has no record of this node, and a
			// rotated or revoked credential is rejected rather than ignored.
			// Both are fixed by enrolling again.
			if errors.Is(err, errUnknownNode) || errors.Is(err, errUnauthenticated) {
				if _, token, err := register(apiURL, enrollToken, desired); err != nil {
					log.Printf("re-enrolling: %v", err)
				} else {
					creds.set(token)
					log.Printf("re-enrolled %s and rotated its credential", id)
				}
			}
		}

		var prog model.Program
		if err := get(apiURL+"/v1/nodes/"+id+"/program", creds.get(), &prog); err != nil {
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

			plan := renderSteering(prog, localAS, nextHop)
			steering.Store(plan)
			if plan.Err != "" {
				// Keep serving the datapath, but say loudly that this node's
				// advertisements are not what the control plane asked for.
				log.Printf("steering plan for %s could not be rendered: %s", id, plan.Err)
			} else {
				for _, line := range plan.Commands {
					log.Printf("bgp: %s", line)
				}
			}

			d := renderDelivery(prog, node, localAS)
			delivery.Store(d)
			if d.TunnelErr != "" {
				// The control plane withdraws a prefix whose return path is
				// down; it cannot know about one that would not even render.
				log.Printf("return tunnels for %s could not be rendered: %s", id, d.TunnelErr)
			}
			if d.SessionErr != "" {
				log.Printf("customer sessions for %s could not be rendered: %s", id, d.SessionErr)
			}
			if len(d.Tunnels) > 0 {
				log.Printf("return paths: %d tunnel(s) for %d customer session(s)", len(d.Tunnels), len(d.Sessions))
			}
		}

		var trained ml.Model
		if err := get(apiURL+"/v1/ml/model", creds.get(), &trained); err != nil {
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

		// Spread the cadence. A fixed two seconds is a schedule, and a
		// burst timed to land between two samples is measured as nothing;
		// a fleet polling in lockstep hands that schedule to an attacker
		// identically on every node.
		time.Sleep(transport.Jitter(pollInterval))
	}
}

var (
	errUnknownNode     = errors.New("control plane does not know this node")
	errNotFound        = errors.New("not found")
	errUnauthenticated = errors.New("control plane rejected this node's credential")
)

// register enrolls with the control plane and collects the credential it
// issues. The credential is returned once, here, and never served again.
func register(apiURL, enrollToken string, node model.Node) (model.Node, string, error) {
	raw, err := json.Marshal(node)
	if err != nil {
		return model.Node{}, "", err
	}
	var out struct {
		Node  model.Node `json:"node"`
		Token string     `json:"token"`
	}
	if err := send(http.MethodPost, apiURL+"/v1/nodes/register", enrollToken, raw, &out); err != nil {
		return model.Node{}, "", err
	}
	if out.Node.ID == "" {
		return model.Node{}, "", errors.New("the control plane returned no node id")
	}
	if out.Token == "" {
		return model.Node{}, "", errors.New("the control plane issued no credential")
	}
	return out.Node, out.Token, nil
}

func heartbeat(apiURL, token, id string, stats pipeline.Stats, tunnels []model.TunnelStatus) error {
	body, err := json.Marshal(struct {
		Stats   pipeline.Stats       `json:"stats"`
		Tunnels []model.TunnelStatus `json:"tunnels,omitempty"`
	}{Stats: stats, Tunnels: tunnels})
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
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return errUnauthenticated
	}
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
