package api

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math"
	"net/http"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Jacksondude1223-bit/scrubline-cloud-scrub/internal/bgp"
	"github.com/Jacksondude1223-bit/scrubline-cloud-scrub/internal/compiler"
	"github.com/Jacksondude1223-bit/scrubline-cloud-scrub/internal/gamefilter"
	"github.com/Jacksondude1223-bit/scrubline-cloud-scrub/internal/metrics"
	"github.com/Jacksondude1223-bit/scrubline-cloud-scrub/internal/ml"
	"github.com/Jacksondude1223-bit/scrubline-cloud-scrub/internal/model"
	"github.com/Jacksondude1223-bit/scrubline-cloud-scrub/internal/pipeline"
	"github.com/Jacksondude1223-bit/scrubline-cloud-scrub/internal/steering"
	"github.com/Jacksondude1223-bit/scrubline-cloud-scrub/internal/store"
	"github.com/Jacksondude1223-bit/scrubline-cloud-scrub/internal/telemetry"
)

// maxBody bounds every request body. Policies and sample batches are the large
// ones; everything else is a handful of fields.
const maxBody = 4 << 20

// ReconcileInterval is how often the fabric is checked against the live node
// set. A node that joins or recovers between deploys would otherwise hold no
// program, and a node that dies would keep its prefixes assigned to it.
const ReconcileInterval = 5 * time.Second

// requestKey is one bucket of the API request counter. Route names come from
// the dispatch switch rather than the raw path, so the label set stays bounded.
type requestKey struct {
	route  string
	status int
}

// Role is what a caller is allowed to do.
type Role string

const (
	// RoleOperator is full control-plane access: policy, deploy, ML, fabric.
	RoleOperator Role = "operator"
	// RoleEnroll may only register a node and collect its credential.
	RoleEnroll Role = "enroll"
	// RoleNode is one scrubber acting for itself: its own heartbeat, its own
	// program, and the published model. Nothing else, and nothing belonging
	// to another node.
	RoleNode Role = "node"
)

// principal is the authenticated caller behind a request.
type principal struct {
	role Role
	// nodeID is set for RoleNode and names the one node this caller may act
	// for.
	nodeID string
}

// Mode is whether this control plane owns the fabric or follows one.
type Mode string

const (
	// ModePrimary owns the fabric: it accepts writes and compiles the plan.
	ModePrimary Mode = "primary"
	// ModeReplica follows a primary. It holds a current copy of the durable
	// state so it can take over without losing anything, and refuses writes
	// so two control planes can never compile conflicting plans.
	ModeReplica Mode = "replica"
)

type Server struct {
	// Token is the operator credential: full control-plane access.
	Token string
	// EnrollToken lets a node register and collect its own credential. It is
	// the fleet's bootstrap secret and nothing more: on its own it cannot
	// read a program, change a policy, or move an announcement.
	EnrollToken string
	Store       *store.Store

	// modeMu guards mode, which a promotion changes at runtime.
	modeMu sync.RWMutex
	mode   Mode

	// requestsMu guards the API request counters.
	requestsMu sync.Mutex
	requests   map[requestKey]uint64
	// recompiles counts fabric recompiles, so an operator can see the control
	// plane reacting to membership churn.
	recompiles atomic.Uint64

	// steeringOnce guards lazy creation of the load controller, so a Server
	// built as a plain struct literal still gets one.
	steeringOnce sync.Once
	steering     *steering.Controller

	// clockMu guards now, which tests replace to age reports without sleeping.
	clockMu sync.RWMutex
	now     func() time.Time

	// reconcileMu serialises recompiles so two membership changes cannot
	// compile competing fabrics.
	reconcileMu sync.Mutex
	// lastLive is the live-node fingerprint the current fabric was compiled
	// from. Guarded by reconcileMu.
	lastLive string

	// mu guards the per-node pipeline cache used by /v1/decide.
	mu    sync.Mutex
	pipes map[string]*pipeline.Pipeline
}

// StartReconciler recompiles the fabric whenever the live node set changes.
// It returns when ctx is done.
func (s *Server) StartReconciler(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = ReconcileInterval
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.reconcile()
		}
	}
}

// Mode reports whether this control plane is the primary or a replica. The
// zero value is primary, so a Server built as a plain struct literal behaves
// as it always has.
func (s *Server) Mode() Mode {
	s.modeMu.RLock()
	defer s.modeMu.RUnlock()
	if s.mode == "" {
		return ModePrimary
	}
	return s.mode
}

// SetMode sets the role. Promotion is deliberate: see Promote.
func (s *Server) SetMode(m Mode) {
	s.modeMu.Lock()
	s.mode = m
	s.modeMu.Unlock()
}

// Promote turns a replica into the primary. It is an operator action and it
// does not check whether the old primary is gone, because nothing reachable
// from here can tell a dead primary from an unreachable one. Promoting while
// the old primary still lives gives two control planes compiling conflicting
// announcement plans, so the old one has to be fenced first.
func (s *Server) Promote() bool {
	s.modeMu.Lock()
	defer s.modeMu.Unlock()
	if s.mode != ModeReplica {
		return false
	}
	s.mode = ModePrimary
	return true
}

// writesAllowed reports whether this control plane may change state, and
// writes the refusal if it may not.
func (s *Server) writesAllowed(w http.ResponseWriter) bool {
	if s.Mode() != ModeReplica {
		return true
	}
	writeJSON(w, http.StatusConflict, map[string]string{
		"error": "this control plane is a replica and does not accept writes; send them to the primary",
		"mode":  string(ModeReplica),
	})
	return false
}

// SetClock replaces the server's time source. Report freshness and report age
// are measured against it, so a test can age the fleet without sleeping.
func (s *Server) SetClock(now func() time.Time) {
	s.clockMu.Lock()
	s.now = now
	s.clockMu.Unlock()
	s.Steering().SetClock(now)
}

func (s *Server) clock() time.Time {
	s.clockMu.RLock()
	defer s.clockMu.RUnlock()
	if s.now == nil {
		return time.Now().UTC()
	}
	return s.now()
}

// Steering returns the load controller, creating it on first use.
func (s *Server) Steering() *steering.Controller {
	s.steeringOnce.Do(func() {
		if s.steering == nil {
			s.steering = steering.New()
		}
	})
	return s.steering
}

// observeLoad folds the fleet's latest counters into the steering controller
// and returns the extra padding each node should carry. A node whose counters
// are missing or stale is marked unfresh, which holds its level where it is.
func (s *Server) observeLoad(nodes []model.Node) map[string]int {
	reports := map[string]telemetry.Report{}
	for _, r := range s.Store.Reports() {
		reports[r.NodeID] = r
	}
	now := s.clock()
	samples := make([]steering.Sample, 0, len(nodes))
	for _, n := range nodes {
		sample := steering.Sample{NodeID: n.ID, CapacityPPS: n.CapacityPPS}
		if r, ok := reports[n.ID]; ok {
			sample.OfferedPPS = r.Stats.OfferedPPS
			sample.Fresh = !r.ReportedAt.IsZero() && now.Sub(r.ReportedAt) <= steering.ReportFreshness
		}
		samples = append(samples, sample)
	}
	return s.Steering().Observe(samples)
}

// reconcile recompiles the last deployed policy when the live node set, or
// the load-driven padding, has moved on from what the current fabric was
// built for.
func (s *Server) reconcile() {
	s.reconcileMu.Lock()
	defer s.reconcileMu.Unlock()

	policyID := s.Store.LastDeployedPolicy()
	if policyID == "" {
		return
	}
	live := s.Store.LiveNodes()
	shedding := s.observeLoad(s.Store.Nodes())
	if fabricKey(live, shedding) == s.lastLive {
		return
	}
	if len(live) == 0 {
		// Every node is stale. Recompiling would blank the fabric; leaving the
		// last programs in place keeps whatever is still enforcing them.
		log.Printf("api: no live nodes, keeping the fabric compiled for policy %s", policyID)
		return
	}
	policy, ok := s.Store.Policy(policyID)
	if !ok {
		return
	}
	plan, programs, err := s.applyDeploy(policy, s.Store.Nodes(), live, shedding)
	if err != nil {
		log.Printf("api: recompiling policy %s failed: %v", policy.ID, err)
		return
	}
	log.Printf("api: fabric changed, recompiled policy %s v%d across %d nodes (%d announcements)",
		policy.ID, policy.Version, len(programs), len(plan))
}

// applyDeploy compiles and stores the fabric for a policy. Callers hold
// reconcileMu.
//
// The plan covers every registered node, not only the live ones: the fabric is
// anycast, so a node that stopped answering needs an explicit withdrawal
// rather than to be left out, and a node that comes back finds its program
// already compiled. live is the set membership is tracked against.
func (s *Server) applyDeploy(policy model.Policy, all, live []model.Node, shedding map[string]int) ([]model.Announcement, map[string]*model.Program, error) {
	plan := compiler.Plan(policy, all, shedding)
	programs := compiler.Compile(policy, all, plan)
	if err := s.Store.PutDeploy(policy.ID, plan, programs); err != nil {
		return nil, nil, err
	}
	s.lastLive = fabricKey(live, shedding)
	s.prunePipelines(programs)
	s.recompiles.Add(1)
	return plan, programs, nil
}

// fabricKey identifies everything a recompile depends on: which nodes are
// live, and how hard each is being padded for load. A recompile only runs
// when one of those actually changed.
func fabricKey(live []model.Node, shedding map[string]int) string {
	ids := make([]string, 0, len(live))
	for _, n := range live {
		ids = append(ids, n.ID)
	}
	sort.Strings(ids)

	padded := make([]string, 0, len(shedding))
	for id, p := range shedding {
		if p != 0 {
			padded = append(padded, fmt.Sprintf("%s=%d", id, p))
		}
	}
	sort.Strings(padded)
	return strings.Join(ids, ",") + "|" + strings.Join(padded, ",")
}

// pipelineFor returns the cached pipeline for a node, reloading it when the
// deployed program has moved on. Building a fresh pipeline per request threw
// away the ZC rate-limit state, so the behavioral cap could never accumulate
// and /v1/decide disagreed with the node agent for the same policy.
func (s *Server) pipelineFor(nodeID string, prog model.Program) *pipeline.Pipeline {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.pipes == nil {
		s.pipes = map[string]*pipeline.Pipeline{}
	}
	pipe, ok := s.pipes[nodeID]
	if !ok {
		pipe = pipeline.New(prog)
		s.pipes[nodeID] = pipe
	} else if id, version, compiled := pipe.Program(); id != prog.PolicyID || version != prog.Version || !compiled.Equal(prog.CompiledAt) {
		pipe.Load(prog)
	}
	return pipe
}

// prunePipelines drops cached pipelines for nodes the fabric no longer covers,
// so the cache cannot outgrow the node set.
func (s *Server) prunePipelines(programs map[string]*model.Program) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for id := range s.pipes {
		if _, ok := programs[id]; !ok {
			delete(s.pipes, id)
		}
	}
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{
			"status": "ok", "product": "scrubline-cloud",
			"datapath": "asic-tcam+fpga+pfring-zc+ml",
			"mode":     string(s.Mode()),
		})
	})
	mux.HandleFunc("/metrics", s.metrics)
	mux.HandleFunc("/v1/", s.route)
	return mux
}

// metrics exposes the control plane's own view plus the datapath counters the
// fleet reported on its heartbeats. It takes the same bearer token as the rest
// of the control plane: rule IDs and traffic volumes are not public.
func (s *Server) metrics(w http.ResponseWriter, r *http.Request) {
	who, ok := s.authenticate(r)
	if !ok {
		unauthorized(w)
		return
	}
	if !who.isOperator() {
		// The fleet view names every node, its load, and its rule hits. A
		// single scrubber has no business reading it.
		forbidden(w, "the operator credential is required to scrape the control plane")
		return
	}
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "GET required"})
		return
	}
	var buf bytes.Buffer
	families := append(s.controlFamilies(), telemetry.Families(s.Store.Reports(), s.clock())...)
	if err := metrics.Write(&buf, families); err != nil {
		log.Printf("api: rendering metrics failed: %v", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to render metrics"})
		return
	}
	w.Header().Set("Content-Type", metrics.ContentType)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(buf.Bytes())
}

// controlFamilies describes the control plane itself: what it knows about the
// fleet, what it last compiled, and how its own API is answering.
func (s *Server) controlFamilies() []metrics.Family {
	nodes := s.Store.Nodes()
	ready, stale := 0, 0
	prefixes := metrics.Family{
		Name: "scrubline_node_prefixes", Type: metrics.Gauge,
		Help: "Protected prefixes a node enforces policy on. Zero means the node is enforcing nothing.",
	}
	for _, n := range nodes {
		if n.Status == model.NodeStale {
			stale++
		} else {
			ready++
		}
		prog, ok := s.Store.Program(n.ID)
		if !ok {
			continue
		}
		prefixes.Samples = append(prefixes.Samples, metrics.Sample{
			Labels: []metrics.Label{{Name: "node", Value: n.ID}, {Name: "name", Value: n.Name}, {Name: "region", Value: n.Region}},
			Value:  float64(len(prog.Prefixes)),
		})
	}

	plan, programs := s.Store.Fabric()
	m := s.Store.Model()

	families := []metrics.Family{
		{
			Name: "scrubline_nodes", Type: metrics.Gauge,
			Help: "Registered nodes by liveness. A stale node is withdrawn from anycast.",
			Samples: []metrics.Sample{
				{Labels: []metrics.Label{{Name: "status", Value: model.NodeReady}}, Value: float64(ready)},
				{Labels: []metrics.Label{{Name: "status", Value: model.NodeStale}}, Value: float64(stale)},
			},
		},
		{
			Name: "scrubline_policies", Type: metrics.Gauge, Help: "Policies held by the control plane.",
			Samples: []metrics.Sample{{Value: float64(len(s.Store.Policies()))}},
		},
		{
			Name: "scrubline_announcements", Type: metrics.Gauge, Help: "Rows in the fabric's BGP announcement plan.",
			Samples: []metrics.Sample{{Value: float64(len(plan))}},
		},
		{
			Name: "scrubline_programs", Type: metrics.Gauge, Help: "Nodes holding a compiled program.",
			Samples: []metrics.Sample{{Value: float64(len(programs))}},
		},
		{
			Name: "scrubline_fabric_recompiles_total", Type: metrics.Counter,
			Help:    "Fabric recompiles, including those triggered by a node joining, recovering, or going stale.",
			Samples: []metrics.Sample{{Value: float64(s.recompiles.Load())}},
		},
		prefixes,
		{
			Name: "scrubline_control_ml_model_ready", Type: metrics.Gauge,
			Help:    "1 when the control plane is publishing a fitted classifier.",
			Samples: []metrics.Sample{{Value: boolValue(m.Ready)}},
		},
		{
			Name: "scrubline_control_ml_samples", Type: metrics.Gauge, Help: "Labeled samples held for training.",
			Samples: []metrics.Sample{{Value: float64(m.Samples)}},
		},
		{
			Name: "scrubline_control_ml_validation_samples", Type: metrics.Gauge,
			Help:    "Samples held out of the fit and scored against. Zero means the set was too small to split.",
			Samples: []metrics.Sample{{Value: float64(m.Validation)}},
		},
		{
			Name: "scrubline_control_ml_accuracy", Type: metrics.Gauge, Help: "Holdout accuracy of the published model.",
			Samples: []metrics.Sample{{Value: m.Accuracy}},
		},
		{
			Name: "scrubline_control_ml_precision", Type: metrics.Gauge,
			Help:    "Holdout precision of the published model. A false positive here is dropped customer traffic.",
			Samples: []metrics.Sample{{Value: m.Precision}},
		},
		{
			Name: "scrubline_control_ml_recall", Type: metrics.Gauge, Help: "Holdout recall of the published model.",
			Samples: []metrics.Sample{{Value: m.Recall}},
		},
	}
	families = append(families, telemetry.AnnouncementFamilies(plan)...)
	families = append(families, s.steeringFamilies(nodes)...)
	return append(families, s.requestFamily())
}

// steeringFamilies exposes the load controller: what it measured, how hard it
// is padding each node, and the ceiling it is measuring against. Without
// these an operator cannot tell a deliberate shed from a misconfiguration.
func (s *Server) steeringFamilies(nodes []model.Node) []metrics.Family {
	byID := make(map[string]model.Node, len(nodes))
	for _, n := range nodes {
		byID[n.ID] = n
	}
	escalation := metrics.Family{
		Name: "scrubline_steering_escalation", Type: metrics.Gauge,
		Help: "Extra AS-path prepends a node carries because of measured load, on top of what its capacity earns it.",
	}
	ratio := metrics.Family{
		Name: "scrubline_steering_load_ratio", Type: metrics.Gauge,
		Help: "A node's measured packet rate as a share of its declared packet-rate capacity. Zero when the node declares no capacity to measure against.",
	}
	capacity := metrics.Family{
		Name: "scrubline_node_capacity_pps", Type: metrics.Gauge,
		Help: "A node's declared packet-rate ceiling. Zero leaves the node out of load-driven steering.",
	}
	for id, level := range s.Steering().Levels() {
		n, known := byID[id]
		if !known {
			continue
		}
		labels := []metrics.Label{
			{Name: "node", Value: n.ID},
			{Name: "name", Value: n.Name},
			{Name: "region", Value: n.Region},
		}
		escalation.Samples = append(escalation.Samples, metrics.Sample{Labels: labels, Value: float64(level.Prepends)})
		ratio.Samples = append(ratio.Samples, metrics.Sample{Labels: labels, Value: level.Ratio})
		capacity.Samples = append(capacity.Samples, metrics.Sample{Labels: labels, Value: float64(n.CapacityPPS)})
	}
	return []metrics.Family{escalation, ratio, capacity}
}

func (s *Server) requestFamily() metrics.Family {
	s.requestsMu.Lock()
	defer s.requestsMu.Unlock()
	fam := metrics.Family{
		Name: "scrubline_api_requests_total", Type: metrics.Counter,
		Help: "Control-plane API requests by route and response status.",
	}
	for k, v := range s.requests {
		fam.Samples = append(fam.Samples, metrics.Sample{
			Labels: []metrics.Label{
				{Name: "route", Value: k.route},
				{Name: "status", Value: strconv.Itoa(k.status)},
			},
			Value: float64(v),
		})
	}
	return fam
}

func boolValue(b bool) float64 {
	if b {
		return 1
	}
	return 0
}

// statusRecorder remembers the status a handler wrote, so a request can be
// counted by outcome.
type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(code int) {
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}

func (s *Server) route(w http.ResponseWriter, r *http.Request) {
	rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
	route := s.dispatch(rec, r)
	s.requestsMu.Lock()
	if s.requests == nil {
		s.requests = map[requestKey]uint64{}
	}
	s.requests[requestKey{route: route, status: rec.status}]++
	s.requestsMu.Unlock()
}

// dispatch handles one request and returns the route name it matched, which is
// what the request counter is labeled by. Returning a name from the switch
// keeps the label set bounded and in step with the routing.
func (s *Server) dispatch(w http.ResponseWriter, r *http.Request) string {
	who, ok := s.authenticate(r)
	if !ok {
		unauthorized(w)
		return "unauthorized"
	}
	path := strings.TrimPrefix(r.URL.Path, "/v1/")

	// Everything below is operator-only unless the case says otherwise. A
	// scrubber holds a credential scoped to itself, so a compromised node
	// cannot rewrite policy, move another node's announcement, or read the
	// fabric.
	//
	// Anything that changes durable state also passes writesAllowed, so a
	// replica refuses it. Three POSTs deliberately do not: promote is how a
	// replica stops being one, and score and decide only compute an answer
	// from state already held.
	switch {
	case r.Method == http.MethodGet && path == "state":
		// A replica follows the primary by pulling this. It is the whole
		// durable state, so it is operator-only: a replica is part of the
		// control plane, not an edge node.
		if !operatorOnly(w, who) {
			return "state"
		}
		writeJSON(w, http.StatusOK, s.Store.Snapshot())
		return "state"
	case r.Method == http.MethodPost && path == "promote":
		if !operatorOnly(w, who) {
			return "promote"
		}
		if !s.Promote() {
			writeJSON(w, http.StatusConflict, map[string]string{"error": "this control plane is already the primary"})
			return "promote"
		}
		log.Printf("api: promoted to primary by an operator")
		writeJSON(w, http.StatusOK, map[string]string{"mode": string(ModePrimary)})
		return "promote"
	case r.Method == http.MethodPost && path == "nodes/register":
		// Enrollment is the one thing the bootstrap credential can do.
		if !who.isOperator() && who.role != RoleEnroll {
			forbidden(w, "registering a node requires the enrollment or operator credential")
			return "nodes/register"
		}
		if !s.writesAllowed(w) {
			return "nodes/register"
		}
		s.register(w, r)
		return "nodes/register"
	case r.Method == http.MethodPost && hasSubpath(path, "nodes", "heartbeat"):
		id, _ := subpathID(path, "nodes", "heartbeat")
		if !who.actsFor(id) {
			forbidden(w, "a node may only heartbeat for itself")
			return "nodes/heartbeat"
		}
		if !s.writesAllowed(w) {
			return "nodes/heartbeat"
		}
		s.heartbeat(w, r, id)
		return "nodes/heartbeat"
	case r.Method == http.MethodGet && path == "nodes":
		if !who.isOperator() {
			forbidden(w, "listing the fleet requires the operator credential")
			return "nodes"
		}
		writeJSON(w, http.StatusOK, s.Store.Nodes())
		return "nodes"
	case r.Method == http.MethodGet && hasSubpath(path, "nodes", "program"):
		id, _ := subpathID(path, "nodes", "program")
		if !who.actsFor(id) {
			// A program names the prefixes a node scrubs and what it
			// announces. One scrubber must not be able to read another's.
			forbidden(w, "a node may only fetch its own program")
			return "nodes/program"
		}
		prog, found := s.Store.Program(id)
		if !found {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "no program deployed"})
			return "nodes/program"
		}
		writeJSON(w, http.StatusOK, prog)
		return "nodes/program"
	case r.Method == http.MethodGet && hasSubpath(path, "nodes", "stats"):
		id, _ := subpathID(path, "nodes", "stats")
		if !who.actsFor(id) {
			forbidden(w, "a node may only read its own counters")
			return "nodes/stats"
		}
		report, found := s.Store.Report(id)
		if !found {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "no counters reported for this node"})
			return "nodes/stats"
		}
		writeJSON(w, http.StatusOK, report)
		return "nodes/stats"
	case r.Method == http.MethodPost && path == "policies":
		if !operatorOnly(w, who) || !s.writesAllowed(w) {
			return "policies"
		}
		s.savePolicy(w, r)
		return "policies"
	case r.Method == http.MethodGet && path == "policies":
		if !operatorOnly(w, who) {
			return "policies"
		}
		writeJSON(w, http.StatusOK, s.Store.Policies())
		return "policies"
	case r.Method == http.MethodPost && hasSubpath(path, "policies", "deploy"):
		if !operatorOnly(w, who) || !s.writesAllowed(w) {
			return "policies/deploy"
		}
		id, _ := subpathID(path, "policies", "deploy")
		s.deploy(w, id)
		return "policies/deploy"
	case r.Method == http.MethodGet && path == "fabric":
		if !operatorOnly(w, who) {
			return "fabric"
		}
		plan, programs := s.Store.Fabric()
		writeJSON(w, http.StatusOK, map[string]any{"announcements": plan, "programs": programs, "ml": s.Store.Model()})
		return "fabric"
	case r.Method == http.MethodPost && path == "ml/samples":
		if !operatorOnly(w, who) || !s.writesAllowed(w) {
			return "ml/samples"
		}
		s.addSamples(w, r)
		return "ml/samples"
	case r.Method == http.MethodGet && path == "ml/samples":
		if !operatorOnly(w, who) {
			return "ml/samples"
		}
		writeJSON(w, http.StatusOK, s.Store.Samples())
		return "ml/samples"
	case r.Method == http.MethodPost && path == "ml/train":
		if !operatorOnly(w, who) || !s.writesAllowed(w) {
			return "ml/train"
		}
		s.train(w, r)
		return "ml/train"
	case r.Method == http.MethodGet && path == "ml/model":
		// Every node installs the published model, so a node credential may
		// read it. It carries weights, not policy or fleet detail.
		if !who.isOperator() && who.role != RoleNode {
			forbidden(w, "reading the model requires a node or operator credential")
			return "ml/model"
		}
		writeJSON(w, http.StatusOK, s.Store.Model())
		return "ml/model"
	case r.Method == http.MethodDelete && path == "ml/model":
		if !operatorOnly(w, who) || !s.writesAllowed(w) {
			return "ml/model"
		}
		// Explicitly retire a model. Nodes clear their installed copy on the
		// next poll; without this a bad model could only be removed by
		// restarting every agent in the fleet.
		withdrawn, err := s.Store.WithdrawModel()
		if err != nil {
			storeFailure(w, "withdrawing the model", err)
			return "ml/model"
		}
		writeJSON(w, http.StatusOK, withdrawn)
		return "ml/model"
	case r.Method == http.MethodPost && path == "ml/score":
		if !operatorOnly(w, who) {
			return "ml/score"
		}
		s.score(w, r)
		return "ml/score"
	case r.Method == http.MethodPost && path == "decide":
		if !operatorOnly(w, who) {
			return "decide"
		}
		s.decide(w, r)
		return "decide"
	default:
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
		return "unknown"
	}
}

// heartbeat keeps a node live and takes the datapath counters it attached. The
// body is optional: an agent that sends none still heartbeats.
func (s *Server) heartbeat(w http.ResponseWriter, r *http.Request, id string) {
	var body struct {
		Stats pipeline.Stats `json:"stats"`
	}
	reported := false
	if err := decode(r, &body); err != nil && !errors.Is(err, io.EOF) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	} else if err == nil {
		reported = true
	}
	known, revived := s.Store.Heartbeat(id)
	if !known {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "unknown node"})
		return
	}
	// The node's identity comes from the record the control plane already
	// holds, not from the body, so a report cannot claim to be another node.
	if reported {
		s.Store.PutReport(id, body.Stats)
	}
	if revived {
		// The node is back in the live set, so it needs a program again.
		s.reconcile()
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// operatorOnly writes a refusal and reports false unless the caller holds the
// operator credential.
func operatorOnly(w http.ResponseWriter, who principal) bool {
	if who.isOperator() {
		return true
	}
	forbidden(w, "the operator credential is required for this endpoint")
	return false
}

// newChallengeSecret mints the key the challenge cookies are derived from.
func newChallengeSecret() (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return hex.EncodeToString(raw), nil
}

// storeFailure reports that durable state could not be written. The change
// has been rolled back, so the caller is told it did not take rather than
// being left to assume it did.
func storeFailure(w http.ResponseWriter, what string, err error) {
	log.Printf("api: %s failed: %v", what, err)
	writeJSON(w, http.StatusServiceUnavailable, map[string]string{
		"error": fmt.Sprintf("%s failed and was rolled back: the control plane could not write its state", what),
	})
}

func unauthorized(w http.ResponseWriter) {
	writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "missing or invalid bearer token"})
}

func forbidden(w http.ResponseWriter, reason string) {
	writeJSON(w, http.StatusForbidden, map[string]string{"error": reason})
}

// hasSubpath reports whether path is exactly "{collection}/{id}/{leaf}".
func hasSubpath(path, collection, leaf string) bool {
	_, ok := subpathID(path, collection, leaf)
	return ok
}

// subpathID pulls {id} out of "{collection}/{id}/{leaf}". An empty or nested id
// does not match, so "policies/deploy" is never read as the id "deploy".
func subpathID(path, collection, leaf string) (string, bool) {
	parts := strings.Split(path, "/")
	if len(parts) != 3 || parts[0] != collection || parts[2] != leaf || parts[1] == "" {
		return "", false
	}
	return parts[1], true
}

func (s *Server) register(w http.ResponseWriter, r *http.Request) {
	var n model.Node
	if err := decode(r, &n); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	if n.Name == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "name required"})
		return
	}
	if err := validateNode(n); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	registered, isNew, err := s.Store.UpsertNode(n)
	if err != nil {
		if errors.Is(err, store.ErrNodeConflict) {
			writeJSON(w, http.StatusConflict, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	// Registration is also credential issue: the node gets a credential
	// scoped to itself, returned once and never again. Re-registering rotates
	// it, so a restarted agent does not leave a second working key behind.
	token, err := s.Store.IssueNodeToken(registered.ID)
	if err != nil {
		log.Printf("api: issuing a credential for %s failed: %v", registered.ID, err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not issue a node credential"})
		return
	}
	if isNew {
		// Compile the standing policy onto the new node now rather than leaving
		// it with no program until someone deploys again.
		s.reconcile()
	}
	writeJSON(w, http.StatusOK, map[string]any{"node": registered, "token": token})
}

func (s *Server) savePolicy(w http.ResponseWriter, r *http.Request) {
	var p model.Policy
	if err := decode(r, &p); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	if p.Name == "" || len(p.Protected) == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "name and protected prefixes required"})
		return
	}
	if err := validatePolicy(p); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	// Filters with a challenge gate mint cookies keyed with this. It is
	// generated once per policy and shipped to every node, because under
	// anycast a cookie minted by one scrubber has to verify on another.
	if p.ChallengeSecret == "" && len(p.Games) > 0 {
		secret, err := newChallengeSecret()
		if err != nil {
			storeFailure(w, "generating a challenge secret", err)
			return
		}
		p.ChallengeSecret = secret
	}
	saved, err := s.Store.SavePolicy(p)
	if err != nil {
		storeFailure(w, "saving the policy", err)
		return
	}
	writeJSON(w, http.StatusOK, saved)
}

func (s *Server) deploy(w http.ResponseWriter, id string) {
	policy, ok := s.Store.Policy(id)
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "unknown policy"})
		return
	}
	// Read the live set under the same lock the recompile holds, so the
	// fingerprint recorded for this fabric is the set it was actually built
	// from.
	s.reconcileMu.Lock()
	live := s.Store.LiveNodes()
	if len(live) == 0 {
		s.reconcileMu.Unlock()
		writeJSON(w, http.StatusConflict, map[string]string{"error": "no live nodes registered"})
		return
	}
	all := s.Store.Nodes()
	plan, programs, err := s.applyDeploy(policy, all, live, s.observeLoad(all))
	s.reconcileMu.Unlock()
	if err != nil {
		storeFailure(w, "deploying the policy", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"policy_id":     policy.ID,
		"version":       policy.Version,
		"announcements": plan,
		"nodes":         len(programs),
		"datapath":      "asic/tcam + fpga + pf_ring zc + ml",
		"ml_ready":      s.Store.Model().Ready,
	})
}

func (s *Server) addSamples(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Samples []ml.Sample `json:"samples"`
	}
	if err := decode(r, &body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	if len(body.Samples) == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "samples required"})
		return
	}
	// Reject the whole batch on the first bad record. One out-of-range field
	// would otherwise train a model whose weights are all NaN.
	for i, sample := range body.Samples {
		if err := ml.ValidateSample(sample); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": fmt.Sprintf("samples[%d]: %v", i, err)})
			return
		}
	}
	stored, err := s.Store.AddSamples(body.Samples)
	if err != nil {
		writeJSON(w, http.StatusRequestEntityTooLarge, map[string]any{"error": err.Error(), "stored": stored})
		return
	}
	writeJSON(w, http.StatusOK, map[string]int{"stored": stored})
}

func (s *Server) train(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Epochs    int     `json:"epochs"`
		LR        float64 `json:"lr"`
		Threshold float64 `json:"threshold"`
	}
	// An absent body means "use the defaults", but a malformed one is an error
	// rather than something to silently ignore.
	if err := decode(r, &body); err != nil && !errors.Is(err, io.EOF) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	if len(s.Store.Samples()) < 2 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "need at least two labeled samples"})
		return
	}
	m, err := s.Store.Train(body.Epochs, body.LR, body.Threshold)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, m)
}

func (s *Server) score(w http.ResponseWriter, r *http.Request) {
	var f model.Flow
	if err := decode(r, &f); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	if err := ml.ValidateFlow(f); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	m := s.Store.Model()
	writeJSON(w, http.StatusOK, map[string]any{"score": ml.Score(m, f), "label": ml.Predict(m, f), "ready": m.Ready})
}

func (s *Server) decide(w http.ResponseWriter, r *http.Request) {
	var body struct {
		NodeID string     `json:"node_id"`
		Flow   model.Flow `json:"flow"`
	}
	if err := decode(r, &body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	if err := ml.ValidateFlow(body.Flow); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	prog, ok := s.Store.Program(body.NodeID)
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "node has no program"})
		return
	}
	pipe := s.pipelineFor(body.NodeID, prog)
	pipe.SetModel(s.Store.Model())
	d := pipe.Decide(body.Flow)
	d.NodeID = body.NodeID
	writeJSON(w, http.StatusOK, d)
}

func validateNode(n model.Node) error {
	if strings.ContainsAny(n.Name, "/|") {
		return errors.New("name must not contain '/' or '|'")
	}
	// Capacity decides how hard a node is prepended against the rest of the
	// fabric, so a value that cannot be compared would quietly make this node
	// the most attractive path everywhere. Reject it at the edge.
	if math.IsNaN(n.CapacityGbps) || math.IsInf(n.CapacityGbps, 0) {
		return fmt.Errorf("capacity_gbps must be a finite number, got %v", n.CapacityGbps)
	}
	if n.CapacityGbps < 0 {
		return fmt.Errorf("capacity_gbps must not be negative, got %v", n.CapacityGbps)
	}
	if n.CapacityPPS < 0 {
		return fmt.Errorf("capacity_pps must not be negative, got %d", n.CapacityPPS)
	}
	for _, b := range n.Backends {
		switch b {
		case model.StageASIC, model.StageFPGA, model.StageZC:
		default:
			return fmt.Errorf("unknown backend %q", b)
		}
	}
	return nil
}

func validatePolicy(p model.Policy) error {
	protected := map[string]bool{}
	for _, prefix := range p.Protected {
		if _, err := netip.ParsePrefix(prefix); err != nil {
			return fmt.Errorf("protected prefix %q: %v", prefix, err)
		}
		protected[prefix] = true
	}
	if err := validateSteering(p, protected); err != nil {
		return err
	}
	if err := validateGames(p); err != nil {
		return err
	}
	seen := map[string]bool{}
	for i, rule := range p.Rules {
		if rule.ID == "" {
			return fmt.Errorf("rules[%d]: id required", i)
		}
		// Rule IDs key the ZC rate-limit table as "<rule>|<src>".
		if strings.Contains(rule.ID, "|") {
			return fmt.Errorf("rules[%d]: id must not contain '|'", i)
		}
		if seen[rule.ID] {
			return fmt.Errorf("rules[%d]: duplicate rule id %q", i, rule.ID)
		}
		seen[rule.ID] = true
		if err := validateRule(rule); err != nil {
			return fmt.Errorf("rules[%d] (%s): %v", i, rule.ID, err)
		}
	}
	return nil
}

// validateSteering checks the per-prefix BGP overrides. A steering row that
// names a prefix the policy does not protect is a typo that would otherwise
// sit in the policy doing nothing.
func validateSteering(p model.Policy, protected map[string]bool) error {
	seen := map[string]bool{}
	for i, st := range p.Steering {
		if st.Prefix == "" {
			return fmt.Errorf("steering[%d]: prefix required", i)
		}
		if !protected[st.Prefix] {
			return fmt.Errorf("steering[%d]: prefix %q is not in this policy's protected list", i, st.Prefix)
		}
		if seen[st.Prefix] {
			return fmt.Errorf("steering[%d]: duplicate steering for prefix %q", i, st.Prefix)
		}
		seen[st.Prefix] = true
		for j, region := range st.Regions {
			if strings.TrimSpace(region) == "" {
				return fmt.Errorf("steering[%d].regions[%d]: region must not be empty", i, j)
			}
		}
		// Communities are written into a routing daemon's control pipe on
		// every node, so they are checked here rather than at the pipe.
		for j, c := range st.Communities {
			if err := bgp.ValidateCommunity(c); err != nil {
				return fmt.Errorf("steering[%d].communities[%d]: %v", i, j, err)
			}
		}
	}
	return nil
}

// validateGames checks the game filters a policy binds to its ports. They
// compile on every node, so a filter that cannot be compiled is refused here
// rather than being logged on fifty scrubbers.
func validateGames(p model.Policy) error {
	seen := map[string]bool{}
	for i, g := range p.Games {
		if g.ID == "" {
			return fmt.Errorf("games[%d]: id required", i)
		}
		// Filter IDs key the session table as "<filter>|<source>".
		if strings.Contains(g.ID, "|") {
			return fmt.Errorf("games[%d]: id must not contain '|'", i)
		}
		if seen[g.ID] {
			return fmt.Errorf("games[%d]: duplicate filter id %q", i, g.ID)
		}
		seen[g.ID] = true
		if g.DPort < 0 || g.DPort > ml.MaxPort {
			return fmt.Errorf("games[%d] (%s): dport must be within 0..%d, got %d", i, g.ID, ml.MaxPort, g.DPort)
		}
		switch strings.ToLower(g.Proto) {
		case "", "any", "udp", "tcp":
		default:
			return fmt.Errorf("games[%d] (%s): unknown proto %q", i, g.ID, g.Proto)
		}
		// A binding with no address, port or protocol would inspect every
		// packet the node sees against one game's grammar.
		if g.DstCIDR == "" && g.DPort == 0 {
			return fmt.Errorf("games[%d] (%s): needs a dst_cidr or a dport, or it would inspect everything", i, g.ID)
		}
	}
	// Compiling is the real check: it parses the CIDRs, the magic hex and
	// the gate, and rejects a profile nobody ships.
	if _, err := gamefilter.Compile(p.Games); err != nil {
		return err
	}
	return nil
}

func validateRule(rule model.Rule) error {
	switch rule.Stage {
	case model.StageASIC, model.StageFPGA, model.StageZC:
	default:
		return fmt.Errorf("unknown stage %q", rule.Stage)
	}
	switch rule.Action {
	case model.ActionDrop, model.ActionPermit, model.ActionLimit, model.ActionInspect, model.ActionCount:
	default:
		return fmt.Errorf("unknown action %q", rule.Action)
	}
	// A TCAM entry carries no meter, so a rate_limit rule on the ASIC stage would
	// compile to an entry that can never fire. Say so instead of dropping it.
	if rule.Stage == model.StageASIC && rule.Action == model.ActionLimit {
		return errors.New("the asic stage cannot meter; use the fpga or zc stage for rate_limit")
	}
	if rule.PPS < 0 {
		return fmt.Errorf("pps must not be negative, got %d", rule.PPS)
	}
	if rule.Action == model.ActionLimit && rule.PPS == 0 {
		return errors.New("rate_limit requires a positive pps")
	}
	// Only two stage/action pairs consume pps: an FPGA meter, and the ZC
	// inspect path's behavioral cap. Silently ignoring it anywhere else is how
	// an observe-only count rule ended up dropping traffic.
	if rule.PPS > 0 && !metersPPS(rule) {
		if rule.Action == model.ActionCount {
			return errors.New("a count rule is observe-only and must not carry pps")
		}
		return fmt.Errorf("the %s stage does not meter on %q; pps belongs on an fpga rate_limit or a zc rate_limit/inspect rule", rule.Stage, rule.Action)
	}
	for name, cidr := range map[string]string{"src_cidr": rule.Match.SrcCIDR, "dst_cidr": rule.Match.DstCIDR} {
		if cidr == "" {
			continue
		}
		// An unparseable CIDR never matches, so the rule silently fails open.
		if _, err := netip.ParsePrefix(cidr); err != nil {
			return fmt.Errorf("match.%s %q: %v", name, cidr, err)
		}
	}
	if rule.Match.DPort < 0 || rule.Match.DPort > ml.MaxPort {
		return fmt.Errorf("match.dport must be within 0..%d, got %d", ml.MaxPort, rule.Match.DPort)
	}
	if rule.Match.SPort < 0 || rule.Match.SPort > ml.MaxPort {
		return fmt.Errorf("match.sport must be within 0..%d, got %d", ml.MaxPort, rule.Match.SPort)
	}
	return nil
}

// metersPPS reports whether a rule's stage and action actually consume PPS.
func metersPPS(rule model.Rule) bool {
	switch rule.Stage {
	case model.StageFPGA:
		return rule.Action == model.ActionLimit
	case model.StageZC:
		return rule.Action == model.ActionLimit || rule.Action == model.ActionInspect
	}
	return false
}

// authenticate resolves the bearer credential on a request to a principal.
//
// Credentials are checked in order of privilege, and an unset credential never
// matches: an empty operator token used to disable authentication entirely,
// which turned a misconfiguration into an open control plane.
func (s *Server) authenticate(r *http.Request) (principal, bool) {
	scheme, token, found := strings.Cut(r.Header.Get("Authorization"), " ")
	if !found || !strings.EqualFold(scheme, "Bearer") || token == "" {
		return principal{}, false
	}
	// Constant time: a byte-wise compare leaks the token through response
	// timing. Both comparisons run regardless of the first result, so the
	// reply does not time differently for an operator and a node.
	operator := s.Token != "" && subtle.ConstantTimeCompare([]byte(token), []byte(s.Token)) == 1
	enroll := s.EnrollToken != "" && subtle.ConstantTimeCompare([]byte(token), []byte(s.EnrollToken)) == 1
	if operator {
		return principal{role: RoleOperator}, true
	}
	if enroll {
		return principal{role: RoleEnroll}, true
	}
	if nodeID, ok := s.Store.NodeForToken(token); ok {
		return principal{role: RoleNode, nodeID: nodeID}, true
	}
	return principal{}, false
}

// isOperator reports whether the caller holds the operator credential.
func (p principal) isOperator() bool { return p.role == RoleOperator }

// actsFor reports whether the caller may act for a specific node. An operator
// may act for any; a node may act only for itself.
func (p principal) actsFor(nodeID string) bool {
	return p.isOperator() || (p.role == RoleNode && p.nodeID == nodeID && nodeID != "")
}

func decode(r *http.Request, v any) error {
	return json.NewDecoder(io.LimitReader(r.Body, maxBody)).Decode(v)
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	// Encode first. Writing straight to the ResponseWriter commits the status
	// code before encoding can fail, which turned an unencodable value into a
	// 200 with an empty body on every affected endpoint.
	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(v); err != nil {
		log.Printf("api: encoding %T response failed: %v", v, err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error":"failed to encode response"}` + "\n"))
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_, _ = w.Write(buf.Bytes())
}
