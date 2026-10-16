package api

import (
	"bytes"
	"context"
	"crypto/subtle"
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
	"github.com/Jacksondude1223-bit/scrubline-cloud-scrub/internal/metrics"
	"github.com/Jacksondude1223-bit/scrubline-cloud-scrub/internal/ml"
	"github.com/Jacksondude1223-bit/scrubline-cloud-scrub/internal/model"
	"github.com/Jacksondude1223-bit/scrubline-cloud-scrub/internal/pipeline"
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

type Server struct {
	Token string
	Store *store.Store

	// requestsMu guards the API request counters.
	requestsMu sync.Mutex
	requests   map[requestKey]uint64
	// recompiles counts fabric recompiles, so an operator can see the control
	// plane reacting to membership churn.
	recompiles atomic.Uint64

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

// reconcile recompiles the last deployed policy when the live node set has
// moved on from the one the current fabric was built for.
func (s *Server) reconcile() {
	s.reconcileMu.Lock()
	defer s.reconcileMu.Unlock()

	policyID := s.Store.LastDeployedPolicy()
	if policyID == "" {
		return
	}
	live := s.Store.LiveNodes()
	if fingerprint(live) == s.lastLive {
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
	plan, programs := s.applyDeploy(policy, s.Store.Nodes(), live)
	log.Printf("api: live node set changed, recompiled policy %s v%d across %d nodes (%d announcements)",
		policy.ID, policy.Version, len(programs), len(plan))
}

// applyDeploy compiles and stores the fabric for a policy. Callers hold
// reconcileMu.
//
// The plan covers every registered node, not only the live ones: the fabric is
// anycast, so a node that stopped answering needs an explicit withdrawal
// rather than to be left out, and a node that comes back finds its program
// already compiled. live is the set membership is tracked against.
func (s *Server) applyDeploy(policy model.Policy, all, live []model.Node) ([]model.Announcement, map[string]*model.Program) {
	plan := compiler.Plan(policy, all)
	programs := compiler.Compile(policy, all, plan)
	s.Store.PutDeploy(policy.ID, plan, programs)
	s.lastLive = fingerprint(live)
	s.prunePipelines(programs)
	s.recompiles.Add(1)
	return plan, programs
}

// fingerprint identifies a live node set, so a recompile only runs when
// membership actually changed.
func fingerprint(nodes []model.Node) string {
	ids := make([]string, 0, len(nodes))
	for _, n := range nodes {
		ids = append(ids, n.ID)
	}
	sort.Strings(ids)
	return strings.Join(ids, ",")
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
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok", "product": "scrubline-cloud", "datapath": "asic-tcam+fpga+pfring-zc+ml"})
	})
	mux.HandleFunc("/metrics", s.metrics)
	mux.HandleFunc("/v1/", s.route)
	return mux
}

// metrics exposes the control plane's own view plus the datapath counters the
// fleet reported on its heartbeats. It takes the same bearer token as the rest
// of the control plane: rule IDs and traffic volumes are not public.
func (s *Server) metrics(w http.ResponseWriter, r *http.Request) {
	if !s.auth(r) {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "missing or invalid bearer token"})
		return
	}
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "GET required"})
		return
	}
	var buf bytes.Buffer
	families := append(s.controlFamilies(), telemetry.Families(s.Store.Reports(), time.Now().UTC())...)
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
	return append(families, s.requestFamily())
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
	if !s.auth(r) {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "missing or invalid bearer token"})
		return "unauthorized"
	}
	path := strings.TrimPrefix(r.URL.Path, "/v1/")
	switch {
	case r.Method == http.MethodPost && path == "nodes/register":
		s.register(w, r)
		return "nodes/register"
	case r.Method == http.MethodPost && hasSubpath(path, "nodes", "heartbeat"):
		id, _ := subpathID(path, "nodes", "heartbeat")
		s.heartbeat(w, r, id)
		return "nodes/heartbeat"
	case r.Method == http.MethodGet && path == "nodes":
		writeJSON(w, http.StatusOK, s.Store.Nodes())
		return "nodes"
	case r.Method == http.MethodGet && hasSubpath(path, "nodes", "program"):
		id, _ := subpathID(path, "nodes", "program")
		prog, found := s.Store.Program(id)
		if !found {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "no program deployed"})
			return "nodes/program"
		}
		writeJSON(w, http.StatusOK, prog)
		return "nodes/program"
	case r.Method == http.MethodGet && hasSubpath(path, "nodes", "stats"):
		id, _ := subpathID(path, "nodes", "stats")
		report, found := s.Store.Report(id)
		if !found {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "no counters reported for this node"})
			return "nodes/stats"
		}
		writeJSON(w, http.StatusOK, report)
		return "nodes/stats"
	case r.Method == http.MethodPost && path == "policies":
		s.savePolicy(w, r)
		return "policies"
	case r.Method == http.MethodGet && path == "policies":
		writeJSON(w, http.StatusOK, s.Store.Policies())
		return "policies"
	case r.Method == http.MethodPost && hasSubpath(path, "policies", "deploy"):
		id, _ := subpathID(path, "policies", "deploy")
		s.deploy(w, id)
		return "policies/deploy"
	case r.Method == http.MethodGet && path == "fabric":
		plan, programs := s.Store.Fabric()
		writeJSON(w, http.StatusOK, map[string]any{"announcements": plan, "programs": programs, "ml": s.Store.Model()})
		return "fabric"
	case r.Method == http.MethodPost && path == "ml/samples":
		s.addSamples(w, r)
		return "ml/samples"
	case r.Method == http.MethodGet && path == "ml/samples":
		writeJSON(w, http.StatusOK, s.Store.Samples())
		return "ml/samples"
	case r.Method == http.MethodPost && path == "ml/train":
		s.train(w, r)
		return "ml/train"
	case r.Method == http.MethodGet && path == "ml/model":
		writeJSON(w, http.StatusOK, s.Store.Model())
		return "ml/model"
	case r.Method == http.MethodDelete && path == "ml/model":
		// Explicitly retire a model. Nodes clear their installed copy on the
		// next poll; without this a bad model could only be removed by
		// restarting every agent in the fleet.
		writeJSON(w, http.StatusOK, s.Store.WithdrawModel())
		return "ml/model"
	case r.Method == http.MethodPost && path == "ml/score":
		s.score(w, r)
		return "ml/score"
	case r.Method == http.MethodPost && path == "decide":
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
	if isNew {
		// Compile the standing policy onto the new node now rather than leaving
		// it with no program until someone deploys again.
		s.reconcile()
	}
	writeJSON(w, http.StatusOK, registered)
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
	writeJSON(w, http.StatusOK, s.Store.SavePolicy(p))
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
	plan, programs := s.applyDeploy(policy, s.Store.Nodes(), live)
	s.reconcileMu.Unlock()
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

func (s *Server) auth(r *http.Request) bool {
	// Fail closed. An empty token used to disable authentication entirely, which
	// turned a misconfiguration into an open control plane.
	if s.Token == "" {
		return false
	}
	scheme, token, found := strings.Cut(r.Header.Get("Authorization"), " ")
	if !found || !strings.EqualFold(scheme, "Bearer") {
		return false
	}
	// Constant time: a byte-wise compare leaks the token through response timing.
	return subtle.ConstantTimeCompare([]byte(token), []byte(s.Token)) == 1
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
