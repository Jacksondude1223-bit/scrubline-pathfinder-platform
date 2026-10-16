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
	"net/http"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Jacksondude1223-bit/scrubline-cloud-scrub/internal/compiler"
	"github.com/Jacksondude1223-bit/scrubline-cloud-scrub/internal/ml"
	"github.com/Jacksondude1223-bit/scrubline-cloud-scrub/internal/model"
	"github.com/Jacksondude1223-bit/scrubline-cloud-scrub/internal/pipeline"
	"github.com/Jacksondude1223-bit/scrubline-cloud-scrub/internal/store"
)

// maxBody bounds every request body. Policies and sample batches are the large
// ones; everything else is a handful of fields.
const maxBody = 4 << 20

// ReconcileInterval is how often the fabric is checked against the live node
// set. A node that joins or recovers between deploys would otherwise hold no
// program, and a node that dies would keep its prefixes assigned to it.
const ReconcileInterval = 5 * time.Second

type Server struct {
	Token string
	Store *store.Store

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
	nodes := s.Store.LiveNodes()
	if fingerprint(nodes) == s.lastLive {
		return
	}
	if len(nodes) == 0 {
		// Every node is stale. Recompiling would blank the fabric; leaving the
		// last programs in place keeps whatever is still enforcing them.
		log.Printf("api: no live nodes, keeping the fabric compiled for policy %s", policyID)
		return
	}
	policy, ok := s.Store.Policy(policyID)
	if !ok {
		return
	}
	assigned, programs := s.applyDeploy(policy, nodes)
	log.Printf("api: live node set changed, recompiled policy %s v%d across %d nodes (%d assignments)",
		policy.ID, policy.Version, len(programs), len(assigned))
}

// applyDeploy compiles and stores the fabric for a policy. Callers hold
// reconcileMu.
func (s *Server) applyDeploy(policy model.Policy, nodes []model.Node) ([]model.Assignment, map[string]*model.Program) {
	assigned := compiler.Assign(policy.Protected, nodes)
	programs := compiler.Compile(policy, nodes, assigned)
	s.Store.PutDeploy(policy.ID, assigned, programs)
	s.lastLive = fingerprint(nodes)
	s.prunePipelines(programs)
	return assigned, programs
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
	mux.HandleFunc("/v1/", s.route)
	return mux
}

func (s *Server) route(w http.ResponseWriter, r *http.Request) {
	if !s.auth(r) {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "missing or invalid bearer token"})
		return
	}
	path := strings.TrimPrefix(r.URL.Path, "/v1/")
	switch {
	case r.Method == http.MethodPost && path == "nodes/register":
		s.register(w, r)
	case r.Method == http.MethodPost && hasSubpath(path, "nodes", "heartbeat"):
		id, _ := subpathID(path, "nodes", "heartbeat")
		known, revived := s.Store.Heartbeat(id)
		if !known {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "unknown node"})
			return
		}
		if revived {
			// The node is back in the live set, so it needs a program again.
			s.reconcile()
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	case r.Method == http.MethodGet && path == "nodes":
		writeJSON(w, http.StatusOK, s.Store.Nodes())
	case r.Method == http.MethodGet && hasSubpath(path, "nodes", "program"):
		id, _ := subpathID(path, "nodes", "program")
		prog, found := s.Store.Program(id)
		if !found {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "no program deployed"})
			return
		}
		writeJSON(w, http.StatusOK, prog)
	case r.Method == http.MethodPost && path == "policies":
		s.savePolicy(w, r)
	case r.Method == http.MethodGet && path == "policies":
		writeJSON(w, http.StatusOK, s.Store.Policies())
	case r.Method == http.MethodPost && hasSubpath(path, "policies", "deploy"):
		id, _ := subpathID(path, "policies", "deploy")
		s.deploy(w, id)
	case r.Method == http.MethodGet && path == "fabric":
		assignments, programs := s.Store.Fabric()
		writeJSON(w, http.StatusOK, map[string]any{"assignments": assignments, "programs": programs, "ml": s.Store.Model()})
	case r.Method == http.MethodPost && path == "ml/samples":
		s.addSamples(w, r)
	case r.Method == http.MethodGet && path == "ml/samples":
		writeJSON(w, http.StatusOK, s.Store.Samples())
	case r.Method == http.MethodPost && path == "ml/train":
		s.train(w, r)
	case r.Method == http.MethodGet && path == "ml/model":
		writeJSON(w, http.StatusOK, s.Store.Model())
	case r.Method == http.MethodDelete && path == "ml/model":
		// Explicitly retire a model. Nodes clear their installed copy on the
		// next poll; without this a bad model could only be removed by
		// restarting every agent in the fleet.
		writeJSON(w, http.StatusOK, s.Store.WithdrawModel())
	case r.Method == http.MethodPost && path == "ml/score":
		s.score(w, r)
	case r.Method == http.MethodPost && path == "decide":
		s.decide(w, r)
	default:
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
	}
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
	nodes := s.Store.LiveNodes()
	if len(nodes) == 0 {
		s.reconcileMu.Unlock()
		writeJSON(w, http.StatusConflict, map[string]string{"error": "no live nodes registered"})
		return
	}
	assigned, programs := s.applyDeploy(policy, nodes)
	s.reconcileMu.Unlock()
	writeJSON(w, http.StatusOK, map[string]any{
		"policy_id":   policy.ID,
		"version":     policy.Version,
		"assignments": assigned,
		"nodes":       len(programs),
		"datapath":    "asic/tcam + fpga + pf_ring zc + ml",
		"ml_ready":    s.Store.Model().Ready,
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
	// A negative or absurd capacity skews prefix assignment; reject it at the
	// edge rather than clamping it silently.
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
	for _, prefix := range p.Protected {
		if _, err := netip.ParsePrefix(prefix); err != nil {
			return fmt.Errorf("protected prefix %q: %v", prefix, err)
		}
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
