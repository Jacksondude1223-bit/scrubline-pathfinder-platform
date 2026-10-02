package api

import (
	"bytes"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/netip"
	"strings"

	"github.com/Jacksondude1223-bit/scrubline-cloud-scrub/internal/compiler"
	"github.com/Jacksondude1223-bit/scrubline-cloud-scrub/internal/ml"
	"github.com/Jacksondude1223-bit/scrubline-cloud-scrub/internal/model"
	"github.com/Jacksondude1223-bit/scrubline-cloud-scrub/internal/pipeline"
	"github.com/Jacksondude1223-bit/scrubline-cloud-scrub/internal/store"
)

// maxBody bounds every request body. Policies and sample batches are the large
// ones; everything else is a handful of fields.
const maxBody = 4 << 20

type Server struct {
	Token string
	Store *store.Store
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
		if !s.Store.Heartbeat(id) {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "unknown node"})
			return
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
	writeJSON(w, http.StatusOK, s.Store.UpsertNode(n))
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
	nodes := s.Store.LiveNodes()
	if len(nodes) == 0 {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "no live nodes registered"})
		return
	}
	assigned := compiler.Assign(policy.Protected, nodes)
	programs := compiler.Compile(policy, nodes, assigned)
	s.Store.PutDeploy(assigned, programs)
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
	pipe := pipeline.New(prog)
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
