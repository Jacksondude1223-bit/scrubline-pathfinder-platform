package api

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"

	"github.com/Jacksondude1223-bit/scrubline-cloud-scrub/internal/compiler"
	"github.com/Jacksondude1223-bit/scrubline-cloud-scrub/internal/model"
	"github.com/Jacksondude1223-bit/scrubline-cloud-scrub/internal/pipeline"
	"github.com/Jacksondude1223-bit/scrubline-cloud-scrub/internal/store"
)

type Server struct {
	Token string
	Store *store.Store
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok", "product": "scrubline-cloud", "datapath": "asic-tcam+fpga+pfring-zc"})
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
	case r.Method == http.MethodPost && strings.HasPrefix(path, "nodes/") && strings.HasSuffix(path, "/heartbeat"):
		id := strings.TrimSuffix(strings.TrimPrefix(path, "nodes/"), "/heartbeat")
		if !s.Store.Heartbeat(id) {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "unknown node"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	case r.Method == http.MethodGet && path == "nodes":
		writeJSON(w, http.StatusOK, s.Store.Nodes())
	case r.Method == http.MethodGet && strings.HasPrefix(path, "nodes/") && strings.HasSuffix(path, "/program"):
		id := strings.TrimSuffix(strings.TrimPrefix(path, "nodes/"), "/program")
		prog, ok := s.Store.Program(id)
		if !ok {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "no program deployed"})
			return
		}
		writeJSON(w, http.StatusOK, prog)
	case r.Method == http.MethodPost && path == "policies":
		s.savePolicy(w, r)
	case r.Method == http.MethodGet && path == "policies":
		writeJSON(w, http.StatusOK, s.Store.Policies())
	case r.Method == http.MethodPost && strings.HasPrefix(path, "policies/") && strings.HasSuffix(path, "/deploy"):
		id := strings.TrimSuffix(strings.TrimPrefix(path, "policies/"), "/deploy")
		s.deploy(w, id)
	case r.Method == http.MethodGet && path == "fabric":
		assignments, programs := s.Store.Fabric()
		writeJSON(w, http.StatusOK, map[string]any{"assignments": assignments, "programs": programs})
	case r.Method == http.MethodPost && path == "decide":
		s.decide(w, r)
	default:
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
	}
}

func (s *Server) register(w http.ResponseWriter, r *http.Request) {
	var n model.Node
	if err := json.NewDecoder(r.Body).Decode(&n); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	if n.Name == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "name required"})
		return
	}
	writeJSON(w, http.StatusOK, s.Store.UpsertNode(n))
}

func (s *Server) savePolicy(w http.ResponseWriter, r *http.Request) {
	var p model.Policy
	if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	if p.Name == "" || len(p.Protected) == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "name and protected prefixes required"})
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
	nodes := s.Store.Nodes()
	if len(nodes) == 0 {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "no nodes registered"})
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
		"datapath":    "asic/tcam + fpga + pf_ring zc",
	})
}

func (s *Server) decide(w http.ResponseWriter, r *http.Request) {
	var body struct {
		NodeID string     `json:"node_id"`
		Flow   model.Flow `json:"flow"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	prog, ok := s.Store.Program(body.NodeID)
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "node has no program"})
		return
	}
	d := pipeline.New(prog).Decide(body.Flow)
	d.NodeID = body.NodeID
	writeJSON(w, http.StatusOK, d)
}

func (s *Server) auth(r *http.Request) bool {
	if s.Token == "" {
		return true
	}
	h := r.Header.Get("Authorization")
	return h == "Bearer "+s.Token
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}
