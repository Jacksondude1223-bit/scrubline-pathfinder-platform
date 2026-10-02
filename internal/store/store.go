package store

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/Jacksondude1223-bit/scrubline-cloud-scrub/internal/model"
)

type Store struct {
	mu          sync.Mutex
	nodes       map[string]*model.Node
	policies    map[string]*model.Policy
	programs    map[string]*model.Program
	assignments []model.Assignment
	seq         int
}

func New() *Store {
	return &Store{
		nodes:    map[string]*model.Node{},
		policies: map[string]*model.Policy{},
		programs: map[string]*model.Program{},
	}
}

func (s *Store) UpsertNode(n model.Node) model.Node {
	s.mu.Lock()
	defer s.mu.Unlock()
	if n.ID == "" {
		n.ID = id("node", n.Name+n.Region)
	}
	if n.Backends == nil {
		n.Backends = []model.Stage{model.StageASIC, model.StageFPGA, model.StageZC}
	}
	n.LastSeen = time.Now().UTC()
	n.Status = "ready"
	cp := n
	s.nodes[n.ID] = &cp
	return cp
}

func (s *Store) Heartbeat(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	n, ok := s.nodes[id]
	if !ok {
		return false
	}
	n.LastSeen = time.Now().UTC()
	n.Status = "ready"
	return true
}

func (s *Store) Nodes() []model.Node {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]model.Node, 0, len(s.nodes))
	for _, n := range s.nodes {
		out = append(out, *n)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func (s *Store) SavePolicy(p model.Policy) model.Policy {
	s.mu.Lock()
	defer s.mu.Unlock()
	if p.ID == "" {
		s.seq++
		p.ID = fmt.Sprintf("pol-%d", s.seq)
	}
	if prev, ok := s.policies[p.ID]; ok {
		p.Version = prev.Version + 1
	} else {
		p.Version = 1
	}
	p.UpdatedAt = time.Now().UTC()
	cp := p
	s.policies[p.ID] = &cp
	return cp
}

func (s *Store) Policies() []model.Policy {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]model.Policy, 0, len(s.policies))
	for _, p := range s.policies {
		out = append(out, *p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func (s *Store) Policy(id string) (model.Policy, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.policies[id]
	if !ok {
		return model.Policy{}, false
	}
	return *p, true
}

func (s *Store) PutDeploy(assignments []model.Assignment, programs map[string]*model.Program) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.assignments = append([]model.Assignment(nil), assignments...)
	s.programs = programs
}

func (s *Store) Program(nodeID string) (model.Program, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.programs[nodeID]
	if !ok {
		return model.Program{}, false
	}
	return *p, true
}

func (s *Store) Fabric() ([]model.Assignment, []model.Program) {
	s.mu.Lock()
	defer s.mu.Unlock()
	progs := make([]model.Program, 0, len(s.programs))
	for _, p := range s.programs {
		progs = append(progs, *p)
	}
	sort.Slice(progs, func(i, j int) bool { return progs[i].NodeID < progs[j].NodeID })
	return append([]model.Assignment(nil), s.assignments...), progs
}

func id(kind, key string) string {
	sum := sha256.Sum256([]byte(kind + ":" + key))
	return kind + "-" + hex.EncodeToString(sum[:4])
}
