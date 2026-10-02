package store

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/Jacksondude1223-bit/scrubline-cloud-scrub/internal/ml"
	"github.com/Jacksondude1223-bit/scrubline-cloud-scrub/internal/model"
)

const (
	// NodeTTL is how long a node stays live after its last heartbeat. The agent
	// polls every two seconds, so this tolerates several missed rounds.
	NodeTTL = 30 * time.Second
	// MaxSamples bounds the labeled training set. Samples arrive over an
	// authenticated API but are never evicted on their own, so without a bound
	// the control plane grows until it is killed.
	MaxSamples = 200000
)

// ErrSampleLimit is returned when a batch would push the training set over
// MaxSamples.
var ErrSampleLimit = fmt.Errorf("training set is limited to %d samples", MaxSamples)

type Store struct {
	mu          sync.Mutex
	nodes       map[string]*model.Node
	policies    map[string]*model.Policy
	programs    map[string]*model.Program
	assignments []model.Assignment
	samples     []ml.Sample
	model       ml.Model
	seq         int
	// now is swapped out in tests; production always uses the wall clock.
	now func() time.Time
}

func New() *Store {
	return &Store{
		nodes:    map[string]*model.Node{},
		policies: map[string]*model.Policy{},
		programs: map[string]*model.Program{},
		now:      func() time.Time { return time.Now().UTC() },
	}
}

// clock reads the store's time source, tolerating a zero-value Store.
func (s *Store) clock() time.Time {
	if s.now == nil {
		return time.Now().UTC()
	}
	return s.now()
}

func (s *Store) UpsertNode(n model.Node) model.Node {
	s.mu.Lock()
	defer s.mu.Unlock()
	if n.ID == "" {
		n.ID = id("node", n.Name, n.Region)
	}
	if n.Backends == nil {
		n.Backends = []model.Stage{model.StageASIC, model.StageFPGA, model.StageZC}
	}
	n.LastSeen = s.clock()
	n.Status = model.NodeReady
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
	n.LastSeen = s.clock()
	n.Status = model.NodeReady
	return true
}

// Nodes lists every registered node with its status refreshed against NodeTTL.
func (s *Store) Nodes() []model.Node {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.snapshot(false)
}

// LiveNodes lists only the nodes that have heartbeated within NodeTTL. Prefix
// assignment uses this: handing a prefix to a node that stopped answering
// blackholes the traffic it was supposed to scrub.
func (s *Store) LiveNodes() []model.Node {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.snapshot(true)
}

// snapshot copies nodes out, stamping status from LastSeen. Callers hold s.mu.
func (s *Store) snapshot(liveOnly bool) []model.Node {
	now := s.clock()
	out := make([]model.Node, 0, len(s.nodes))
	for _, n := range s.nodes {
		cp := *n
		if now.Sub(cp.LastSeen) > NodeTTL {
			cp.Status = model.NodeStale
			if liveOnly {
				continue
			}
		} else {
			cp.Status = model.NodeReady
		}
		out = append(out, cp)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Name != out[j].Name {
			return out[i].Name < out[j].Name
		}
		return out[i].ID < out[j].ID
	})
	return out
}

func (s *Store) SavePolicy(p model.Policy) model.Policy {
	s.mu.Lock()
	defer s.mu.Unlock()
	if p.ID == "" {
		// Skip IDs a client already claimed, so a generated ID never silently
		// overwrites an existing policy.
		for {
			s.seq++
			p.ID = fmt.Sprintf("pol-%d", s.seq)
			if _, taken := s.policies[p.ID]; !taken {
				break
			}
		}
	}
	if prev, ok := s.policies[p.ID]; ok {
		p.Version = prev.Version + 1
	} else {
		p.Version = 1
	}
	p.UpdatedAt = s.clock()
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
	sort.Slice(out, func(i, j int) bool {
		if out[i].Name != out[j].Name {
			return out[i].Name < out[j].Name
		}
		return out[i].ID < out[j].ID
	})
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
	// Copy the caller's map so a later mutation of it cannot reach into the store.
	s.programs = make(map[string]*model.Program, len(programs))
	for k, v := range programs {
		cp := *v
		s.programs[k] = &cp
	}
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

// AddSamples appends a labeled batch and reports the new total.
func (s *Store) AddSamples(in []ml.Sample) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.samples)+len(in) > MaxSamples {
		return len(s.samples), ErrSampleLimit
	}
	s.samples = append(s.samples, in...)
	return len(s.samples), nil
}

func (s *Store) Samples() []ml.Sample {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]ml.Sample(nil), s.samples...)
}

// Train fits a model on the current sample set. The fit itself runs outside the
// store lock: it is O(epochs * samples) and holding the lock across it stalled
// every other request, heartbeats included, long enough to mark nodes stale.
func (s *Store) Train(epochs int, lr, threshold float64) (ml.Model, error) {
	s.mu.Lock()
	samples := append([]ml.Sample(nil), s.samples...)
	s.mu.Unlock()

	m, err := ml.Train(samples, epochs, lr, threshold)
	if err != nil {
		return ml.Model{}, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.model = m
	return m, nil
}

func (s *Store) Model() ml.Model {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.model
}

// id derives a stable identifier from the given parts. The parts are joined with
// a separator that cannot appear inside them, so ("scrub","ab") and
// ("scru","bab") no longer hash to the same node ID.
func id(kind string, parts ...string) string {
	h := sha256.New()
	h.Write([]byte(kind))
	for _, p := range parts {
		h.Write([]byte{0})
		h.Write([]byte(p))
	}
	return kind + "-" + hex.EncodeToString(h.Sum(nil)[:8])
}
