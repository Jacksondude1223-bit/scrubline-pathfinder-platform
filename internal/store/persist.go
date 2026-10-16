package store

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"github.com/Jacksondude1223-bit/scrubline-cloud-scrub/internal/ml"
	"github.com/Jacksondude1223-bit/scrubline-cloud-scrub/internal/model"
	"github.com/Jacksondude1223-bit/scrubline-cloud-scrub/internal/telemetry"
)

// snapshotVersion guards the on-disk format. A file written by a newer build
// is refused rather than half-understood.
const snapshotVersion = 1

// Snapshot is the durable half of the control plane.
//
// Programs, the announcement plan, and the steering levels are left out on
// purpose: they are derived from the policy and the live node set, and
// recompiling them from a stale snapshot would hand the fabric a plan built
// for nodes that may no longer be there. Reports are left out for the same
// reason — a counter from before the restart is not a measurement of now.
//
// Liveness is not durable either. Heartbeats arrive every couple of seconds
// per node, and persisting them would mean rewriting this file constantly to
// save something that is worthless the moment the process stops. Nodes
// therefore load back stale and are withdrawn from anycast until they check
// in, which is the truth: nobody knows whether they are up.
type Snapshot struct {
	Version      int               `json:"version"`
	SavedAt      time.Time         `json:"saved_at"`
	Seq          int               `json:"seq"`
	Nodes        []model.Node      `json:"nodes"`
	NodeTokens   map[string]string `json:"node_tokens"`
	Policies     []model.Policy    `json:"policies"`
	LastPolicyID string            `json:"last_policy_id"`
	Samples      []ml.Sample       `json:"samples"`
	Model        ml.Model          `json:"model"`
}

// Open builds a store backed by a file, loading it if it already exists. An
// empty path keeps everything in memory, which is what the tests and the
// single-shot demo use.
func Open(path string) (*Store, error) {
	s := New()
	s.path = path
	if path == "" {
		return s, nil
	}
	raw, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		// Nothing to load. Write the empty state now rather than discovering
		// at the first policy save that the directory is not writable.
		s.mu.Lock()
		defer s.mu.Unlock()
		if err := s.persistLocked(); err != nil {
			return nil, err
		}
		return s, nil
	}
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}
	var snap Snapshot
	if err := json.Unmarshal(raw, &snap); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", path, err)
	}
	if snap.Version != snapshotVersion {
		return nil, fmt.Errorf("%s is format version %d, this build understands %d", path, snap.Version, snapshotVersion)
	}
	s.load(snap)
	return s, nil
}

// load installs a snapshot. It rebuilds what was deliberately not written:
// the credential reverse index, and nothing else, because everything else
// derived is recompiled from the policy once nodes check in.
func (s *Store) load(snap Snapshot) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.seq = snap.Seq
	s.lastPolicyID = snap.LastPolicyID
	s.samples = append([]ml.Sample(nil), snap.Samples...)
	s.model = snap.Model

	s.nodes = make(map[string]*model.Node, len(snap.Nodes))
	for _, n := range snap.Nodes {
		cp := n
		// Whatever the file says, nothing has heartbeated since the restart,
		// so the node is stale until it does. Status is derived from
		// LastSeen, so clearing the timestamp is what actually decides it.
		cp.LastSeen = time.Time{}
		cp.Status = model.NodeStale
		s.nodes[cp.ID] = &cp
	}
	s.policies = make(map[string]*model.Policy, len(snap.Policies))
	for _, p := range snap.Policies {
		cp := p
		s.policies[cp.ID] = &cp
	}
	s.nodeTokens = make(map[string]string, len(snap.NodeTokens))
	s.tokenNodes = make(map[string]string, len(snap.NodeTokens))
	for nodeID, hash := range snap.NodeTokens {
		s.nodeTokens[nodeID] = hash
		s.tokenNodes[hash] = nodeID
	}
	// Derived state starts empty and is recompiled once the fleet checks in.
	s.programs = map[string]*model.Program{}
	s.plan = nil
	s.reports = map[string]telemetry.Report{}
}

// Snapshot copies the durable state out. Callers hold nothing; this takes the
// lock itself.
func (s *Store) Snapshot() Snapshot {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.snapshotLocked()
}

func (s *Store) snapshotLocked() Snapshot {
	snap := Snapshot{
		Version:      snapshotVersion,
		SavedAt:      s.clock(),
		Seq:          s.seq,
		LastPolicyID: s.lastPolicyID,
		Samples:      append([]ml.Sample(nil), s.samples...),
		Model:        s.model,
		NodeTokens:   make(map[string]string, len(s.nodeTokens)),
		Nodes:        make([]model.Node, 0, len(s.nodes)),
		Policies:     make([]model.Policy, 0, len(s.policies)),
	}
	for _, n := range s.nodes {
		cp := *n
		// Liveness is not durable, so it is not written. Status is derived
		// from LastSeen everywhere, which means leaving a timestamp here
		// would bring nodes back apparently alive after a restart that
		// nothing has heartbeated through.
		cp.LastSeen = time.Time{}
		cp.Status = model.NodeStale
		snap.Nodes = append(snap.Nodes, cp)
	}
	for _, p := range s.policies {
		snap.Policies = append(snap.Policies, *p)
	}
	for id, hash := range s.nodeTokens {
		snap.NodeTokens[id] = hash
	}
	sortNodes(snap.Nodes)
	sortPolicies(snap.Policies)
	return snap
}

// Load replaces the store's contents with a snapshot and writes it through.
// A replica uses this to follow its primary.
func (s *Store) Load(snap Snapshot) error {
	if snap.Version != snapshotVersion {
		return fmt.Errorf("snapshot is format version %d, this build understands %d", snap.Version, snapshotVersion)
	}
	s.load(snap)
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.persistLocked()
}

// persistLocked writes the durable state out, atomically. Callers hold s.mu.
//
// The write goes to a sibling temp file, is flushed to the platter, and is
// then renamed over the real one; the directory is flushed too, because a
// rename that is not itself durable can be lost by a crash. A torn write
// therefore leaves the previous state intact rather than a truncated file.
func (s *Store) persistLocked() error {
	if s.path == "" {
		return nil
	}
	raw, err := json.Marshal(s.snapshotLocked())
	if err != nil {
		return fmt.Errorf("encoding the control-plane state: %w", err)
	}

	dir := filepath.Dir(s.path)
	tmp := s.path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("opening %s: %w", tmp, err)
	}
	if _, err := f.Write(raw); err != nil {
		f.Close()
		os.Remove(tmp)
		return fmt.Errorf("writing %s: %w", tmp, err)
	}
	if err := f.Sync(); err != nil {
		f.Close()
		os.Remove(tmp)
		return fmt.Errorf("flushing %s: %w", tmp, err)
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("closing %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, s.path); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("replacing %s: %w", s.path, err)
	}
	return syncDir(dir)
}

// syncDir flushes a directory entry so a rename survives a crash.
func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("opening %s: %w", dir, err)
	}
	defer d.Close()
	if err := d.Sync(); err != nil {
		return fmt.Errorf("flushing %s: %w", dir, err)
	}
	return nil
}
