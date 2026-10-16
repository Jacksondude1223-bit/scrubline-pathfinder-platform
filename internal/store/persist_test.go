package store

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Jacksondude1223-bit/scrubline-cloud-scrub/internal/ml"
	"github.com/Jacksondude1223-bit/scrubline-cloud-scrub/internal/model"
	"github.com/Jacksondude1223-bit/scrubline-cloud-scrub/internal/pipeline"
)

func tempStore(t *testing.T) (*Store, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "state.json")
	s, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	return s, path
}

// The whole point: a restart keeps the policies, the credentials and the
// model, so the fabric does not have to be rebuilt by hand during an attack.
func TestStateSurvivesARestart(t *testing.T) {
	s, path := tempStore(t)
	node, _, err := s.UpsertNode(model.Node{Name: "scrub-a", Region: "iad", CapacityGbps: 100, CapacityPPS: 1_000_000})
	if err != nil {
		t.Fatalf("UpsertNode: %v", err)
	}
	token, err := s.IssueNodeToken(node.ID)
	if err != nil {
		t.Fatalf("IssueNodeToken: %v", err)
	}
	policy := mustSave(t, s, model.Policy{Name: "edge", Protected: []string{"203.0.113.0/24"}})
	if err := s.PutDeploy(policy.ID, nil, map[string]*model.Program{}); err != nil {
		t.Fatalf("PutDeploy: %v", err)
	}
	if _, err := s.AddSamples([]ml.Sample{
		{Flow: model.Flow{Proto: "tcp", PPS: 10}, Label: 0},
		{Flow: model.Flow{Proto: "udp", Flags: "syn", PPS: 500000}, Label: 1},
	}); err != nil {
		t.Fatalf("AddSamples: %v", err)
	}
	if _, err := s.Train(50, 0.2, 0.6); err != nil {
		t.Fatalf("Train: %v", err)
	}

	reopened, err := Open(path)
	if err != nil {
		t.Fatalf("reopening: %v", err)
	}
	if got, ok := reopened.Policy(policy.ID); !ok || got.Name != "edge" {
		t.Fatalf("the policy did not survive: %+v %v", got, ok)
	}
	if got := reopened.LastDeployedPolicy(); got != policy.ID {
		t.Fatalf("the deployed policy did not survive, got %q", got)
	}
	if got := len(reopened.Samples()); got != 2 {
		t.Fatalf("expected the training set to survive, got %d samples", got)
	}
	if !reopened.Model().Ready {
		t.Fatal("the fitted model did not survive")
	}
	// The credential survives, so the fleet does not have to re-enrol and
	// the enrollment secret is not needed on every control-plane restart.
	if got, ok := reopened.NodeForToken(token); !ok || got != node.ID {
		t.Fatalf("the node credential did not survive: %q %v", got, ok)
	}
	if got := len(reopened.Nodes()); got != 1 {
		t.Fatalf("expected the node registration to survive, got %d", got)
	}
}

// Liveness is not durable. A node loads back stale, because nobody knows
// whether it is up until it heartbeats.
func TestNodesComeBackStale(t *testing.T) {
	s, path := tempStore(t)
	node, _, err := s.UpsertNode(model.Node{Name: "scrub-a", Region: "iad"})
	if err != nil {
		t.Fatalf("UpsertNode: %v", err)
	}
	if got := s.LiveNodes(); len(got) != 1 {
		t.Fatalf("expected the node live before the restart, got %d", len(got))
	}

	reopened, err := Open(path)
	if err != nil {
		t.Fatalf("reopening: %v", err)
	}
	if got := reopened.LiveNodes(); len(got) != 0 {
		t.Fatalf("a node must not come back live without heartbeating, got %+v", got)
	}
	if got := reopened.Nodes(); len(got) != 1 || got[0].Status != model.NodeStale {
		t.Fatalf("expected the node reported stale, got %+v", got)
	}
	// One heartbeat brings it back, and reports it as a revival so the
	// fabric is recompiled onto it.
	ok, revived := reopened.Heartbeat(node.ID)
	if !ok || !revived {
		t.Fatalf("expected a revival on the first heartbeat after a restart: %v %v", ok, revived)
	}
}

// Derived state is not written: recompiling a plan from a snapshot would
// hand the fabric announcements built for nodes that may be gone.
func TestDerivedStateIsNotPersisted(t *testing.T) {
	s, path := tempStore(t)
	node, _, _ := s.UpsertNode(model.Node{Name: "scrub-a", Region: "iad"})
	policy := mustSave(t, s, model.Policy{Name: "edge", Protected: []string{"203.0.113.0/24"}})
	if err := s.PutDeploy(policy.ID, []model.Announcement{{Prefix: "203.0.113.0/24", NodeID: node.ID, State: model.StateAnnounce}},
		map[string]*model.Program{node.ID: {NodeID: node.ID, PolicyID: policy.ID}}); err != nil {
		t.Fatalf("PutDeploy: %v", err)
	}
	s.PutReport(node.ID, pipeline.Stats{Decisions: 5})

	reopened, err := Open(path)
	if err != nil {
		t.Fatalf("reopening: %v", err)
	}
	plan, programs := reopened.Fabric()
	if len(plan) != 0 || len(programs) != 0 {
		t.Fatalf("expected the plan and programs to be recompiled, not restored: %d/%d", len(plan), len(programs))
	}
	if got := len(reopened.Reports()); got != 0 {
		t.Fatalf("a counter from before the restart is not a measurement of now, got %d reports", got)
	}
	// What it does keep is which policy to recompile from.
	if got := reopened.LastDeployedPolicy(); got != policy.ID {
		t.Fatalf("expected the deployed policy remembered, got %q", got)
	}
}

// A write that cannot be made durable must not be reported as having
// happened. The caller would otherwise act on a policy the control plane
// forgets at the next restart.
func TestAFailedWriteIsRolledBack(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	s, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	first := mustSave(t, s, model.Policy{Name: "good", Protected: []string{"203.0.113.0/24"}})

	// Make the directory unwritable so the temp file cannot be created.
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Skipf("cannot make the directory read-only here: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })
	if os.Geteuid() == 0 {
		t.Skip("running as root, which ignores the directory mode")
	}

	if _, err := s.SavePolicy(model.Policy{Name: "doomed", Protected: []string{"198.51.100.0/24"}}); err == nil {
		t.Fatal("expected a policy save to fail when the state cannot be written")
	}
	if got := len(s.Policies()); got != 1 {
		t.Fatalf("the failed save was kept in memory: %d policies", got)
	}
	if got, ok := s.Policy(first.ID); !ok || got.Name != "good" {
		t.Fatalf("the surviving policy was disturbed: %+v", got)
	}
}

// A torn write must leave the previous state intact rather than a truncated
// file, which is what the temp-file-and-rename is for.
func TestAPartialWriteDoesNotCorruptTheState(t *testing.T) {
	s, path := tempStore(t)
	mustSave(t, s, model.Policy{Name: "edge", Protected: []string{"203.0.113.0/24"}})

	// Simulate a crash mid-write: a leftover temp file beside the real one.
	if err := os.WriteFile(path+".tmp", []byte("{ truncated"), 0o600); err != nil {
		t.Fatalf("writing the stray temp file: %v", err)
	}
	reopened, err := Open(path)
	if err != nil {
		t.Fatalf("a stray temp file must not stop the control plane: %v", err)
	}
	if got := len(reopened.Policies()); got != 1 {
		t.Fatalf("expected the committed state intact, got %d policies", got)
	}
}

func TestACorruptStateFileIsRefused(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	if err := os.WriteFile(path, []byte("not json"), 0o600); err != nil {
		t.Fatalf("writing: %v", err)
	}
	if _, err := Open(path); err == nil {
		t.Fatal("expected a corrupt state file to be refused rather than silently ignored")
	}
}

// A file from a newer build is refused rather than half-understood.
func TestAFutureFormatIsRefused(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	raw, _ := json.Marshal(Snapshot{Version: snapshotVersion + 1})
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatalf("writing: %v", err)
	}
	_, err := Open(path)
	if err == nil {
		t.Fatal("expected a newer format to be refused")
	}
}

// An empty path keeps everything in memory, which is what the tests and the
// demo use. It must not try to touch the disk.
func TestNoPathMeansNoPersistence(t *testing.T) {
	s := New()
	if _, err := s.SavePolicy(model.Policy{Name: "edge", Protected: []string{"203.0.113.0/24"}}); err != nil {
		t.Fatalf("an in-memory store should accept writes: %v", err)
	}
	if _, err := s.IssueNodeToken("node-a"); err != nil {
		t.Fatalf("an in-memory store should issue credentials: %v", err)
	}
}

// A replica installs the primary's state wholesale.
func TestLoadReplacesStateAndWritesThrough(t *testing.T) {
	primary, _ := tempStore(t)
	mustSave(t, primary, model.Policy{Name: "edge", Protected: []string{"203.0.113.0/24"}})

	replica, replicaPath := tempStore(t)
	mustSave(t, replica, model.Policy{Name: "stale-local", Protected: []string{"198.51.100.0/24"}})

	if err := replica.Load(primary.Snapshot()); err != nil {
		t.Fatalf("Load: %v", err)
	}
	got := replica.Policies()
	if len(got) != 1 || got[0].Name != "edge" {
		t.Fatalf("expected the primary's state to replace the replica's, got %+v", got)
	}
	// It is written through, so a replica that restarts keeps what it had.
	reopened, err := Open(replicaPath)
	if err != nil {
		t.Fatalf("reopening the replica: %v", err)
	}
	if got := reopened.Policies(); len(got) != 1 || got[0].Name != "edge" {
		t.Fatalf("the followed state was not made durable, got %+v", got)
	}
}

func TestLoadRefusesAnUnknownFormat(t *testing.T) {
	s := New()
	if err := s.Load(Snapshot{Version: snapshotVersion + 1}); err == nil {
		t.Fatal("expected an unknown snapshot format to be refused")
	}
}

// Snapshots must be byte-stable, so an unchanged state does not rewrite the
// file differently on every save.
func TestSnapshotIsStable(t *testing.T) {
	s := New()
	s.SetClock(func() time.Time { return time.Unix(1_700_000_000, 0).UTC() })
	for i := 0; i < 8; i++ {
		if _, _, err := s.UpsertNode(model.Node{Name: "scrub", Region: string(rune('a' + i))}); err != nil {
			t.Fatalf("UpsertNode: %v", err)
		}
	}
	first, err := json.Marshal(s.Snapshot())
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	for i := 0; i < 20; i++ {
		again, err := json.Marshal(s.Snapshot())
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		if string(again) != string(first) {
			t.Fatal("the snapshot is not byte-stable across calls")
		}
	}
}
