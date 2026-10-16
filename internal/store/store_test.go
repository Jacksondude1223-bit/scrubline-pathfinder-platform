package store

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/Jacksondude1223-bit/scrubline-cloud-scrub/internal/ml"
	"github.com/Jacksondude1223-bit/scrubline-cloud-scrub/internal/model"
	"github.com/Jacksondude1223-bit/scrubline-cloud-scrub/internal/pipeline"
)

// Joining the id parts without a separator made ("scrub","ab") and
// ("scru","bab") hash to the same node id, so one node silently replaced
// the other.
// mustSave saves a policy and fails the test if the store could not.
func mustSave(t *testing.T, s *Store, p model.Policy) model.Policy {
	t.Helper()
	saved, err := s.SavePolicy(p)
	if err != nil {
		t.Fatalf("SavePolicy: %v", err)
	}
	return saved
}

func TestNodeIDsDoNotCollideAcrossNameRegionSplits(t *testing.T) {
	s := New()
	a, _, _ := s.UpsertNode(model.Node{Name: "scrub", Region: "ab", CapacityGbps: 10})
	b, _, _ := s.UpsertNode(model.Node{Name: "scru", Region: "bab", CapacityGbps: 10})
	if a.ID == b.ID {
		t.Fatalf("distinct nodes share id %s", a.ID)
	}
	if got := len(s.Nodes()); got != 2 {
		t.Fatalf("expected both nodes to be registered, got %d", got)
	}
}

func TestNodeIDIsStableAcrossReRegistration(t *testing.T) {
	s := New()
	first, firstIsNew, _ := s.UpsertNode(model.Node{Name: "scrub-a", Region: "iad", CapacityGbps: 10})
	second, secondIsNew, _ := s.UpsertNode(model.Node{Name: "scrub-a", Region: "iad", CapacityGbps: 20})
	if first.ID != second.ID {
		t.Fatalf("re-registering changed the node id: %s then %s", first.ID, second.ID)
	}
	if got := len(s.Nodes()); got != 1 {
		t.Fatalf("expected one node, got %d", got)
	}
	if !firstIsNew {
		t.Fatal("the first registration should report the node as new")
	}
	if secondIsNew {
		t.Fatal("re-registering an existing node must not report it as new")
	}
}

// A node that stopped answering must drop out of the live set, which is
// what withdraws it from anycast.
func TestLiveNodesExcludesStaleNodes(t *testing.T) {
	s := New()
	clock := time.Now().UTC()
	s.now = func() time.Time { return clock }

	live, _, _ := s.UpsertNode(model.Node{Name: "fresh", Region: "iad", CapacityGbps: 10})
	clock = clock.Add(NodeTTL + time.Second)
	stale := live

	if got := s.LiveNodes(); len(got) != 0 {
		t.Fatalf("expected no live nodes past the TTL, got %+v", got)
	}
	nodes := s.Nodes()
	if len(nodes) != 1 || nodes[0].Status != model.NodeStale {
		t.Fatalf("expected %s reported as stale, got %+v", stale.ID, nodes)
	}

	if ok, _ := s.Heartbeat(stale.ID); !ok {
		t.Fatal("heartbeat for a known node should succeed")
	}
	if got := s.LiveNodes(); len(got) != 1 {
		t.Fatalf("expected the node live again after a heartbeat, got %+v", got)
	}
	if got := s.Nodes()[0].Status; got != model.NodeReady {
		t.Fatalf("expected status %q, got %q", model.NodeReady, got)
	}
}

func TestHeartbeatForUnknownNodeFails(t *testing.T) {
	if ok, _ := New().Heartbeat("node-nope"); ok {
		t.Fatal("expected a heartbeat for an unknown node to fail")
	}
}

// A generated id must not land on one a client already claimed.
func TestGeneratedPolicyIDSkipsClientSuppliedIDs(t *testing.T) {
	s := New()
	claimed := mustSave(t, s, model.Policy{ID: "pol-1", Name: "claimed", Protected: []string{"203.0.113.0/24"}})
	generated := mustSave(t, s, model.Policy{Name: "generated", Protected: []string{"203.0.114.0/24"}})
	if generated.ID == claimed.ID {
		t.Fatalf("generated id %s collided with the client-supplied one", generated.ID)
	}
	if got, ok := s.Policy("pol-1"); !ok || got.Name != "claimed" {
		t.Fatalf("the claimed policy was overwritten: %+v", got)
	}
	if got := len(s.Policies()); got != 2 {
		t.Fatalf("expected two policies, got %d", got)
	}
}

func TestSavePolicyBumpsVersion(t *testing.T) {
	s := New()
	first := mustSave(t, s, model.Policy{Name: "p", Protected: []string{"203.0.113.0/24"}})
	if first.Version != 1 {
		t.Fatalf("expected version 1, got %d", first.Version)
	}
	second := mustSave(t, s, model.Policy{ID: first.ID, Name: "p", Protected: []string{"203.0.113.0/24"}})
	if second.Version != 2 {
		t.Fatalf("expected version 2, got %d", second.Version)
	}
}

func TestTrainRejectsPoisonedSamplesWithoutStoringAModel(t *testing.T) {
	s := New()
	if _, err := s.AddSamples([]ml.Sample{
		{Flow: model.Flow{Proto: "tcp", PPS: 10}, Label: 0},
		{Flow: model.Flow{Proto: "udp", PPS: -1}, Label: 1},
	}); err != nil {
		t.Fatalf("AddSamples: %v", err)
	}
	if _, err := s.Train(10, 0.2, 0.6); err == nil {
		t.Fatal("expected training on an out-of-range sample to fail")
	}
	if s.Model().Ready {
		t.Fatal("a failed fit must not publish a model")
	}
}

func TestSampleLimitIsEnforced(t *testing.T) {
	s := New()
	batch := make([]ml.Sample, MaxSamples)
	for i := range batch {
		batch[i] = ml.Sample{Flow: model.Flow{Proto: "tcp", PPS: 1}, Label: 0}
	}
	if _, err := s.AddSamples(batch); err != nil {
		t.Fatalf("the first full batch should fit: %v", err)
	}
	stored, err := s.AddSamples([]ml.Sample{{Flow: model.Flow{Proto: "tcp", PPS: 1}, Label: 0}})
	if err == nil {
		t.Fatal("expected the sample limit to be enforced")
	}
	if stored != MaxSamples {
		t.Fatalf("expected the stored count to stay at %d, got %d", MaxSamples, stored)
	}
}

// PutDeploy must not keep a reference the caller can still mutate.
func TestPutDeployCopiesPrograms(t *testing.T) {
	s := New()
	progs := map[string]*model.Program{
		"node-a": {NodeID: "node-a", PolicyID: "pol-1", Version: 1, Prefixes: []string{"203.0.113.0/24"}},
	}
	if err := s.PutDeploy("pol-1", []model.Announcement{{Prefix: "203.0.113.0/24", NodeID: "node-a", State: model.StateAnnounce}}, progs); err != nil {
		t.Fatalf("PutDeploy: %v", err)
	}
	progs["node-a"].Version = 99
	got, ok := s.Program("node-a")
	if !ok {
		t.Fatal("expected the program to be stored")
	}
	if got.Version != 1 {
		t.Fatalf("the caller mutated stored state: version is %d", got.Version)
	}
}

func TestConcurrentStoreAccessIsRaceFree(t *testing.T) {
	s := New()
	node, _, _ := s.UpsertNode(model.Node{Name: "scrub-a", Region: "iad", CapacityGbps: 10})
	done := make(chan struct{})
	for i := 0; i < 4; i++ {
		go func() {
			defer func() { done <- struct{}{} }()
			for j := 0; j < 100; j++ {
				s.Heartbeat(node.ID)
				s.Nodes()
				s.LiveNodes()
				s.Policies()
				s.Fabric()
				s.Model()
				_, _ = s.AddSamples([]ml.Sample{{Flow: model.Flow{Proto: "tcp", PPS: 1}, Label: 0}})
			}
		}()
	}
	for i := 0; i < 4; i++ {
		<-done
	}
}

// A Store built without New must not panic on its time source.
func TestZeroValueStoreClockDoesNotPanic(t *testing.T) {
	var s Store
	if s.clock().IsZero() {
		t.Fatal("expected a usable clock on a zero-value store")
	}
}

// Node IDs derive from name and region, so two scrubbers sharing both collapse
// onto one ID. That used to silently merge them.
func TestConflictingRegistrationIsRefusedWhileTheIncumbentIsLive(t *testing.T) {
	s := New()
	clock := time.Now().UTC()
	s.now = func() time.Time { return clock }

	first, isNew, err := s.UpsertNode(model.Node{Name: "scrub-a", Region: "iad", Advertise: "10.0.0.1:9091"})
	if err != nil || !isNew {
		t.Fatalf("first registration: isNew=%v err=%v", isNew, err)
	}
	if _, _, err := s.UpsertNode(model.Node{Name: "scrub-a", Region: "iad", Advertise: "10.0.0.2:9091"}); !errors.Is(err, ErrNodeConflict) {
		t.Fatalf("expected a conflict for a second live node on the same identity, got %v", err)
	}
	if got := s.Nodes()[0]; got.Advertise != "10.0.0.1:9091" {
		t.Fatalf("the incumbent was overwritten: %+v", got)
	}

	// The same node re-registering from the same address is fine.
	if _, _, err := s.UpsertNode(model.Node{Name: "scrub-a", Region: "iad", Advertise: "10.0.0.1:9091"}); err != nil {
		t.Fatalf("re-registering the incumbent: %v", err)
	}

	// Once the incumbent ages out, a replacement may take the identity: that is
	// a rescheduled container, not a duplicate.
	clock = clock.Add(NodeTTL + time.Second)
	replacement, _, err := s.UpsertNode(model.Node{Name: "scrub-a", Region: "iad", Advertise: "10.0.0.2:9091"})
	if err != nil {
		t.Fatalf("expected a stale node to be replaceable, got %v", err)
	}
	if replacement.ID != first.ID || replacement.Advertise != "10.0.0.2:9091" {
		t.Fatalf("unexpected replacement %+v", replacement)
	}
}

// A heartbeat that brings a node back from stale changes the live set, which
// has to be reported so the fabric is recompiled onto it.
func TestHeartbeatReportsRevival(t *testing.T) {
	s := New()
	clock := time.Now().UTC()
	s.now = func() time.Time { return clock }

	node, _, err := s.UpsertNode(model.Node{Name: "scrub-a", Region: "iad"})
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	if ok, revived := s.Heartbeat(node.ID); !ok || revived {
		t.Fatalf("a heartbeat inside the TTL is not a revival: ok=%v revived=%v", ok, revived)
	}
	clock = clock.Add(NodeTTL + time.Second)
	if ok, revived := s.Heartbeat(node.ID); !ok || !revived {
		t.Fatalf("expected a heartbeat past the TTL to report a revival: ok=%v revived=%v", ok, revived)
	}
	if ok, revived := s.Heartbeat(node.ID); !ok || revived {
		t.Fatalf("the following heartbeat is not a revival: ok=%v revived=%v", ok, revived)
	}
}

func TestPutDeployRecordsThePolicy(t *testing.T) {
	s := New()
	if got := s.LastDeployedPolicy(); got != "" {
		t.Fatalf("expected no deployed policy on a fresh store, got %q", got)
	}
	if err := s.PutDeploy("pol-7", nil, map[string]*model.Program{}); err != nil {
		t.Fatalf("PutDeploy: %v", err)
	}
	if got := s.LastDeployedPolicy(); got != "pol-7" {
		t.Fatalf("expected pol-7, got %q", got)
	}
}

// The zero model means "never trained", which a node cannot tell from
// "retired". Withdrawal has to be explicit or a bad model can only be removed
// by restarting every agent.
func TestWithdrawModelIsDistinguishableFromUntrained(t *testing.T) {
	s := New()
	if s.Model().Withdrawn {
		t.Fatal("an untrained model must not read as withdrawn")
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
	if !s.Model().Ready {
		t.Fatal("expected a ready model")
	}
	withdrawn, err := s.WithdrawModel()
	if err != nil {
		t.Fatalf("WithdrawModel: %v", err)
	}
	if withdrawn.Ready || !withdrawn.Withdrawn {
		t.Fatalf("expected a withdrawn, not-ready model, got %+v", withdrawn)
	}
	if got := s.Model(); got.Ready || !got.Withdrawn {
		t.Fatalf("the withdrawal was not published: %+v", got)
	}
}

// Reports are keyed to a known node, so the map stays bounded by the node set.
func TestReportsAreOnlyKeptForKnownNodes(t *testing.T) {
	s := New()
	node, _, err := s.UpsertNode(model.Node{Name: "scrub-a", Region: "iad"})
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	if ok := s.PutReport("node-nope", pipeline.Stats{Decisions: 5}); ok {
		t.Fatal("a report for an unknown node should be dropped")
	}
	if got := len(s.Reports()); got != 0 {
		t.Fatalf("expected no reports, got %d", got)
	}
	if ok := s.PutReport(node.ID, pipeline.Stats{Decisions: 5}); !ok {
		t.Fatal("a report for a known node should be kept")
	}
	reports := s.Reports()
	if len(reports) != 1 {
		t.Fatalf("expected one report, got %d", len(reports))
	}
	// Identity comes from the node record, not from the reporter.
	if reports[0].NodeID != node.ID || reports[0].Name != "scrub-a" || reports[0].Region != "iad" {
		t.Fatalf("unexpected report identity %+v", reports[0])
	}
	if reports[0].ReportedAt.IsZero() {
		t.Fatal("expected the report to be stamped")
	}

	// A later report replaces the previous one rather than accumulating.
	s.PutReport(node.ID, pipeline.Stats{Decisions: 9})
	if got := s.Reports(); len(got) != 1 || got[0].Stats.Decisions != 9 {
		t.Fatalf("expected the report to be replaced, got %+v", got)
	}
}

// A node credential is handed out once and only its hash is kept, so a dump
// of the store cannot be replayed against the control plane.
func TestNodeTokensAreStoredHashed(t *testing.T) {
	s := New()
	node, _, err := s.UpsertNode(model.Node{Name: "scrub-a", Region: "iad"})
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	token, err := s.IssueNodeToken(node.ID)
	if err != nil {
		t.Fatalf("IssueNodeToken: %v", err)
	}
	if len(token) != 64 {
		t.Fatalf("expected a 256-bit hex credential, got %d characters", len(token))
	}
	for _, held := range s.nodeTokens {
		if held == token {
			t.Fatal("the plaintext credential was stored")
		}
	}
	if got, ok := s.NodeForToken(token); !ok || got != node.ID {
		t.Fatalf("expected the credential to resolve to %s, got %q (%v)", node.ID, got, ok)
	}
}

func TestUnknownAndEmptyTokensResolveToNothing(t *testing.T) {
	s := New()
	for _, token := range []string{"", "nope", "0000000000000000000000000000000000000000000000000000000000000000"} {
		if _, ok := s.NodeForToken(token); ok {
			t.Fatalf("token %q should not resolve", token)
		}
	}
}

// Two nodes must never share a credential.
func TestIssuedTokensAreDistinct(t *testing.T) {
	s := New()
	seen := map[string]bool{}
	for i := 0; i < 50; i++ {
		token, err := s.IssueNodeToken(fmt.Sprintf("node-%d", i))
		if err != nil {
			t.Fatalf("IssueNodeToken: %v", err)
		}
		if seen[token] {
			t.Fatalf("credential %s was issued twice", token)
		}
		seen[token] = true
	}
}

// Re-issuing rotates: the old credential stops working the moment a new one
// is handed out, so a restart does not leave a second valid key behind.
func TestReissuingRotatesTheCredential(t *testing.T) {
	s := New()
	first, err := s.IssueNodeToken("node-a")
	if err != nil {
		t.Fatalf("IssueNodeToken: %v", err)
	}
	second, err := s.IssueNodeToken("node-a")
	if err != nil {
		t.Fatalf("IssueNodeToken: %v", err)
	}
	if first == second {
		t.Fatal("re-issuing returned the same credential")
	}
	if _, ok := s.NodeForToken(first); ok {
		t.Fatal("the superseded credential still works")
	}
	if got, ok := s.NodeForToken(second); !ok || got != "node-a" {
		t.Fatalf("the new credential does not resolve: %q %v", got, ok)
	}
	// Rotation must not leave the old hash behind in the reverse index.
	if len(s.tokenNodes) != 1 {
		t.Fatalf("expected one live credential, got %d", len(s.tokenNodes))
	}
}

func TestRevokingACredentialStopsIt(t *testing.T) {
	s := New()
	token, err := s.IssueNodeToken("node-a")
	if err != nil {
		t.Fatalf("IssueNodeToken: %v", err)
	}
	if revoked, err := s.RevokeNodeToken("node-a"); err != nil || !revoked {
		t.Fatalf("expected the revocation to find the credential: %v %v", revoked, err)
	}
	if _, ok := s.NodeForToken(token); ok {
		t.Fatal("a revoked credential still works")
	}
	if revoked, err := s.RevokeNodeToken("node-a"); err != nil || revoked {
		t.Fatalf("revoking twice should report nothing to revoke: %v %v", revoked, err)
	}
}
