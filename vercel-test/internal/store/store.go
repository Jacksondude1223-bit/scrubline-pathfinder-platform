package store

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/Jacksondude1223-bit/scrubline-cloud-scrub/internal/ml"
	"github.com/Jacksondude1223-bit/scrubline-cloud-scrub/internal/model"
	"github.com/Jacksondude1223-bit/scrubline-cloud-scrub/internal/pipeline"
	"github.com/Jacksondude1223-bit/scrubline-cloud-scrub/internal/telemetry"
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

// ErrNodeConflict is returned when a registration would take over the identity
// of a different node that is still live. Node IDs derive from name and region,
// so two scrubbers sharing both used to silently overwrite each other.
var ErrNodeConflict = errors.New("a different live node is already registered under this name and region")

type Store struct {
	mu       sync.Mutex
	nodes    map[string]*model.Node
	policies map[string]*model.Policy
	programs map[string]*model.Program
	plan     []model.Announcement
	samples  []ml.Sample
	model    ml.Model
	seq      int
	// lastPolicyID is the policy of the most recent deploy. The fabric is
	// recompiled against it when the live node set changes, so a node that
	// joins or recovers after a deploy is not left without a program.
	lastPolicyID string
	// reports holds the datapath counters each node last sent with its
	// heartbeat, keyed by node ID so the map stays bounded by the node set.
	reports map[string]telemetry.Report
	// tunnels holds what each node last reported about its return paths.
	// Like reports it is derived and not durable: a tunnel's state from
	// before a restart says nothing about whether it carries traffic now.
	tunnels map[string][]model.TunnelStatus
	// nodeTokens maps a node to the hash of its current credential, and
	// tokenNodes maps back from the hash. Only hashes are kept: a dump of
	// this store must not hand anyone a working credential.
	nodeTokens map[string]string
	tokenNodes map[string]string
	// tenants are the customers whose traffic is being scrubbed, with their
	// credentials held the same way the nodes' are.
	tenants      map[string]*model.Tenant
	tenantTokens map[string]string
	tokenTenants map[string]string
	// path is where durable state is written. Empty keeps everything in
	// memory, which is what the tests and the single-shot demo use.
	path string
	// now is swapped out in tests; production always uses the wall clock.
	now func() time.Time
}

// sortNodes and sortPolicies keep a snapshot byte-stable, so an unchanged
// state does not rewrite the file differently each time.
func sortNodes(nodes []model.Node) {
	sort.Slice(nodes, func(i, j int) bool { return nodes[i].ID < nodes[j].ID })
}

func sortPolicies(policies []model.Policy) {
	sort.Slice(policies, func(i, j int) bool { return policies[i].ID < policies[j].ID })
}

func sortTenants(tenants []model.Tenant) {
	sort.Slice(tenants, func(i, j int) bool {
		if tenants[i].Name != tenants[j].Name {
			return tenants[i].Name < tenants[j].Name
		}
		return tenants[i].ID < tenants[j].ID
	})
}

func New() *Store {
	return &Store{
		nodes:      map[string]*model.Node{},
		policies:   map[string]*model.Policy{},
		programs:   map[string]*model.Program{},
		reports:    map[string]telemetry.Report{},
		tunnels:    map[string][]model.TunnelStatus{},
		nodeTokens: map[string]string{},
		tokenNodes: map[string]string{},

		tenants:      map[string]*model.Tenant{},
		tenantTokens: map[string]string{},
		tokenTenants: map[string]string{},

		now: func() time.Time { return time.Now().UTC() },
	}
}

// SetClock replaces the store's time source. It exists so tests outside this
// package can age nodes past their TTL without sleeping.
func (s *Store) SetClock(now func() time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.now = now
}

// clock reads the store's time source, tolerating a zero-value Store.
func (s *Store) clock() time.Time {
	if s.now == nil {
		return time.Now().UTC()
	}
	return s.now()
}

// UpsertNode registers or refreshes a node. It reports whether the node is new
// to the fabric, which is what triggers a recompile.
func (s *Store) UpsertNode(n model.Node) (model.Node, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if n.ID == "" {
		n.ID = id("node", n.Name, n.Region)
	}
	if n.Backends == nil {
		n.Backends = []model.Stage{model.StageASIC, model.StageFPGA, model.StageZC}
	}
	now := s.clock()
	prev, existed := s.nodes[n.ID]
	if existed {
		// Two scrubbers under the same name and region collapse onto one ID.
		// Refuse while the incumbent is still live rather than merging them;
		// once it has aged out, a replacement is free to take the identity.
		stillLive := now.Sub(prev.LastSeen) <= NodeTTL
		if stillLive && prev.Advertise != "" && n.Advertise != "" && prev.Advertise != n.Advertise {
			return model.Node{}, false, fmt.Errorf("%w: %s is advertised by %s", ErrNodeConflict, n.ID, prev.Advertise)
		}
	}
	n.LastSeen = now
	n.Status = model.NodeReady
	cp := n
	s.nodes[n.ID] = &cp
	if err := s.persistLocked(); err != nil {
		// Roll back rather than report a registration the control plane
		// cannot remember across a restart.
		if existed {
			s.nodes[n.ID] = prev
		} else {
			delete(s.nodes, n.ID)
		}
		return model.Node{}, false, err
	}
	return cp, !existed, nil
}

// Heartbeat refreshes a node's liveness. It reports whether the node was known,
// and whether this heartbeat brought it back from stale, which changes the live
// set and so has to trigger a recompile.
func (s *Store) Heartbeat(id string) (ok, revived bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	n, found := s.nodes[id]
	if !found {
		return false, false
	}
	now := s.clock()
	revived = now.Sub(n.LastSeen) > NodeTTL
	n.LastSeen = now
	n.Status = model.NodeReady
	return true, revived
}

// Nodes lists every registered node with its status refreshed against NodeTTL.
func (s *Store) Nodes() []model.Node {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.snapshot(false)
}

// LiveNodes lists only the nodes that have heartbeated within NodeTTL. Prefix
// The announcement plan uses this: a node past its TTL is withdrawn from
// anycast so its share of the traffic moves to the nodes still answering.
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

func (s *Store) SavePolicy(p model.Policy) (model.Policy, error) {
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
	previous, existed := s.policies[p.ID]
	s.policies[p.ID] = &cp
	if err := s.persistLocked(); err != nil {
		if existed {
			s.policies[p.ID] = previous
		} else {
			delete(s.policies, p.ID)
		}
		return model.Policy{}, err
	}
	return cp, nil
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

func (s *Store) PutDeploy(policyID string, plan []model.Announcement, programs map[string]*model.Program) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	// Only the deployed policy is durable; the plan and the programs are
	// recompiled from it. A recompile that does not change which policy is
	// deployed therefore does not touch the disk, which matters because
	// membership churn recompiles often.
	changed := s.lastPolicyID != policyID
	s.lastPolicyID = policyID
	s.plan = append([]model.Announcement(nil), plan...)
	// Copy the caller's map so a later mutation of it cannot reach into the store.
	s.programs = make(map[string]*model.Program, len(programs))
	for k, v := range programs {
		cp := *v
		s.programs[k] = &cp
	}
	if !changed {
		return nil
	}
	return s.persistLocked()
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

// Fabric returns the BGP announcement plan and the compiled programs.
func (s *Store) Fabric() ([]model.Announcement, []model.Program) {
	s.mu.Lock()
	defer s.mu.Unlock()
	progs := make([]model.Program, 0, len(s.programs))
	for _, p := range s.programs {
		progs = append(progs, *p)
	}
	sort.Slice(progs, func(i, j int) bool { return progs[i].NodeID < progs[j].NodeID })
	return append([]model.Announcement(nil), s.plan...), progs
}

// AddSamples appends a labeled batch and reports the new total.
func (s *Store) AddSamples(in []ml.Sample) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.samples)+len(in) > MaxSamples {
		return len(s.samples), ErrSampleLimit
	}
	before := len(s.samples)
	s.samples = append(s.samples, in...)
	if err := s.persistLocked(); err != nil {
		s.samples = s.samples[:before]
		return before, err
	}
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
	previous := s.model
	s.model = m
	if err := s.persistLocked(); err != nil {
		s.model = previous
		return ml.Model{}, err
	}
	return m, nil
}

// PutReport records a node's datapath counters. A report for a node the
// control plane does not know is dropped: without that the map would grow on
// anything that can reach the endpoint.
func (s *Store) PutReport(nodeID string, stats pipeline.Stats) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	n, ok := s.nodes[nodeID]
	if !ok {
		return false
	}
	if s.reports == nil {
		s.reports = map[string]telemetry.Report{}
	}
	s.reports[nodeID] = telemetry.Report{
		NodeID:     nodeID,
		Name:       n.Name,
		Region:     n.Region,
		Stats:      stats,
		ReportedAt: s.clock(),
	}
	return true
}

// PutTunnelStatus records what a node says about its return paths. Like a
// counter report, one from a node the control plane does not know is dropped:
// without that the map would grow on anything that can reach the endpoint.
func (s *Store) PutTunnelStatus(nodeID string, statuses []model.TunnelStatus) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.nodes[nodeID]; !ok {
		return false
	}
	if s.tunnels == nil {
		s.tunnels = map[string][]model.TunnelStatus{}
	}
	now := s.clock()
	cp := make([]model.TunnelStatus, 0, len(statuses))
	for _, st := range statuses {
		// The control plane stamps the time, not the node: the fleet's
		// clocks are not synchronised, and a node with a wrong one would
		// otherwise decide how old its own report looks.
		st.ReportedAt = now
		cp = append(cp, st)
	}
	sort.Slice(cp, func(i, j int) bool { return cp[i].TunnelID < cp[j].TunnelID })
	s.tunnels[nodeID] = cp
	return true
}

// TunnelStatus returns one node's last report about its return paths.
func (s *Store) TunnelStatus(nodeID string) []model.TunnelStatus {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]model.TunnelStatus(nil), s.tunnels[nodeID]...)
}

// TunnelHealth is the fleet's return-path state, keyed by node and tunnel.
// It is what the compiler reads to decide whether a node should still be
// attracting a prefix it may not be able to deliver.
func (s *Store) TunnelHealth() map[string]map[string]string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make(map[string]map[string]string, len(s.tunnels))
	for nodeID, statuses := range s.tunnels {
		byTunnel := make(map[string]string, len(statuses))
		for _, st := range statuses {
			byTunnel[st.TunnelID] = st.State
		}
		out[nodeID] = byTunnel
	}
	return out
}

// Report returns one node's last reported counters.
func (s *Store) Report(nodeID string) (telemetry.Report, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.reports[nodeID]
	return r, ok
}

// Reports lists the datapath counters collected from the fleet, oldest node ID
// first so a scrape is stable.
func (s *Store) Reports() []telemetry.Report {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]telemetry.Report, 0, len(s.reports))
	for _, r := range s.reports {
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].NodeID < out[j].NodeID })
	return out
}

// IssueNodeToken mints a fresh credential for a node and returns it. The
// plaintext is returned exactly once, at enrollment; only its hash is kept.
//
// Issuing replaces whatever the node had, so a restart rotates the credential
// and an old one stops working the moment a new one is handed out.
func (s *Store) IssueNodeToken(nodeID string) (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("generating a node credential: %w", err)
	}
	token := hex.EncodeToString(raw)

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.nodeTokens == nil {
		s.nodeTokens = map[string]string{}
		s.tokenNodes = map[string]string{}
	}
	if previous, ok := s.nodeTokens[nodeID]; ok {
		delete(s.tokenNodes, previous)
	}
	sum := tokenHash(token)
	s.nodeTokens[nodeID] = sum
	s.tokenNodes[sum] = nodeID
	if err := s.persistLocked(); err != nil {
		// A credential the control plane cannot remember is worse than none:
		// the agent would hold a key that stops working at the next restart.
		delete(s.nodeTokens, nodeID)
		delete(s.tokenNodes, sum)
		return "", err
	}
	return token, nil
}

// NodeForToken resolves a presented credential to the node that holds it.
//
// The lookup is by hash, so the store never compares against a live secret and
// a timing signal would only reveal something about the hash of a value the
// caller already knows.
func (s *Store) NodeForToken(token string) (string, bool) {
	if token == "" {
		return "", false
	}
	sum := tokenHash(token)
	s.mu.Lock()
	defer s.mu.Unlock()
	id, ok := s.tokenNodes[sum]
	return id, ok
}

// RevokeNodeToken drops a node's credential.
func (s *Store) RevokeNodeToken(nodeID string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sum, ok := s.nodeTokens[nodeID]
	if !ok {
		return false, nil
	}
	delete(s.nodeTokens, nodeID)
	delete(s.tokenNodes, sum)
	if err := s.persistLocked(); err != nil {
		s.nodeTokens[nodeID] = sum
		s.tokenNodes[sum] = nodeID
		return false, err
	}
	return true, nil
}

// ErrUnknownTenant is returned when a tenant is named that does not exist.
var ErrUnknownTenant = errors.New("unknown tenant")

// SaveTenant creates or replaces a customer record.
func (s *Store) SaveTenant(t model.Tenant) (model.Tenant, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.tenants == nil {
		s.tenants = map[string]*model.Tenant{}
	}
	now := s.clock()
	if t.ID == "" {
		// Derived from the name, so re-sending the same customer updates
		// them rather than quietly creating a second record holding half
		// their prefixes.
		t.ID = id("ten", t.Name)
	}
	previous, existed := s.tenants[t.ID]
	if existed {
		t.CreatedAt = previous.CreatedAt
	} else {
		t.CreatedAt = now
	}
	t.UpdatedAt = now
	cp := t
	s.tenants[t.ID] = &cp
	if err := s.persistLocked(); err != nil {
		if existed {
			s.tenants[t.ID] = previous
		} else {
			delete(s.tenants, t.ID)
		}
		return model.Tenant{}, err
	}
	return cp, nil
}

// Tenants lists the customers, by name.
func (s *Store) Tenants() []model.Tenant {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]model.Tenant, 0, len(s.tenants))
	for _, t := range s.tenants {
		out = append(out, *t)
	}
	sortTenants(out)
	return out
}

// Tenant returns one customer.
func (s *Store) Tenant(id string) (model.Tenant, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.tenants[id]
	if !ok {
		return model.Tenant{}, false
	}
	return *t, true
}

// DeleteTenant removes a customer and the credential they hold. Both go
// together: a credential that outlived its tenant would authenticate to an
// empty entitlement rather than to nothing.
func (s *Store) DeleteTenant(id string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	previous, ok := s.tenants[id]
	if !ok {
		return false, nil
	}
	hash, hadToken := s.tenantTokens[id]
	delete(s.tenants, id)
	delete(s.tenantTokens, id)
	delete(s.tokenTenants, hash)
	if err := s.persistLocked(); err != nil {
		s.tenants[id] = previous
		if hadToken {
			s.tenantTokens[id] = hash
			s.tokenTenants[hash] = id
		}
		return false, err
	}
	return true, nil
}

// IssueTenantToken mints a credential for a customer and returns it. Like a
// node's, the plaintext is returned exactly once and only its hash is kept,
// so issuing again rotates it and the previous one stops working.
func (s *Store) IssueTenantToken(tenantID string) (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("generating a tenant credential: %w", err)
	}
	token := hex.EncodeToString(raw)

	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.tenants[tenantID]; !ok {
		return "", ErrUnknownTenant
	}
	if s.tenantTokens == nil {
		s.tenantTokens = map[string]string{}
		s.tokenTenants = map[string]string{}
	}
	if previous, ok := s.tenantTokens[tenantID]; ok {
		delete(s.tokenTenants, previous)
	}
	sum := tokenHash(token)
	s.tenantTokens[tenantID] = sum
	s.tokenTenants[sum] = tenantID
	if err := s.persistLocked(); err != nil {
		delete(s.tenantTokens, tenantID)
		delete(s.tokenTenants, sum)
		return "", err
	}
	return token, nil
}

// TenantForToken resolves a presented credential to the customer holding it.
// The lookup is by hash, so the store never compares against a live secret.
func (s *Store) TenantForToken(token string) (model.Tenant, bool) {
	if token == "" {
		return model.Tenant{}, false
	}
	sum := tokenHash(token)
	s.mu.Lock()
	defer s.mu.Unlock()
	id, ok := s.tokenTenants[sum]
	if !ok {
		return model.Tenant{}, false
	}
	t, ok := s.tenants[id]
	if !ok {
		return model.Tenant{}, false
	}
	return *t, true
}

func tokenHash(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// LastDeployedPolicy reports the policy the fabric was last compiled from, or
// "" when nothing has been deployed yet.
func (s *Store) LastDeployedPolicy() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.lastPolicyID
}

// WithdrawModel retires the published model. The zero model means "never
// trained", which a node cannot tell from "retired", so the withdrawal is
// explicit and nodes clear their copy when they see it.
func (s *Store) WithdrawModel() (ml.Model, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	previous := s.model
	s.model = ml.Model{Withdrawn: true}
	if err := s.persistLocked(); err != nil {
		s.model = previous
		return ml.Model{}, err
	}
	return s.model, nil
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
