package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Jacksondude1223-bit/scrubline-cloud-scrub/internal/steering"
	"github.com/Jacksondude1223-bit/scrubline-cloud-scrub/internal/store"
)

const testToken = "test-token"

func newTestServer() http.Handler {
	return (&Server{Token: testToken, Store: store.New()}).Handler()
}

func do(t *testing.T, h http.Handler, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	var r io.Reader
	if body != "" {
		r = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, path, r)
	req.Header.Set("Authorization", "Bearer "+testToken)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// Every response must carry a body. A 200 with zero bytes is how the NaN model
// bug surfaced: callers saw success and parsed nothing.
func requireJSON(t *testing.T, rec *httptest.ResponseRecorder, wantCode int) map[string]any {
	t.Helper()
	if rec.Code != wantCode {
		t.Fatalf("expected status %d, got %d: %s", wantCode, rec.Code, rec.Body.String())
	}
	if rec.Body.Len() == 0 {
		t.Fatalf("status %d came back with an empty body", rec.Code)
	}
	var out map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("response is not JSON (%v): %q", err, rec.Body.String())
	}
	return out
}

func TestAuthRejectsBadAndMissingTokens(t *testing.T) {
	h := newTestServer()
	for _, header := range []string{"", "Bearer wrong", "wrong", "Basic " + testToken, "Bearer"} {
		req := httptest.NewRequest(http.MethodGet, "/v1/nodes", nil)
		if header != "" {
			req.Header.Set("Authorization", header)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("header %q: expected 401, got %d", header, rec.Code)
		}
	}
}

func TestAuthAcceptsALowercaseScheme(t *testing.T) {
	h := newTestServer()
	req := httptest.NewRequest(http.MethodGet, "/v1/nodes", nil)
	req.Header.Set("Authorization", "bearer "+testToken)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("the bearer scheme is case-insensitive per RFC 7235; got %d", rec.Code)
	}
}

// An empty token used to disable authentication altogether.
func TestEmptyServerTokenFailsClosed(t *testing.T) {
	h := (&Server{Token: "", Store: store.New()}).Handler()
	req := httptest.NewRequest(http.MethodGet, "/v1/nodes", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected an empty token to deny every request, got %d", rec.Code)
	}
}

// One negative pps used to poison the model with NaN, after which ml/model,
// ml/score, fabric and decide all answered 200 with an empty body forever.
func TestOutOfRangeSampleIsRejectedAndEndpointsStayHealthy(t *testing.T) {
	h := newTestServer()
	rec := do(t, h, http.MethodPost, "/v1/ml/samples",
		`{"samples":[{"label":0,"flow":{"proto":"tcp","pps":40,"dport":443}},{"label":1,"flow":{"proto":"udp","pps":-5,"dport":53}}]}`)
	body := requireJSON(t, rec, http.StatusBadRequest)
	if !strings.Contains(fmt.Sprint(body["error"]), "samples[1]") {
		t.Fatalf("expected the offending index to be named, got %v", body["error"])
	}
	for _, path := range []string{"/v1/ml/model", "/v1/fabric", "/v1/ml/samples"} {
		requireJSON(t, do(t, h, http.MethodGet, path, ""), http.StatusOK)
	}
	requireJSON(t, do(t, h, http.MethodPost, "/v1/ml/score", `{"proto":"tcp","pps":500000,"dport":443}`), http.StatusOK)
}

func TestBadLabelIsRejected(t *testing.T) {
	h := newTestServer()
	rec := do(t, h, http.MethodPost, "/v1/ml/samples", `{"samples":[{"label":99,"flow":{"proto":"tcp","pps":1,"dport":1}}]}`)
	body := requireJSON(t, rec, http.StatusBadRequest)
	if !strings.Contains(fmt.Sprint(body["error"]), "label") {
		t.Fatalf("expected a label error, got %v", body["error"])
	}
}

func TestScoreRejectsAnOutOfRangeFlow(t *testing.T) {
	h := newTestServer()
	requireJSON(t, do(t, h, http.MethodPost, "/v1/ml/score", `{"proto":"tcp","pps":-1}`), http.StatusBadRequest)
}

func TestTrainOnGoodSamplesPublishesAModel(t *testing.T) {
	h := newTestServer()
	var samples []string
	for i := 0; i < 10; i++ {
		samples = append(samples,
			fmt.Sprintf(`{"label":0,"flow":{"proto":"tcp","pps":40,"dport":443,"sport":%d}}`, 40000+i),
			fmt.Sprintf(`{"label":1,"flow":{"proto":"tcp","flags":"syn","pps":200000,"dport":443,"sport":%d}}`, 1000+i))
	}
	requireJSON(t, do(t, h, http.MethodPost, "/v1/ml/samples", `{"samples":[`+strings.Join(samples, ",")+`]}`), http.StatusOK)
	trained := requireJSON(t, do(t, h, http.MethodPost, "/v1/ml/train", `{"epochs":300,"lr":0.2,"threshold":0.65}`), http.StatusOK)
	if trained["ready"] != true {
		t.Fatalf("expected a ready model, got %v", trained)
	}
	scored := requireJSON(t, do(t, h, http.MethodPost, "/v1/ml/score", `{"proto":"tcp","flags":"syn","pps":250000,"dport":443,"sport":9}`), http.StatusOK)
	if scored["label"] != float64(1) {
		t.Fatalf("expected a syn flood to score as an attack, got %v", scored)
	}
}

func TestTrainNeedsTwoSamples(t *testing.T) {
	h := newTestServer()
	requireJSON(t, do(t, h, http.MethodPost, "/v1/ml/samples", `{"samples":[{"label":0,"flow":{"proto":"tcp","pps":1}}]}`), http.StatusOK)
	requireJSON(t, do(t, h, http.MethodPost, "/v1/ml/train", `{}`), http.StatusBadRequest)
}

func TestTrainRejectsAMalformedBody(t *testing.T) {
	h := newTestServer()
	requireJSON(t, do(t, h, http.MethodPost, "/v1/ml/train", `{"epochs":`), http.StatusBadRequest)
}

// Unparseable CIDRs never match, so the rule silently fails open.
func TestPolicyValidationRejectsBadCIDRs(t *testing.T) {
	h := newTestServer()
	for _, body := range []string{
		`{"name":"p","protected":["203.0.113.0/99"]}`,
		`{"name":"p","protected":["not-an-ip"]}`,
		`{"name":"p","protected":["203.0.113.0/24"],"rules":[{"id":"r","stage":"asic","action":"drop","match":{"src_cidr":"garbage/8"}}]}`,
		`{"name":"p","protected":["203.0.113.0/24"],"rules":[{"id":"r","stage":"asic","action":"drop","match":{"dst_cidr":"10.0.0.0/64"}}]}`,
	} {
		requireJSON(t, do(t, h, http.MethodPost, "/v1/policies", body), http.StatusBadRequest)
	}
}

func TestPolicyValidationRejectsUnusableRules(t *testing.T) {
	h := newTestServer()
	cases := map[string]string{
		"unknown stage":      `{"name":"p","protected":["203.0.113.0/24"],"rules":[{"id":"r","stage":"xdp","action":"drop"}]}`,
		"unknown action":     `{"name":"p","protected":["203.0.113.0/24"],"rules":[{"id":"r","stage":"asic","action":"mangle"}]}`,
		"asic cannot meter":  `{"name":"p","protected":["203.0.113.0/24"],"rules":[{"id":"r","stage":"asic","action":"rate_limit","pps":100}]}`,
		"limit without pps":  `{"name":"p","protected":["203.0.113.0/24"],"rules":[{"id":"r","stage":"fpga","action":"rate_limit"}]}`,
		"negative pps":       `{"name":"p","protected":["203.0.113.0/24"],"rules":[{"id":"r","stage":"fpga","action":"rate_limit","pps":-1}]}`,
		"missing rule id":    `{"name":"p","protected":["203.0.113.0/24"],"rules":[{"stage":"asic","action":"drop"}]}`,
		"pipe in rule id":    `{"name":"p","protected":["203.0.113.0/24"],"rules":[{"id":"a|b","stage":"asic","action":"drop"}]}`,
		"duplicate rule ids": `{"name":"p","protected":["203.0.113.0/24"],"rules":[{"id":"r","stage":"asic","action":"drop"},{"id":"r","stage":"fpga","action":"drop"}]}`,
		"dport out of range": `{"name":"p","protected":["203.0.113.0/24"],"rules":[{"id":"r","stage":"asic","action":"drop","match":{"dport":70000}}]}`,
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			requireJSON(t, do(t, h, http.MethodPost, "/v1/policies", body), http.StatusBadRequest)
		})
	}
}

func TestNodeValidationRejectsNegativeCapacity(t *testing.T) {
	h := newTestServer()
	requireJSON(t, do(t, h, http.MethodPost, "/v1/nodes/register", `{"name":"evil","region":"x","capacity_gbps":-1}`), http.StatusBadRequest)
}

func TestNodeValidationRejectsUnknownBackend(t *testing.T) {
	h := newTestServer()
	requireJSON(t, do(t, h, http.MethodPost, "/v1/nodes/register", `{"name":"n","region":"x","backends":["xdp"]}`), http.StatusBadRequest)
}

func TestDeployRequiresALiveNode(t *testing.T) {
	h := newTestServer()
	policy := requireJSON(t, do(t, h, http.MethodPost, "/v1/policies", `{"name":"p","protected":["203.0.113.0/24"]}`), http.StatusOK)
	id := policy["id"].(string)
	requireJSON(t, do(t, h, http.MethodPost, "/v1/policies/"+id+"/deploy", ""), http.StatusConflict)
}

func TestDeployUnknownPolicy(t *testing.T) {
	h := newTestServer()
	requireJSON(t, do(t, h, http.MethodPost, "/v1/policies/pol-nope/deploy", ""), http.StatusNotFound)
}

func TestFullDeployAndDecideFlow(t *testing.T) {
	h := newTestServer()
	node := requireJSON(t, do(t, h, http.MethodPost, "/v1/nodes/register", `{"name":"scrub-a","region":"iad","capacity_gbps":100}`), http.StatusOK)
	nodeID := node["id"].(string)

	policyBody := `{"name":"game-edge","protected":["203.0.113.0/24"],"rules":[
		{"id":"allow-ops","stage":"asic","action":"permit","priority":10,"match":{"src_cidr":"192.0.2.7/32"}},
		{"id":"tcam-flood","stage":"asic","action":"drop","priority":100,"match":{"src_cidr":"198.51.100.0/24","dst_cidr":"203.0.113.0/24"}},
		{"id":"fpga-meter","stage":"fpga","action":"rate_limit","priority":300,"pps":1000,"match":{"dst_cidr":"203.0.113.0/24","proto":"udp"}}]}`
	policy := requireJSON(t, do(t, h, http.MethodPost, "/v1/policies", policyBody), http.StatusOK)
	id := policy["id"].(string)

	deployed := requireJSON(t, do(t, h, http.MethodPost, "/v1/policies/"+id+"/deploy", ""), http.StatusOK)
	if deployed["nodes"] != float64(1) {
		t.Fatalf("expected one programmed node, got %v", deployed["nodes"])
	}
	requireJSON(t, do(t, h, http.MethodGet, "/v1/nodes/"+nodeID+"/program", ""), http.StatusOK)

	// The allow-list entry wins over the drop behind it.
	allowed := requireJSON(t, do(t, h, http.MethodPost, "/v1/decide",
		fmt.Sprintf(`{"node_id":%q,"flow":{"src_ip":"192.0.2.7","dst_ip":"203.0.113.10","proto":"tcp","dport":443,"pps":10}}`, nodeID)), http.StatusOK)
	if allowed["action"] != "permit" || allowed["rule_id"] != "allow-ops" {
		t.Fatalf("expected the permit rule to decide, got %v", allowed)
	}
	dropped := requireJSON(t, do(t, h, http.MethodPost, "/v1/decide",
		fmt.Sprintf(`{"node_id":%q,"flow":{"src_ip":"198.51.100.4","dst_ip":"203.0.113.10","proto":"tcp","dport":443,"pps":10}}`, nodeID)), http.StatusOK)
	if dropped["action"] != "drop" || dropped["stage"] != "asic" {
		t.Fatalf("expected a TCAM drop, got %v", dropped)
	}
	metered := requireJSON(t, do(t, h, http.MethodPost, "/v1/decide",
		fmt.Sprintf(`{"node_id":%q,"flow":{"src_ip":"192.0.2.9","dst_ip":"203.0.113.10","proto":"udp","dport":19132,"pps":5000}}`, nodeID)), http.StatusOK)
	if metered["action"] != "drop" || metered["stage"] != "fpga" {
		t.Fatalf("expected an FPGA meter drop, got %v", metered)
	}
}

func TestHeartbeatAndProgramPathsAreExact(t *testing.T) {
	h := newTestServer()
	node := requireJSON(t, do(t, h, http.MethodPost, "/v1/nodes/register", `{"name":"scrub-a","region":"iad","capacity_gbps":10}`), http.StatusOK)
	id := node["id"].(string)
	requireJSON(t, do(t, h, http.MethodPost, "/v1/nodes/"+id+"/heartbeat", ""), http.StatusOK)
	requireJSON(t, do(t, h, http.MethodPost, "/v1/nodes/nope/heartbeat", ""), http.StatusNotFound)
	// A nested or missing id must not be read as a node id. ServeMux collapses a
	// doubled slash with a redirect before the route is reached, so the remaining
	// shapes are what the router itself has to reject.
	requireJSON(t, do(t, h, http.MethodGet, "/v1/nodes/a/b/program", ""), http.StatusNotFound)
	requireJSON(t, do(t, h, http.MethodPost, "/v1/nodes/heartbeat", ""), http.StatusNotFound)
	requireJSON(t, do(t, h, http.MethodGet, "/v1/nodes/program", ""), http.StatusNotFound)
	// A deploy path with no policy id must not be read as one either.
	requireJSON(t, do(t, h, http.MethodPost, "/v1/policies/deploy", ""), http.StatusNotFound)
}

func TestDecideForUnknownNode(t *testing.T) {
	h := newTestServer()
	requireJSON(t, do(t, h, http.MethodPost, "/v1/decide", `{"node_id":"node-nope","flow":{"dst_ip":"203.0.113.1"}}`), http.StatusNotFound)
}

func TestHealthNeedsNoToken(t *testing.T) {
	rec := httptest.NewRecorder()
	newTestServer().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/health", nil))
	if rec.Code != http.StatusOK || rec.Body.Len() == 0 {
		t.Fatalf("expected an unauthenticated health body, got %d %q", rec.Code, rec.Body.String())
	}
}

func TestUnknownRouteIsJSON(t *testing.T) {
	h := newTestServer()
	requireJSON(t, do(t, h, http.MethodGet, "/v1/nope", ""), http.StatusNotFound)
	requireJSON(t, do(t, h, http.MethodDelete, "/v1/nodes", ""), http.StatusNotFound)
}

// writeJSON must not commit a 200 it cannot fill.
func TestWriteJSONReportsEncodingFailure(t *testing.T) {
	rec := httptest.NewRecorder()
	writeJSON(rec, http.StatusOK, map[string]any{"bad": func() {}})
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500 when encoding fails, got %d", rec.Code)
	}
	var out map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("expected a JSON error body, got %q", rec.Body.String())
	}
}

func TestBodyLimitIsEnforced(t *testing.T) {
	h := newTestServer()
	var buf bytes.Buffer
	buf.WriteString(`{"name":"big","protected":["203.0.113.0/24"],"pad":"`)
	buf.WriteString(strings.Repeat("x", maxBody))
	buf.WriteString(`"}`)
	rec := do(t, h, http.MethodPost, "/v1/policies", buf.String())
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected an oversized body to be rejected, got %d", rec.Code)
	}
}

// newTestAPI returns the server alongside its handler, for tests that need to
// reach past the HTTP surface.
func newTestAPI() (*Server, http.Handler) {
	s := &Server{Token: testToken, Store: store.New()}
	return s, s.Handler()
}

// newTestAPIWithClock returns a server whose node liveness can be aged without
// sleeping. advance moves the clock the store stamps heartbeats against.
func newTestAPIWithClock() (s *Server, h http.Handler, advance func(time.Duration)) {
	st := store.New()
	var mu sync.Mutex
	now := time.Now().UTC()
	clock := func() time.Time {
		mu.Lock()
		defer mu.Unlock()
		return now
	}
	st.SetClock(clock)
	s = &Server{Token: testToken, Store: st}
	// The store, the server's freshness check, and the steering controller's
	// dwell all run off the same clock, so a test can age the whole fabric.
	s.SetClock(clock)
	return s, s.Handler(), func(d time.Duration) {
		mu.Lock()
		defer mu.Unlock()
		now = now.Add(d)
	}
}

func registerNode(t *testing.T, h http.Handler, name, region string, capacity int) string {
	t.Helper()
	body := fmt.Sprintf(`{"name":%q,"region":%q,"capacity_gbps":%d,"advertise":"%s:9091"}`, name, region, capacity, name)
	out := requireJSON(t, do(t, h, http.MethodPost, "/v1/nodes/register", body), http.StatusOK)
	id, _ := out["id"].(string)
	if id == "" {
		t.Fatalf("register %s returned no id: %v", name, out)
	}
	return id
}

const zcCapPolicy = `{
  "name": "cap",
  "protected": ["203.0.113.0/24"],
  "rules": [{"id":"zc-cap","stage":"zc","action":"rate_limit","pps":100,"match":{"dst_cidr":"203.0.113.0/24","proto":"tcp"}}]
}`

func savePolicyAndDeploy(t *testing.T, h http.Handler, policy string) string {
	t.Helper()
	saved := requireJSON(t, do(t, h, http.MethodPost, "/v1/policies", policy), http.StatusOK)
	id, _ := saved["id"].(string)
	if id == "" {
		t.Fatalf("policy save returned no id: %v", saved)
	}
	requireJSON(t, do(t, h, http.MethodPost, "/v1/policies/"+id+"/deploy", ""), http.StatusOK)
	return id
}

// /v1/decide built a fresh pipeline per request, so the ZC behavioral cap
// never accumulated and the control plane disagreed with the node agent about
// the same policy.
func TestDecideAccumulatesRateStateAcrossRequests(t *testing.T) {
	_, h := newTestAPI()
	node := registerNode(t, h, "scrub-a", "iad", 100)
	savePolicyAndDeploy(t, h, zcCapPolicy)

	flow := fmt.Sprintf(`{"node_id":%q,"flow":{"src_ip":"192.0.2.5","dst_ip":"203.0.113.9","proto":"tcp","dport":443,"pps":60}}`, node)
	first := requireJSON(t, do(t, h, http.MethodPost, "/v1/decide", flow), http.StatusOK)
	if first["action"] != "permit" {
		t.Fatalf("60 pps is under the 100 pps cap: %v", first)
	}
	second := requireJSON(t, do(t, h, http.MethodPost, "/v1/decide", flow), http.StatusOK)
	if second["action"] != "drop" {
		t.Fatalf("120 pps inside one second is over the cap, got %v", second)
	}
}

// A node that registers after a deploy used to 404 on its program forever,
// enforcing nothing until a human deployed again.
func TestNodeRegisteringAfterADeployGetsAProgram(t *testing.T) {
	_, h := newTestAPI()
	registerNode(t, h, "scrub-a", "iad", 100)
	savePolicyAndDeploy(t, h, zcCapPolicy)

	late := registerNode(t, h, "scrub-b", "fra", 80)
	prog := requireJSON(t, do(t, h, http.MethodGet, "/v1/nodes/"+late+"/program", ""), http.StatusOK)
	if prog["policy_id"] != "pol-1" {
		t.Fatalf("the late node was not compiled into the fabric: %v", prog)
	}

	// The standing policy is now spread over both nodes.
	fabric := requireJSON(t, do(t, h, http.MethodGet, "/v1/fabric", ""), http.StatusOK)
	programs, _ := fabric["programs"].([]any)
	if len(programs) != 2 {
		t.Fatalf("expected the fabric to cover both nodes, got %d programs", len(programs))
	}
}

// Recompiling must not run when nothing changed: a stable fabric should keep
// the programs it has, untouched.
func TestReconcileIsANoOpWhileMembershipIsStable(t *testing.T) {
	s, h := newTestAPI()
	node := registerNode(t, h, "scrub-a", "iad", 100)
	savePolicyAndDeploy(t, h, zcCapPolicy)

	before, ok := s.Store.Program(node)
	if !ok {
		t.Fatal("expected a program after deploy")
	}
	for i := 0; i < 3; i++ {
		s.reconcile()
	}
	after, _ := s.Store.Program(node)
	if !after.CompiledAt.Equal(before.CompiledAt) {
		t.Fatalf("a stable fabric was recompiled: %v then %v", before.CompiledAt, after.CompiledAt)
	}
}

// Losing every node must not blank the fabric: whatever is still enforcing the
// last program should keep doing so.
func TestReconcileKeepsTheFabricWhenEveryNodeIsStale(t *testing.T) {
	s, h := newTestAPI()
	node := registerNode(t, h, "scrub-a", "iad", 100)
	savePolicyAndDeploy(t, h, zcCapPolicy)

	s.lastLive = "something-else" // force the membership check to fire
	s.reconcile()
	if _, ok := s.Store.Program(node); !ok {
		t.Fatal("the node's program was dropped")
	}
}

// Two scrubbers sharing a name and region collapse onto one node ID.
func TestRegisteringOverALiveNodeIsRefused(t *testing.T) {
	_, h := newTestAPI()
	registerNode(t, h, "scrub-a", "iad", 100)
	rec := do(t, h, http.MethodPost, "/v1/nodes/register",
		`{"name":"scrub-a","region":"iad","capacity_gbps":50,"advertise":"10.0.0.9:9091"}`)
	if rec.Code != http.StatusConflict {
		t.Fatalf("expected 409 for a duplicate live node, got %d: %s", rec.Code, rec.Body.String())
	}
}

// pps is only consumed by an FPGA meter and the ZC inspect path. Accepting it
// elsewhere and ignoring it is how a count rule ended up dropping traffic.
func TestPolicyRejectsPPSOnRulesThatDoNotMeter(t *testing.T) {
	_, h := newTestAPI()
	for _, tc := range []struct{ name, rule, want string }{
		{"count on zc", `{"id":"r","stage":"zc","action":"count","pps":10,"match":{}}`, "observe-only"},
		{"count on fpga", `{"id":"r","stage":"fpga","action":"count","pps":10,"match":{}}`, "observe-only"},
		{"inspect on fpga", `{"id":"r","stage":"fpga","action":"inspect","pps":10,"match":{}}`, "does not meter"},
		{"drop on zc", `{"id":"r","stage":"zc","action":"drop","pps":10,"match":{}}`, "does not meter"},
		{"permit on asic", `{"id":"r","stage":"asic","action":"permit","pps":10,"match":{}}`, "does not meter"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := fmt.Sprintf(`{"name":"p","protected":["203.0.113.0/24"],"rules":[%s]}`, tc.rule)
			out := requireJSON(t, do(t, h, http.MethodPost, "/v1/policies", body), http.StatusBadRequest)
			if msg, _ := out["error"].(string); !strings.Contains(msg, tc.want) {
				t.Fatalf("expected an error mentioning %q, got %q", tc.want, msg)
			}
		})
	}
}

// The stage/action pairs that do meter must still be accepted.
func TestPolicyAcceptsPPSOnMeteringRules(t *testing.T) {
	_, h := newTestAPI()
	body := `{"name":"p","protected":["203.0.113.0/24"],"rules":[
	  {"id":"f","stage":"fpga","action":"rate_limit","pps":10,"match":{}},
	  {"id":"z","stage":"zc","action":"rate_limit","pps":10,"match":{}},
	  {"id":"zi","stage":"zc","action":"inspect","pps":10,"match":{}}
	]}`
	requireJSON(t, do(t, h, http.MethodPost, "/v1/policies", body), http.StatusOK)
}

// A bad model has to be retirable without restarting every agent.
func TestModelCanBeWithdrawn(t *testing.T) {
	_, h := newTestAPI()
	samples := `{"samples":[
	  {"flow":{"proto":"tcp","dport":443,"sport":40001,"pps":40},"label":0},
	  {"flow":{"proto":"udp","dport":19132,"sport":1001,"pps":300000},"label":1}
	]}`
	requireJSON(t, do(t, h, http.MethodPost, "/v1/ml/samples", samples), http.StatusOK)
	requireJSON(t, do(t, h, http.MethodPost, "/v1/ml/train", `{"epochs":100,"lr":0.2,"threshold":0.6}`), http.StatusOK)
	if got := requireJSON(t, do(t, h, http.MethodGet, "/v1/ml/model", ""), http.StatusOK); got["ready"] != true {
		t.Fatalf("expected a ready model, got %v", got)
	}

	withdrawn := requireJSON(t, do(t, h, http.MethodDelete, "/v1/ml/model", ""), http.StatusOK)
	if withdrawn["withdrawn"] != true || withdrawn["ready"] == true {
		t.Fatalf("expected a withdrawn model, got %v", withdrawn)
	}
	after := requireJSON(t, do(t, h, http.MethodGet, "/v1/ml/model", ""), http.StatusOK)
	if after["withdrawn"] != true {
		t.Fatalf("the withdrawal was not published to agents: %v", after)
	}
}

func scrape(t *testing.T, h http.Handler) string {
	t.Helper()
	rec := do(t, h, http.MethodGet, "/metrics", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 from /metrics, got %d: %s", rec.Code, rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/plain") {
		t.Fatalf("unexpected content type %q", ct)
	}
	return rec.Body.String()
}

// Rule IDs and traffic volumes are not public.
func TestMetricsRequiresTheToken(t *testing.T) {
	_, h := newTestAPI()
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for an unauthenticated scrape, got %d", rec.Code)
	}
}

func TestMetricsDescribeTheControlPlane(t *testing.T) {
	_, h := newTestAPI()
	registerNode(t, h, "scrub-a", "iad", 100)
	savePolicyAndDeploy(t, h, zcCapPolicy)

	out := scrape(t, h)
	for _, want := range []string{
		`scrubline_nodes{status="ready"} 1`,
		`scrubline_nodes{status="stale"} 0`,
		"scrubline_policies 1",
		"scrubline_announcements 1",
		`scrubline_bgp_announced{node=`,
		"scrubline_programs 1",
		`scrubline_node_prefixes{node=`,
		"scrubline_fabric_recompiles_total 1",
		"scrubline_control_ml_model_ready 0",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in scrape:\n%s", want, out)
		}
	}
}

// The control plane can only answer "is mitigation working" if nodes tell it
// what their datapath did.
func TestHeartbeatCarriesDatapathCounters(t *testing.T) {
	_, h := newTestAPI()
	node := registerNode(t, h, "scrub-a", "iad", 100)
	savePolicyAndDeploy(t, h, zcCapPolicy)

	body := `{"stats":{"decisions":40,"unowned":2,
	  "stages":[{"stage":"asic","dropped":10,"permitted":0,"pps_dropped":5000,"pps_permitted":0}],
	  "rules":[{"rule_id":"zc-cap","stage":"zc","matches":9,"drops":4,"pps_seen":900,"pps_dropped":400}],
	  "ml":{"ready":false,"scored":0,"drops":0,"passes":0},
	  "rate_buckets":7,"rate_buckets_max":65536}}`
	requireJSON(t, do(t, h, http.MethodPost, "/v1/nodes/"+node+"/heartbeat", body), http.StatusOK)

	reported := requireJSON(t, do(t, h, http.MethodGet, "/v1/nodes/"+node+"/stats", ""), http.StatusOK)
	if reported["node_id"] != node {
		t.Fatalf("expected the report keyed to the node, got %v", reported)
	}

	out := scrape(t, h)
	for _, want := range []string{
		`scrubline_decisions_total{node="` + node + `",name="scrub-a",region="iad"} 40`,
		`scrubline_rule_drops_total{node="` + node + `",name="scrub-a",region="iad",stage="zc",rule="zc-cap"} 4`,
		`scrubline_stage_dropped_pps_total{node="` + node + `",name="scrub-a",region="iad",stage="asic"} 5000`,
		"scrubline_report_age_seconds{node=",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in scrape:\n%s", want, out)
		}
	}
}

// An agent that sends no counters still heartbeats.
func TestHeartbeatWithoutCountersStillWorks(t *testing.T) {
	_, h := newTestAPI()
	node := registerNode(t, h, "scrub-a", "iad", 100)
	requireJSON(t, do(t, h, http.MethodPost, "/v1/nodes/"+node+"/heartbeat", ""), http.StatusOK)
	if rec := do(t, h, http.MethodGet, "/v1/nodes/"+node+"/stats", ""); rec.Code != http.StatusNotFound {
		t.Fatalf("expected no report to be recorded, got %d", rec.Code)
	}
}

func TestHeartbeatRejectsAMalformedReport(t *testing.T) {
	_, h := newTestAPI()
	node := registerNode(t, h, "scrub-a", "iad", 100)
	rec := do(t, h, http.MethodPost, "/v1/nodes/"+node+"/heartbeat", `{"stats":`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for a malformed body, got %d: %s", rec.Code, rec.Body.String())
	}
}

// A report for a node the control plane does not know must not be recorded;
// otherwise the map grows on anything that can reach the endpoint.
func TestReportForAnUnknownNodeIsNotRecorded(t *testing.T) {
	s, h := newTestAPI()
	rec := do(t, h, http.MethodPost, "/v1/nodes/node-nope/heartbeat", `{"stats":{"decisions":1}}`)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for an unknown node, got %d", rec.Code)
	}
	if got := len(s.Store.Reports()); got != 0 {
		t.Fatalf("expected no reports to be stored, got %d", got)
	}
}

func TestAPIRequestsAreCountedByRouteAndStatus(t *testing.T) {
	_, h := newTestAPI()
	do(t, h, http.MethodGet, "/v1/nodes", "")
	do(t, h, http.MethodGet, "/v1/nodes", "")
	do(t, h, http.MethodGet, "/v1/nodes/node-nope/program", "")

	out := scrape(t, h)
	for _, want := range []string{
		`scrubline_api_requests_total{route="nodes",status="200"} 2`,
		`scrubline_api_requests_total{route="nodes/program",status="404"} 1`,
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in scrape:\n%s", want, out)
		}
	}
}

// An unauthenticated request is counted too: a spike of them is the signal
// that something is probing the control plane.
func TestUnauthenticatedRequestsAreCounted(t *testing.T) {
	_, h := newTestAPI()
	req := httptest.NewRequest(http.MethodGet, "/v1/nodes", nil)
	req.Header.Set("Authorization", "Bearer wrong")
	h.ServeHTTP(httptest.NewRecorder(), req)

	if out := scrape(t, h); !strings.Contains(out, `scrubline_api_requests_total{route="unauthorized",status="401"} 1`) {
		t.Fatalf("expected the rejected request to be counted:\n%s", out)
	}
}

const twoPrefixPolicy = `{
  "name": "anycast",
  "protected": ["203.0.113.0/24", "198.51.100.0/24"],
  "rules": [{"id":"zc-cap","stage":"zc","action":"rate_limit","pps":100,"match":{"proto":"tcp"}}]
}`

func fabricPlan(t *testing.T, h http.Handler) []map[string]any {
	t.Helper()
	fabric := requireJSON(t, do(t, h, http.MethodGet, "/v1/fabric", ""), http.StatusOK)
	raw, ok := fabric["announcements"].([]any)
	if !ok {
		t.Fatalf("fabric carries no announcement plan: %v", fabric)
	}
	out := make([]map[string]any, 0, len(raw))
	for _, r := range raw {
		out = append(out, r.(map[string]any))
	}
	return out
}

// Under anycast nothing is exclusively owned: every live node announces and
// enforces every protected prefix, so a flood on one prefix is absorbed by
// the whole fabric.
func TestDeployAnnouncesEveryPrefixFromEveryNode(t *testing.T) {
	_, h := newTestAPI()
	a := registerNode(t, h, "scrub-a", "iad", 100)
	b := registerNode(t, h, "scrub-b", "fra", 100)
	savePolicyAndDeploy(t, h, twoPrefixPolicy)

	if got := len(fabricPlan(t, h)); got != 4 {
		t.Fatalf("expected 2 prefixes across 2 nodes, got %d announcement rows", got)
	}
	for _, node := range []string{a, b} {
		prog := requireJSON(t, do(t, h, http.MethodGet, "/v1/nodes/"+node+"/program", ""), http.StatusOK)
		prefixes, _ := prog["prefixes"].([]any)
		if len(prefixes) != 2 {
			t.Fatalf("node %s enforces %v, expected both prefixes", node, prefixes)
		}
		announcements, _ := prog["announcements"].([]any)
		if len(announcements) != 2 {
			t.Fatalf("node %s carries %d announcements, expected 2", node, len(announcements))
		}
	}
}

// Capacity is weighted by prepending, not by picking a winner.
func TestSmallerNodesAreMorePrepended(t *testing.T) {
	_, h := newTestAPI()
	registerNode(t, h, "scrub-big", "iad", 400)
	registerNode(t, h, "scrub-small", "sin", 100)
	savePolicyAndDeploy(t, h, zcCapPolicy)

	prepends := map[string]float64{}
	for _, row := range fabricPlan(t, h) {
		prepends[row["node_name"].(string)] = row["prepends"].(float64)
	}
	if prepends["scrub-big"] != 0 {
		t.Fatalf("the largest node should announce unpadded, got %v", prepends["scrub-big"])
	}
	if prepends["scrub-small"] != 2 {
		t.Fatalf("a quarter-capacity node should carry 2 prepends, got %v", prepends["scrub-small"])
	}
}

// A node going stale is withdrawn from anycast, and its traffic moves to the
// nodes still answering. That is the failover path.
func TestStaleNodeIsWithdrawnFromTheFabric(t *testing.T) {
	s, h, advance := newTestAPIWithClock()
	registerNode(t, h, "scrub-a", "iad", 100)
	dead := registerNode(t, h, "scrub-dead", "sin", 100)
	savePolicyAndDeploy(t, h, zcCapPolicy)

	for _, row := range fabricPlan(t, h) {
		if row["state"] != "announce" {
			t.Fatalf("expected both nodes announcing to begin with, got %v", row)
		}
	}

	// Age the fleet past the TTL, leaving one node heartbeating.
	advance(store.NodeTTL + time.Second)
	if ok, _ := s.Store.Heartbeat(dead); !ok {
		t.Fatal("heartbeat for a known node should succeed")
	}
	s.reconcile()

	states := map[string]string{}
	for _, row := range fabricPlan(t, h) {
		states[row["node_name"].(string)] = row["state"].(string)
	}
	if states["scrub-a"] != "withdraw" {
		t.Fatalf("expected the silent node withdrawn, got %q", states["scrub-a"])
	}
	if states["scrub-dead"] != "announce" {
		t.Fatalf("expected the heartbeating node still announcing, got %q", states["scrub-dead"])
	}
}

// Convergence is not instant, so a withdrawing node keeps scrubbing whatever
// still arrives for the prefix.
func TestWithdrawnNodeKeepsEnforcing(t *testing.T) {
	s, h, advance := newTestAPIWithClock()
	quiet := registerNode(t, h, "scrub-a", "iad", 100)
	alive := registerNode(t, h, "scrub-b", "fra", 100)
	savePolicyAndDeploy(t, h, zcCapPolicy)

	advance(store.NodeTTL + time.Second)
	s.Store.Heartbeat(alive)
	s.reconcile()

	prog := requireJSON(t, do(t, h, http.MethodGet, "/v1/nodes/"+quiet+"/program", ""), http.StatusOK)
	prefixes, _ := prog["prefixes"].([]any)
	if len(prefixes) != 1 {
		t.Fatalf("a withdrawing node must keep enforcing during convergence, got %v", prefixes)
	}
}

// Region pinning keeps a prefix inside a jurisdiction: an out-of-region node
// neither announces it nor inspects traffic for it.
func TestRegionPinnedPrefixStaysInItsRegion(t *testing.T) {
	_, h := newTestAPI()
	registerNode(t, h, "scrub-eu", "fra", 100)
	us := registerNode(t, h, "scrub-us", "iad", 100)
	savePolicyAndDeploy(t, h, `{
	  "name": "pinned",
	  "protected": ["203.0.113.0/24", "198.51.100.0/24"],
	  "steering": [{"prefix":"203.0.113.0/24","regions":["fra"],"communities":["65000:100"]}],
	  "rules": []
	}`)

	for _, row := range fabricPlan(t, h) {
		if row["prefix"] == "203.0.113.0/24" && row["node_name"] == "scrub-us" {
			t.Fatalf("a pinned prefix was announced out of region: %v", row)
		}
	}
	prog := requireJSON(t, do(t, h, http.MethodGet, "/v1/nodes/"+us+"/program", ""), http.StatusOK)
	prefixes, _ := prog["prefixes"].([]any)
	if len(prefixes) != 1 || prefixes[0] != "198.51.100.0/24" {
		t.Fatalf("the out-of-region node must not enforce the pinned prefix, got %v", prefixes)
	}
}

// Communities are written into a routing daemon's control pipe on every node,
// so they are checked when the policy is saved, not at the pipe.
func TestPolicyRejectsUnsafeSteering(t *testing.T) {
	_, h := newTestAPI()
	for _, tc := range []struct{ name, steering, want string }{
		{"injection", `{"prefix":"203.0.113.0/24","communities":["65000:1\nannounce route 0.0.0.0/0"]}`, "community"},
		{"bad community", `{"prefix":"203.0.113.0/24","communities":["nope"]}`, "community"},
		{"unprotected prefix", `{"prefix":"192.0.2.0/24"}`, "not in this policy's protected list"},
		{"empty prefix", `{"prefix":""}`, "prefix required"},
		{"empty region", `{"prefix":"203.0.113.0/24","regions":["  "]}`, "region must not be empty"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := fmt.Sprintf(`{"name":"p","protected":["203.0.113.0/24"],"steering":[%s],"rules":[]}`, tc.steering)
			out := requireJSON(t, do(t, h, http.MethodPost, "/v1/policies", body), http.StatusBadRequest)
			if msg, _ := out["error"].(string); !strings.Contains(msg, tc.want) {
				t.Fatalf("expected an error mentioning %q, got %q", tc.want, msg)
			}
		})
	}
}

func TestPolicyRejectsDuplicateSteering(t *testing.T) {
	_, h := newTestAPI()
	body := `{"name":"p","protected":["203.0.113.0/24"],"rules":[],"steering":[
	  {"prefix":"203.0.113.0/24","regions":["iad"]},
	  {"prefix":"203.0.113.0/24","regions":["fra"]}
	]}`
	out := requireJSON(t, do(t, h, http.MethodPost, "/v1/policies", body), http.StatusBadRequest)
	if msg, _ := out["error"].(string); !strings.Contains(msg, "duplicate steering") {
		t.Fatalf("expected a duplicate-steering error, got %q", msg)
	}
}

// A capacity that cannot be compared would decide prepends for the whole
// fabric.
func TestRegisterRejectsNonFiniteCapacity(t *testing.T) {
	_, h := newTestAPI()
	// JSON has no NaN literal, so this arrives as a string the decoder rejects,
	// and an overflowing number is rejected too.
	for _, body := range []string{
		`{"name":"n","region":"iad","capacity_gbps":"NaN"}`,
		`{"name":"n","region":"iad","capacity_gbps":1e999}`,
		`{"name":"n","region":"iad","capacity_gbps":-1}`,
	} {
		if rec := do(t, h, http.MethodPost, "/v1/nodes/register", body); rec.Code != http.StatusBadRequest {
			t.Fatalf("body %s: expected 400, got %d: %s", body, rec.Code, rec.Body.String())
		}
	}
}

func registerNodeWithPPS(t *testing.T, h http.Handler, name, region string, gbps int, pps int64) string {
	t.Helper()
	body := fmt.Sprintf(`{"name":%q,"region":%q,"capacity_gbps":%d,"capacity_pps":%d,"advertise":"%s:9091"}`,
		name, region, gbps, pps, name)
	out := requireJSON(t, do(t, h, http.MethodPost, "/v1/nodes/register", body), http.StatusOK)
	id, _ := out["id"].(string)
	if id == "" {
		t.Fatalf("register %s returned no id: %v", name, out)
	}
	return id
}

// reportLoad sends a heartbeat carrying an offered packet rate.
func reportLoad(t *testing.T, h http.Handler, node string, offered uint64) {
	t.Helper()
	body := fmt.Sprintf(`{"stats":{"offered_pps":%d,"load_window_seconds":10}}`, offered)
	requireJSON(t, do(t, h, http.MethodPost, "/v1/nodes/"+node+"/heartbeat", body), http.StatusOK)
}

func prependsByName(t *testing.T, h http.Handler) map[string]float64 {
	t.Helper()
	out := map[string]float64{}
	for _, row := range fabricPlan(t, h) {
		if row["state"] == "announce" {
			out[row["node_name"].(string)] = row["prepends"].(float64)
		}
	}
	return out
}

// The whole point of the loop: a node measured near its ceiling is padded so
// the next-closest node takes the overflow, and is unpadded once it recovers.
func TestSaturatedNodeIsPaddedAndRecovers(t *testing.T) {
	s, h, advance := newTestAPIWithClock()
	hot := registerNodeWithPPS(t, h, "scrub-hot", "iad", 100, 1_000_000)
	registerNodeWithPPS(t, h, "scrub-cool", "fra", 100, 1_000_000)
	savePolicyAndDeploy(t, h, zcCapPolicy)

	if got := prependsByName(t, h); got["scrub-hot"] != 0 {
		t.Fatalf("expected an even fabric to start, got %v", got)
	}

	reportLoad(t, h, hot, 950_000) // 95% of its ceiling
	s.reconcile()
	if got := prependsByName(t, h); got["scrub-hot"] != 1 || got["scrub-cool"] != 0 {
		t.Fatalf("expected the saturated node padded and its neighbour left alone, got %v", got)
	}

	// Still saturated, but inside the dwell window: nothing moves.
	reportLoad(t, h, hot, 990_000)
	s.reconcile()
	if got := prependsByName(t, h); got["scrub-hot"] != 1 {
		t.Fatalf("padding moved inside the dwell window, got %v", got)
	}

	// Past the dwell and recovered: the padding unwinds.
	advance(steering.MinDwell + time.Second)
	reportLoad(t, h, hot, 50_000)
	s.reconcile()
	if got := prependsByName(t, h); got["scrub-hot"] != 0 {
		t.Fatalf("expected the padding to unwind once load fell, got %v", got)
	}
}

// A node that declares no packet ceiling cannot be measured, so it is never
// padded for load however much traffic it reports.
func TestNodeWithoutAPacketCeilingIsNeverPaddedForLoad(t *testing.T) {
	s, h, _ := newTestAPIWithClock()
	node := registerNode(t, h, "scrub-a", "iad", 100) // no capacity_pps
	savePolicyAndDeploy(t, h, zcCapPolicy)

	reportLoad(t, h, node, 500_000_000)
	s.reconcile()
	if got := prependsByName(t, h); got["scrub-a"] != 0 {
		t.Fatalf("a node with no declared ceiling was padded: %v", got)
	}
}

// Counters that stopped arriving must not drive the routing table: a node
// whose agent went quiet holds the padding it had rather than being judged on
// a measurement from minutes ago.
func TestStaleCountersHoldThePadding(t *testing.T) {
	s, h, advance := newTestAPIWithClock()
	hot := registerNodeWithPPS(t, h, "scrub-hot", "iad", 100, 1_000_000)
	cool := registerNodeWithPPS(t, h, "scrub-cool", "fra", 100, 1_000_000)
	savePolicyAndDeploy(t, h, zcCapPolicy)

	reportLoad(t, h, hot, 950_000)
	s.reconcile()
	if got := prependsByName(t, h)["scrub-hot"]; got != 1 {
		t.Fatalf("expected the node padded while reporting, got %v", got)
	}

	// The agent keeps heartbeating but stops attaching counters, so the node
	// stays live while its measurement ages out. Well past the dwell, a fresh
	// idle report would unwind the padding; a stale one must not.
	for i := 0; i < 8; i++ {
		advance((steering.ReportFreshness + steering.MinDwell) / 4)
		// A bodiless heartbeat keeps the node live without refreshing stats.
		requireJSON(t, do(t, h, http.MethodPost, "/v1/nodes/"+hot+"/heartbeat", ""), http.StatusOK)
		requireJSON(t, do(t, h, http.MethodPost, "/v1/nodes/"+cool+"/heartbeat", ""), http.StatusOK)
		s.reconcile()
	}
	if got := len(prependsByName(t, h)); got != 2 {
		t.Fatalf("both nodes should still be live and announcing, got %d", got)
	}
	if got := prependsByName(t, h)["scrub-hot"]; got != 1 {
		t.Fatalf("a stale report moved the padding, got %v", got)
	}
	if reason := s.Steering().Levels()[hot].Reason; !strings.Contains(reason, "no recent counters") {
		t.Fatalf("the controller should say it is holding on stale data, got %q", reason)
	}
}

// Nothing should recompile while the fabric and the load picture are steady:
// a needless recompile is a needless BGP update.
func TestSteadyLoadDoesNotRecompile(t *testing.T) {
	s, h, _ := newTestAPIWithClock()
	node := registerNodeWithPPS(t, h, "scrub-a", "iad", 100, 1_000_000)
	savePolicyAndDeploy(t, h, zcCapPolicy)
	reportLoad(t, h, node, 100_000)
	s.reconcile()

	before, _ := s.Store.Program(node)
	for i := 0; i < 5; i++ {
		reportLoad(t, h, node, 100_000)
		s.reconcile()
	}
	after, _ := s.Store.Program(node)
	if !after.CompiledAt.Equal(before.CompiledAt) {
		t.Fatalf("steady load triggered a recompile: %v then %v", before.CompiledAt, after.CompiledAt)
	}
}

func TestSteeringMetricsExposeTheLoop(t *testing.T) {
	s, h, _ := newTestAPIWithClock()
	node := registerNodeWithPPS(t, h, "scrub-a", "iad", 100, 1_000_000)
	savePolicyAndDeploy(t, h, zcCapPolicy)
	reportLoad(t, h, node, 900_000)
	s.reconcile()

	out := scrape(t, h)
	for _, want := range []string{
		`scrubline_steering_escalation{node="` + node + `",name="scrub-a",region="iad"} 1`,
		`scrubline_steering_load_ratio{node="` + node + `",name="scrub-a",region="iad"} 0.9`,
		`scrubline_node_capacity_pps{node="` + node + `",name="scrub-a",region="iad"} 1e+06`,
		`scrubline_offered_pps{node="` + node + `",name="scrub-a",region="iad"} 900000`,
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in scrape:\n%s", want, out)
		}
	}
}

func TestRegisterRejectsNegativePacketCapacity(t *testing.T) {
	_, h := newTestAPI()
	rec := do(t, h, http.MethodPost, "/v1/nodes/register", `{"name":"n","region":"iad","capacity_pps":-1}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", rec.Code, rec.Body.String())
	}
}
