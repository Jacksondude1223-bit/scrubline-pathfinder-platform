package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

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
		"scrubline_assignments 1",
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
