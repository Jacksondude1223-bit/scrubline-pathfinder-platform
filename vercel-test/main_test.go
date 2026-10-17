package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestConfiguration(t *testing.T) {
	for _, pair := range [][2]string{{"", "enroll"}, {"operator", ""}, {"same", "same"}} {
		if _, err := newHandler(pair[0], pair[1]); err == nil {
			t.Fatalf("accepted invalid credentials %q", pair)
		}
	}
}

func TestControlPlaneLifecycle(t *testing.T) {
	h, err := newHandler("operator", "enroll")
	if err != nil {
		t.Fatal(err)
	}
	call := func(method, path, token, body string, status int) map[string]any {
		t.Helper()
		r := httptest.NewRequest(method, path, strings.NewReader(body))
		if token != "" {
			r.Header.Set("Authorization", "Bearer "+token)
		}
		r.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != status {
			t.Fatalf("%s %s: got %d %s, want %d", method, path, w.Code, w.Body.String(), status)
		}
		if w.Header().Get("Cache-Control") != "no-store" || w.Header().Get("X-Scrubline-Test-Mode") != "ephemeral-memory" {
			t.Fatal("missing test/cache headers")
		}
		var out map[string]any
		if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
			t.Fatal(err)
		}
		return out
	}
	call("GET", "/", "", "", http.StatusOK)
	if call("GET", "/health", "", "", 200)["status"] != "ok" {
		t.Fatal("unhealthy")
	}
	call("GET", "/v1/nodes", "", "", 401)
	call("GET", "/v1/fabric", "enroll", "", 403)
	registered := call("POST", "/v1/nodes/register", "enroll", `{"name":"test","region":"iad","capacity_gbps":10,"advertise":"192.0.2.1:9091"}`, 200)
	if registered["token"] == "" {
		t.Fatal("no node token issued")
	}
	node := registered["node"].(map[string]any)["id"].(string)
	policy := call("POST", "/v1/policies", "operator", `{"name":"test","protected":["203.0.113.0/24"],"rules":[{"id":"bogon","stage":"asic","action":"drop","priority":100,"match":{"src_cidr":"0.0.0.0/8"}}]}`, 200)
	deployed := call("POST", "/v1/policies/"+policy["id"].(string)+"/deploy", "operator", "", 200)
	if deployed["nodes"] != float64(1) {
		t.Fatalf("unexpected deploy: %v", deployed)
	}
	decision := call("POST", "/v1/decide", "operator", `{"node_id":"`+node+`","flow":{"src_ip":"0.1.2.3","dst_ip":"203.0.113.10","proto":"udp","dport":19132,"pps":100}}`, 200)
	if decision["action"] != "drop" {
		t.Fatalf("unexpected decision: %v", decision)
	}
	call("POST", "/v1/policies", "operator", `{"name":"bad","protected":["203.0.113.0/24"],"rules":[{"id":"c","stage":"zc","action":"count","pps":10,"match":{}}]}`, 400)
	call("GET", "/v1/does-not-exist", "operator", "", 404)
}
