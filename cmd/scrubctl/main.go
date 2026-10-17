package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/Jacksondude1223-bit/scrubline-cloud-scrub/internal/transport"
)

func main() {
	api := flag.String("api", "http://127.0.0.1:8080", "control API")
	caFile := flag.String("ca", "", "PEM bundle to verify the control plane against; empty uses the system roots")
	flag.Parse()
	httpClient, err := transport.Client(transport.ClientConfig{CAFile: *caFile, Timeout: 30 * time.Second})
	if err != nil {
		exit(err.Error())
	}
	client = httpClient
	token := os.Getenv("SCRUBLINE_API_TOKEN")
	if token == "" {
		fmt.Fprintln(os.Stderr, "SCRUBLINE_API_TOKEN is required (the operator credential)")
		os.Exit(1)
	}
	args := flag.Args()
	if len(args) == 0 {
		fmt.Println("usage: scrubctl nodes | policies | apply <file> | deploy <policy-id> | fabric | bgp |\n" +
			"                decide <node-id> <flow.json> | ml-load <file> | ml-train | ml-model |\n" +
			"                analytics [window] | attacks [window] | tenants | tenant-add <file> |\n" +
			"                tenant-token <tenant-id> | tenant-rm <tenant-id>")
		os.Exit(1)
	}
	switch args[0] {
	case "nodes":
		fmt.Println(string(call(token, http.MethodGet, *api+"/v1/nodes", nil)))
	case "policies":
		fmt.Println(string(call(token, http.MethodGet, *api+"/v1/policies", nil)))
	case "fabric":
		fmt.Println(string(call(token, http.MethodGet, *api+"/v1/fabric", nil)))
	case "bgp":
		printPlan(call(token, http.MethodGet, *api+"/v1/fabric", nil))
	case "apply":
		if len(args) < 2 {
			exit("apply <file>")
		}
		raw, err := os.ReadFile(args[1])
		if err != nil {
			exit(err.Error())
		}
		if !json.Valid(raw) {
			exit(fmt.Sprintf("%s does not contain valid JSON", args[1]))
		}
		fmt.Println(string(call(token, http.MethodPost, *api+"/v1/policies", raw)))
	case "deploy":
		if len(args) < 2 {
			exit("deploy <policy-id>")
		}
		fmt.Println(string(call(token, http.MethodPost, *api+"/v1/policies/"+args[1]+"/deploy", []byte("{}"))))
	case "decide":
		if len(args) < 3 {
			exit("decide <node-id> <flow.json>")
		}
		flow, err := os.ReadFile(args[2])
		if err != nil {
			exit(err.Error())
		}
		if !json.Valid(flow) {
			exit(fmt.Sprintf("%s does not contain valid JSON", args[2]))
		}
		body, err := json.Marshal(map[string]json.RawMessage{"node_id": json.RawMessage(fmt.Sprintf("%q", args[1])), "flow": flow})
		if err != nil {
			exit(err.Error())
		}
		fmt.Println(string(call(token, http.MethodPost, *api+"/v1/decide", body)))
	case "ml-load":
		if len(args) < 2 {
			exit("ml-load <file>")
		}
		raw, err := os.ReadFile(args[1])
		if err != nil {
			exit(err.Error())
		}
		if !json.Valid(raw) {
			exit(fmt.Sprintf("%s does not contain valid JSON", args[1]))
		}
		fmt.Println(string(call(token, http.MethodPost, *api+"/v1/ml/samples", raw)))
	case "ml-train":
		body := []byte(`{"epochs":300,"lr":0.2,"threshold":0.65}`)
		if len(args) > 1 {
			raw, err := os.ReadFile(args[1])
			if err != nil {
				exit(err.Error())
			}
			body = raw
		}
		fmt.Println(string(call(token, http.MethodPost, *api+"/v1/ml/train", body)))
	case "ml-model":
		fmt.Println(string(call(token, http.MethodGet, *api+"/v1/ml/model", nil)))
	case "analytics":
		printOverview(call(token, http.MethodGet, *api+"/v1/analytics/overview?window="+windowArg(args), nil))
	case "attacks":
		printAttacks(call(token, http.MethodGet, *api+"/v1/analytics/events?window="+windowArg(args), nil))
	case "tenants":
		fmt.Println(string(call(token, http.MethodGet, *api+"/v1/tenants", nil)))
	case "tenant-add":
		if len(args) < 2 {
			exit("tenant-add <file>")
		}
		raw, err := os.ReadFile(args[1])
		if err != nil {
			exit(err.Error())
		}
		if !json.Valid(raw) {
			exit(fmt.Sprintf("%s does not contain valid JSON", args[1]))
		}
		fmt.Println(string(call(token, http.MethodPost, *api+"/v1/tenants", raw)))
	case "tenant-token":
		if len(args) < 2 {
			exit("tenant-token <tenant-id>")
		}
		// The credential comes back exactly once. Say so, because there is
		// no second chance to copy it.
		fmt.Println(string(call(token, http.MethodPost, *api+"/v1/tenants/"+args[1]+"/token", []byte("{}"))))
		fmt.Fprintln(os.Stderr, "this credential is shown once; only its hash is kept")
	case "tenant-rm":
		if len(args) < 2 {
			exit("tenant-rm <tenant-id>")
		}
		fmt.Println(string(call(token, http.MethodDelete, *api+"/v1/tenants/"+args[1], nil)))
	default:
		exit("unknown command")
	}
}

// windowArg is the span a report covers, defaulting to a day.
func windowArg(args []string) string {
	if len(args) > 1 {
		return args[1]
	}
	return "24h"
}

// printOverview renders the customer-facing view as a table: one line per
// protected prefix, what arrived, and what was scrubbed out of it.
func printOverview(raw []byte) {
	var out struct {
		Window   string `json:"window"`
		Prefixes []struct {
			Prefix       string  `json:"prefix"`
			Offered      uint64  `json:"offered"`
			Dropped      uint64  `json:"dropped"`
			MitigatedPct float64 `json:"mitigated_pct"`
			PeakPPS      uint64  `json:"peak_pps"`
			OfferedPPS   uint64  `json:"offered_pps"`
			Nodes        int     `json:"nodes"`
			Attacks      int     `json:"attacks"`
			UnderAttack  bool    `json:"under_attack"`
		} `json:"prefixes"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		exit(fmt.Sprintf("reading the analytics: %v", err))
	}
	if len(out.Prefixes) == 0 {
		fmt.Println("no protected prefixes are being reported on yet")
		return
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintf(w, "PREFIX\tOFFERED\tSCRUBBED\tMITIGATED\tPEAK PPS\tNOW PPS\tNODES\tATTACKS\tSTATE\n")
	for _, p := range out.Prefixes {
		state := "clear"
		if p.UnderAttack {
			state = "UNDER ATTACK"
		}
		fmt.Fprintf(w, "%s\t%d\t%d\t%.1f%%\t%d\t%d\t%d\t%d\t%s\n",
			p.Prefix, p.Offered, p.Dropped, p.MitigatedPct, p.PeakPPS, p.OfferedPPS, p.Nodes, p.Attacks, state)
	}
	_ = w.Flush()
	fmt.Printf("\nover the last %s\n", out.Window)
}

// printAttacks renders the attack log: when, how big, and what stopped it.
func printAttacks(raw []byte) {
	var out struct {
		Window string `json:"window"`
		Events []struct {
			Prefix         string    `json:"prefix"`
			StartedAt      time.Time `json:"started_at"`
			Seconds        float64   `json:"seconds"`
			Ongoing        bool      `json:"ongoing"`
			PeakPPS        uint64    `json:"peak_pps"`
			PeakDroppedPPS uint64    `json:"peak_dropped_pps"`
			Pulse          bool      `json:"pulse"`
			Vectors        []struct {
				RuleID   string `json:"rule_id"`
				FilterID string `json:"filter_id"`
				Stage    string `json:"stage"`
			} `json:"vectors"`
		} `json:"events"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		exit(fmt.Sprintf("reading the attack log: %v", err))
	}
	if len(out.Events) == 0 {
		fmt.Printf("no attacks in the last %s\n", out.Window)
		return
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "STARTED\tPREFIX\tFOR\tPEAK PPS\tSCRUBBED PPS\tSHAPE\tSTOPPED BY")
	for _, e := range out.Events {
		shape := "flood"
		if e.Pulse {
			shape = "burst train"
		}
		took := (time.Duration(e.Seconds) * time.Second).String()
		if e.Ongoing {
			took += " (ongoing)"
		}
		names := make([]string, 0, len(e.Vectors))
		for _, v := range e.Vectors {
			name := v.RuleID
			if name == "" {
				name = v.FilterID
			}
			names = append(names, fmt.Sprintf("%s(%s)", name, v.Stage))
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%d\t%d\t%s\t%s\n",
			e.StartedAt.Format(time.RFC3339), e.Prefix, took,
			e.PeakPPS, e.PeakDroppedPPS, shape, orDash(strings.Join(names, " ")))
	}
	_ = w.Flush()
}

// printPlan renders the fabric's BGP posture as a table: which node announces
// which prefix, and how hard each one is padded away from it.
func printPlan(raw []byte) {
	var fabric struct {
		Announcements []struct {
			Prefix   string `json:"prefix"`
			NodeName string `json:"node_name"`
			Region   string `json:"region"`
			State    string `json:"state"`
			Prepends int    `json:"prepends"`
			NextHop  string `json:"next_hop"`
			Reason   string `json:"reason"`
		} `json:"announcements"`
	}
	if err := json.Unmarshal(raw, &fabric); err != nil {
		exit(fmt.Sprintf("reading the fabric: %v", err))
	}
	if len(fabric.Announcements) == 0 {
		fmt.Println("no announcements; deploy a policy first")
		return
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "PREFIX\tNODE\tREGION\tSTATE\tPREPENDS\tNEXT HOP\tWHY")
	for _, a := range fabric.Announcements {
		prepends := strconv.Itoa(a.Prepends)
		if a.State != "announce" {
			prepends = "-"
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
			a.Prefix, a.NodeName, a.Region, a.State, prepends, orDash(a.NextHop), a.Reason)
	}
	_ = w.Flush()
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// client reaches the control plane; it is configured in main.
var client = http.DefaultClient

func call(token, method, url string, body []byte) []byte {
	req, err := http.NewRequest(method, url, bytes.NewReader(body))
	if err != nil {
		exit(err.Error())
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		exit(err.Error())
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		exit(fmt.Sprintf("reading %s %s: %v", method, url, err))
	}
	if resp.StatusCode >= 300 {
		exit(fmt.Sprintf("%s %s: %s: %s", method, url, resp.Status, strings.TrimSpace(string(raw))))
	}
	return raw
}

func exit(msg string) {
	fmt.Fprintln(os.Stderr, msg)
	os.Exit(1)
}
