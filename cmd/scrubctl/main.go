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
		fmt.Println("usage: scrubctl nodes | policies | apply <file> | deploy <policy-id> | fabric | bgp | decide <node-id> <flow.json> | ml-load <file> | ml-train | ml-model")
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
	default:
		exit("unknown command")
	}
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
