package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
)

func main() {
	api := flag.String("api", "http://127.0.0.1:8080", "control API")
	flag.Parse()
	token := os.Getenv("SCRUBLINE_API_TOKEN")
	if token == "" {
		fmt.Fprintln(os.Stderr, "SCRUBLINE_API_TOKEN is required")
		os.Exit(1)
	}
	args := flag.Args()
	if len(args) == 0 {
		fmt.Println("usage: scrubctl nodes | policies | apply <file> | deploy <policy-id> | fabric | decide <node-id> <flow.json> | ml-load <file> | ml-train | ml-model")
		os.Exit(1)
	}
	switch args[0] {
	case "nodes":
		fmt.Println(string(call(token, http.MethodGet, *api+"/v1/nodes", nil)))
	case "policies":
		fmt.Println(string(call(token, http.MethodGet, *api+"/v1/policies", nil)))
	case "fabric":
		fmt.Println(string(call(token, http.MethodGet, *api+"/v1/fabric", nil)))
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

func call(token, method, url string, body []byte) []byte {
	req, err := http.NewRequest(method, url, bytes.NewReader(body))
	if err != nil {
		exit(err.Error())
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
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
