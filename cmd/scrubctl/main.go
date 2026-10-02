package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
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
		fmt.Println("usage: scrubctl nodes | policies | apply <file> | deploy <policy-id> | fabric | decide <node-id> <flow.json>")
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
		body, _ := json.Marshal(map[string]json.RawMessage{"node_id": json.RawMessage(fmt.Sprintf("%q", args[1])), "flow": flow})
		fmt.Println(string(call(token, http.MethodPost, *api+"/v1/decide", body)))
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
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 300 {
		exit(string(raw))
	}
	return raw
}

func exit(msg string) {
	fmt.Fprintln(os.Stderr, msg)
	os.Exit(1)
}
