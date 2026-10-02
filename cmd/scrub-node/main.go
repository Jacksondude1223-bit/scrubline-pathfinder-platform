package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"io"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/Jacksondude1223-bit/scrubline-cloud-scrub/internal/ml"
	"github.com/Jacksondude1223-bit/scrubline-cloud-scrub/internal/model"
	"github.com/Jacksondude1223-bit/scrubline-cloud-scrub/internal/pipeline"
)

func main() {
	apiURL := flag.String("api", "http://127.0.0.1:8080", "control API base URL")
	name := flag.String("name", "scrub-a", "node name")
	region := flag.String("region", "iad", "node region")
	capacity := flag.Float64("capacity", 40, "scrub capacity in Gbps")
	listen := flag.String("listen", "127.0.0.1:9091", "local decide/metrics address")
	flag.Parse()
	token := os.Getenv("SCRUBLINE_API_TOKEN")
	if token == "" {
		log.Fatal("SCRUBLINE_API_TOKEN is required")
	}

	node := model.Node{
		Name: *name, Region: *region, CapacityGbps: *capacity, Advertise: *listen,
		Backends: []model.Stage{model.StageASIC, model.StageFPGA, model.StageZC},
	}
	raw, _ := json.Marshal(node)
	res := call(token, http.MethodPost, *apiURL+"/v1/nodes/register", raw)
	if err := json.Unmarshal(res, &node); err != nil {
		log.Fatal(err)
	}
	log.Printf("registered %s as %s backends=asic,fpga,zc", node.Name, node.ID)

	pipe := pipeline.New(model.Program{NodeID: node.ID})
	go poll(*apiURL, token, node.ID, pipe)
	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]string{"node": node.ID, "name": node.Name, "datapath": "asic-tcam+fpga+pfring-zc"})
	})
	mux.HandleFunc("/decide", func(w http.ResponseWriter, r *http.Request) {
		var f model.Flow
		if err := json.NewDecoder(r.Body).Decode(&f); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		d := pipe.Decide(f)
		d.NodeID = node.ID
		writeJSON(w, d)
	})
	log.Printf("node dataplane listening on %s", *listen)
	log.Fatal(http.ListenAndServe(*listen, mux))
}

func poll(apiURL, token, id string, pipe *pipeline.Pipeline) {
	client := &http.Client{Timeout: 5 * time.Second}
	for {
		req, _ := http.NewRequest(http.MethodPost, apiURL+"/v1/nodes/"+id+"/heartbeat", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		_, _ = client.Do(req)

		req, _ = http.NewRequest(http.MethodGet, apiURL+"/v1/nodes/"+id+"/program", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		resp, err := client.Do(req)
		if err == nil && resp.StatusCode == http.StatusOK {
			var prog model.Program
			if json.NewDecoder(resp.Body).Decode(&prog) == nil {
				pipe.Load(prog)
				log.Printf("programmed node %s version=%d asic=%d fpga=%d zc=%d prefixes=%v", id, prog.Version, len(prog.ASIC), len(prog.FPGA), len(prog.ZC), prog.Prefixes)
			}
			resp.Body.Close()
		} else if resp != nil {
			resp.Body.Close()
		}
		req, _ = http.NewRequest(http.MethodGet, apiURL+"/v1/ml/model", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		resp, err = client.Do(req)
		if err == nil && resp.StatusCode == http.StatusOK {
			var trained ml.Model
			if json.NewDecoder(resp.Body).Decode(&trained) == nil && trained.Ready {
				pipe.SetModel(trained)
			}
			resp.Body.Close()
		} else if resp != nil {
			resp.Body.Close()
		}
		time.Sleep(2 * time.Second)
	}
}

func call(token, method, url string, body []byte) []byte {
	req, err := http.NewRequest(method, url, bytes.NewReader(body))
	if err != nil {
		log.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 300 {
		log.Fatalf("%s %s: %s", method, url, raw)
	}
	return raw
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}
