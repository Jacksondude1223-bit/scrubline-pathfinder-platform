# Scrubline Cloud

Distributed denial-of-service scrubbing for SecNov. Multi-node, API-controlled, and built on ASIC/TCAM ACLs, FPGA meters, and PF_RING ZC. This is the cloud fabric, not the XDP host filter.

Attack traffic is steered onto scrubbing nodes. Each node drops in hardware first, then meters in the FPGA, then hands residual flows to a PF_RING ZC userspace inspect path. The control API compiles one policy into all three programs and assigns protected prefixes across the live nodes.

A node counts as live while it has heartbeated within the last 30 seconds. A node past that window is reported `stale` and is skipped by prefix assignment, so a prefix is never handed to a scrubber that stopped answering. A node that holds no prefix assignment enforces nothing.

## Datapath

Within a stage the first matching rule decides: `drop` and `permit` are both terminal, so a `permit` rule acts as an allow-list that exempts a source from the stages behind it. A TCAM entry carries no meter, so `rate_limit` is rejected on the `asic` stage.

1. ASIC / TCAM ACL. Longest-prefix and port ACLs. Terminal drops never leave the chip.
2. FPGA. Line-rate meters and flag matches for what the TCAM did not already drop.
3. PF_RING ZC. Zero-copy userspace inspect for residual traffic. No XDP redirect, no eBPF drop path. A logistic classifier trained from the control API scores this stage and drops flows over the threshold.

The model is flow-level only: rate, protocol, ports, and TCP flags. It does not inspect payloads. Train it with labeled samples, then nodes pull the weights on the same poll as the hardware program.

Hardware programming is represented as compiled programs the node agent pulls. A node without a switch ASIC, FPGA, or PF_RING license still enforces the same decision order in the software pipeline so the control plane can be tested. On an appliance, the agent writes the TCAM key, FPGA table, and `zc:<node>` cluster from that program.

## Run

```sh
export SCRUBLINE_API_TOKEN=dev-scrubline-token
go test ./...
go run ./cmd/scrub-api -addr 127.0.0.1:8080
```

In other shells:

```sh
export SCRUBLINE_API_TOKEN=dev-scrubline-token
go run ./cmd/scrub-node -name scrub-a -region iad -capacity 100 -listen 127.0.0.1:9091
go run ./cmd/scrub-node -name scrub-b -region fra -capacity 80 -listen 127.0.0.1:9092
go run ./cmd/scrub-node -name scrub-c -region sin -capacity 40 -listen 127.0.0.1:9093
sh scripts/demo.sh
go run ./cmd/scrubctl fabric
```

Three nodes in Docker:

```sh
SCRUBLINE_API_TOKEN=dev-scrubline-token docker compose -f deploy/docker-compose.yml up --build
```

## API

Bearer token is `SCRUBLINE_API_TOKEN`. Spec is in `api/openapi.yaml`. The token is required: an empty one is a misconfiguration, not a way to open the control plane. The node agent's own `/decide` takes the same bearer token; its `/health` is open for liveness probes.

Policies are validated on save. A prefix or match CIDR that does not parse is rejected rather than compiled into a rule that silently never matches, and flow records are rejected if `pps` is negative or a port falls outside 0..65535.

- `POST /v1/nodes/register` node name, region, capacity, backends
- `GET /v1/nodes`
- `POST /v1/policies` protected prefixes and stage rules
- `POST /v1/policies/{id}/deploy` assign prefixes across live nodes and compile ASIC, FPGA, ZC programs
- `POST /v1/nodes/{id}/heartbeat` keep a node live
- `GET /v1/fabric` assignments and compiled programs
- `GET /v1/nodes/{id}/program` what a node agent installs
- `POST /v1/decide` run a flow record through a node's pipeline
- `POST /v1/ml/samples` labeled flow records (`label` 0 clean, 1 attack)
- `POST /v1/ml/train` fit the ZC logistic model
- `GET /v1/ml/model` weights the node agent installs

Example policy: `configs/policy.example.json`. Example training set: `configs/ml.samples.json`.

```sh
go run ./cmd/scrubctl ml-load configs/ml.samples.json
go run ./cmd/scrubctl ml-train
```
