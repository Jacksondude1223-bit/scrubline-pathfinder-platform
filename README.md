# Scrubline Cloud

Distributed denial-of-service scrubbing for SecNov. Multi-node, API-controlled, and built on ASIC/TCAM ACLs, FPGA meters, and PF_RING ZC. This is the cloud fabric, not the XDP host filter.

Attack traffic is steered onto scrubbing nodes. Each node drops in hardware first, then meters in the FPGA, then hands residual flows to a PF_RING ZC userspace inspect path. The control API compiles one policy into all three programs and assigns protected prefixes across the live nodes.

## Datapath

1. ASIC / TCAM ACL. Longest-prefix and port ACLs. Terminal drops never leave the chip.
2. FPGA. Line-rate meters and flag matches for what the TCAM did not already drop.
3. PF_RING ZC. Zero-copy userspace inspect for residual traffic. No XDP redirect, no eBPF drop path.

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

Bearer token is `SCRUBLINE_API_TOKEN`. Spec is in `api/openapi.yaml`.

- `POST /v1/nodes/register` node name, region, capacity, backends
- `GET /v1/nodes`
- `POST /v1/policies` protected prefixes and stage rules
- `POST /v1/policies/{id}/deploy` assign prefixes and compile ASIC, FPGA, ZC programs
- `GET /v1/fabric` assignments and compiled programs
- `GET /v1/nodes/{id}/program` what a node agent installs
- `POST /v1/decide` run a flow record through a node's pipeline

Example policy: `configs/policy.example.json`.
