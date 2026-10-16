# Scrubline Cloud

Distributed denial-of-service scrubbing for SecNov. Multi-node, API-controlled, and built on ASIC/TCAM ACLs, FPGA meters, and PF_RING ZC. This is the cloud fabric, not the XDP host filter.

Attack traffic is steered onto scrubbing nodes. Each node drops in hardware first, then meters in the FPGA, then hands residual flows to a PF_RING ZC userspace inspect path. The control API compiles one policy into all three programs and assigns protected prefixes across the live nodes.

A node counts as live while it has heartbeated within the last 30 seconds. A node past that window is reported `stale` and is skipped by prefix assignment, so a prefix is never handed to a scrubber that stopped answering. A node that holds no prefix assignment enforces nothing.

The fabric is kept compiled against the live set rather than against whoever happened to be up at the last deploy. A node that registers or recovers after a deploy is compiled into the standing policy immediately, and the control plane re-checks membership every few seconds so a node that dies has its prefixes reassigned. If every node goes stale the last programs are kept rather than blanked, so whatever is still enforcing them keeps doing so.

Node IDs derive from name and region, so two scrubbers sharing both collapse onto one identity. A registration that would take over a node that is still live is refused with `409`; once the incumbent has aged out, a replacement is free to take the identity. Each agent advertises the address peers should dial with `-advertise` — it defaults to `-listen`, or to `hostname:port` when `-listen` is a wildcard.

## Datapath

Within a stage the first matching rule decides: `drop` and `permit` are both terminal, so a `permit` rule acts as an allow-list that exempts a source from the stages behind it. A TCAM entry carries no meter, so `rate_limit` is rejected on the `asic` stage.

Rules are ordered by `priority` on every stage, not just the ASIC, and the ordering is stable, so rules sharing a priority keep policy order and compile identically on every node. A node is only given entries for the backends it advertised at registration.

`count` is observe-only and never drops: it records the match and leaves the verdict to a later rule. Only two stage/action pairs consume `pps` — an `fpga` `rate_limit` meter, and the `zc` behavioral cap on `rate_limit` or `inspect`. A policy carrying `pps` anywhere else is rejected rather than accepted and ignored.

1. ASIC / TCAM ACL. Longest-prefix and port ACLs. Terminal drops never leave the chip.
2. FPGA. Line-rate meters and flag matches for what the TCAM did not already drop.
3. PF_RING ZC. Zero-copy userspace inspect for residual traffic. No XDP redirect, no eBPF drop path. A logistic classifier trained from the control API scores this stage and drops flows over the threshold.

The model is flow-level only: rate, protocol, ports, and TCP flags. It does not inspect payloads. Train it with labeled samples, then nodes pull the weights on the same poll as the hardware program.

One sample in five is held out of the fit, and the reported `accuracy`, `precision`, and `recall` are measured on that holdout. Watch precision: a false positive here is dropped customer traffic. Sets below ten samples are too small to split and report training metrics with `validation: 0`. `DELETE /v1/ml/model` retires a published model; agents clear their copy on the next poll, which is the only way to pull a bad model without restarting the fleet.

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

Three nodes in Docker. The nodes wait on the API's healthcheck, so they no
longer race it on startup. The token is read from the environment rather than
baked into the compose file, so it has to be set:

```sh
SCRUBLINE_API_TOKEN=dev-scrubline-token docker compose -f deploy/docker-compose.yml up --build
```

The control API is published on 8080 and the three node dataplanes on 9091,
9092, and 9093:

```sh
curl -H "Authorization: Bearer dev-scrubline-token" \
  -d '{"dst_ip":"203.0.113.10","proto":"tcp","dport":443,"pps":10}' \
  http://127.0.0.1:9091/decide
```

## Observability

Both binaries expose Prometheus metrics at `/metrics`. The exposition carries
rule IDs and traffic volumes, so it takes the same bearer token as the rest of
the control plane — configure the scraper with it. `/health` stays open for
liveness probes.

A node counts what its datapath did and attaches those counters to the
heartbeat it already sends every couple of seconds, so the control plane has a
fleet view without a second round trip. Both ends render the same metric names,
one series per node, so a dashboard written against a node works against the
control plane.

The counters that answer "is mitigation working, and which rule is doing the
work":

- `scrubline_rule_matches_total{node,stage,rule}` and `scrubline_rule_drops_total{...}` — per rule. A rule with matches and no drops is seeing traffic it is not acting on; a rule with neither is dead weight in the policy.
- `scrubline_stage_dropped_total{node,stage}` and `scrubline_stage_permitted_total{...}` — where in the pipeline traffic is being decided. Work moving from `asic` toward `zc` means the cheap stages are missing it.
- `scrubline_*_pps_total` — the same counts weighted by the per-flow rate reported on each decision. A volume indicator, not a packet counter.
- `scrubline_unowned_flows_total{node}` — flows for a prefix the node was not assigned. A rising value means the steering layer and the fabric disagree about who scrubs what.
- `scrubline_rate_buckets{node}` against `scrubline_rate_buckets_max{node}` — at the bound, the ZC behavioral cap has stopped tracking every source.
- `scrubline_report_age_seconds{node}` — how stale the control plane's copy of a node's counters is.

Counters survive a reprogram for rules that stay in the policy, so a poll every
two seconds does not reset the series. A rule that is removed, or moved to
another stage, takes its series with it.

The control plane also reports its own view: `scrubline_nodes{status}`,
`scrubline_assignments`, `scrubline_programs`, `scrubline_node_prefixes{node}`
(zero means the node is enforcing nothing), `scrubline_fabric_recompiles_total`,
the published model's holdout metrics, and
`scrubline_api_requests_total{route,status}`.

```sh
curl -H "Authorization: Bearer $SCRUBLINE_API_TOKEN" http://127.0.0.1:8080/metrics
curl -H "Authorization: Bearer $SCRUBLINE_API_TOKEN" http://127.0.0.1:9091/metrics
```

## API

Bearer token is `SCRUBLINE_API_TOKEN`. Spec is in `api/openapi.yaml`. The token is required: an empty one is a misconfiguration, not a way to open the control plane. The node agent's own `/decide` takes the same bearer token; its `/health` is open for liveness probes.

Policies are validated on save. A prefix or match CIDR that does not parse is rejected rather than compiled into a rule that silently never matches, and flow records are rejected if `pps` is negative or a port falls outside 0..65535.

- `POST /v1/nodes/register` node name, region, capacity, backends
- `GET /v1/nodes`
- `POST /v1/policies` protected prefixes and stage rules
- `POST /v1/policies/{id}/deploy` assign prefixes across live nodes and compile ASIC, FPGA, ZC programs
- `POST /v1/nodes/{id}/heartbeat` keep a node live; the body optionally carries the node's datapath counters
- `GET /v1/nodes/{id}/stats` the counters a node last reported
- `GET /v1/fabric` assignments and compiled programs
- `GET /metrics` Prometheus exposition for the control plane and the fleet
- `GET /v1/nodes/{id}/program` what a node agent installs
- `POST /v1/decide` run a flow record through a node's pipeline
- `POST /v1/ml/samples` labeled flow records (`label` 0 clean, 1 attack)
- `POST /v1/ml/train` fit the ZC logistic model
- `GET /v1/ml/model` weights the node agent installs
- `DELETE /v1/ml/model` retire the published model; agents clear it on the next poll

Example policy: `configs/policy.example.json`. Example training set: `configs/ml.samples.json`.

```sh
go run ./cmd/scrubctl ml-load configs/ml.samples.json
go run ./cmd/scrubctl ml-train
```
