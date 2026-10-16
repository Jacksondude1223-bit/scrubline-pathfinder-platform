# Scrubline Cloud

Distributed denial-of-service scrubbing for SecNov. Multi-node, API-controlled, and built on ASIC/TCAM ACLs, FPGA meters, and PF_RING ZC. This is the cloud fabric, not the XDP host filter.

Attack traffic is steered onto scrubbing nodes by anycast. Each node drops in hardware first, then meters in the FPGA, then hands residual flows to a PF_RING ZC userspace inspect path. The control API compiles one policy into all three programs and into the fabric's BGP posture.

A node counts as live while it has heartbeated within the last 30 seconds. A node past that window is reported `stale` and is withdrawn from anycast, so traffic moves to the nodes still answering.

The fabric is kept compiled against the live set rather than against whoever happened to be up at the last deploy. A node that registers or recovers after a deploy is compiled into the standing policy immediately, and the control plane re-checks membership every few seconds. If every node goes stale the last programs are kept rather than blanked, so whatever is still enforcing them keeps doing so.

Node IDs derive from name and region, so two scrubbers sharing both collapse onto one identity. A registration that would take over a node that is still live is refused with `409`; once the incumbent has aged out, a replacement is free to take the identity. Each agent advertises the address peers should dial with `-advertise` — it defaults to `-listen`, or to `hostname:port` when `-listen` is a wildcard.

## Steering

The fabric is anycast. Every eligible node announces every protected prefix, so
nothing is owned by one scrubber and an attack on a single prefix is absorbed by
the whole fabric instead of landing on whichever node won a hash. Traffic lands
wherever BGP decides is closest to the source, which also puts scrubbing near
the attack rather than hauling it across the backbone.

Three things shape the plan:

- **Capacity, as AS-path prepends.** The largest announcing node advertises
  unpadded; each halving of capacity relative to it costs one prepend, up to
  five. A prepend makes a node a less attractive path for sources that have a
  choice, which weights the split without pinning a prefix anywhere. A node
  whose capacity cannot be compared is padded to the maximum, so a bad
  registration sheds traffic rather than attracting it.
- **Liveness.** A node past its TTL is withdrawn, and the survivors re-weight
  against each other. That withdrawal *is* the failover — nothing is
  reassigned, and the prefix is still announced from everywhere else.
- **Measured load.** A node running near its packet-rate ceiling is padded
  further so the next-closest node takes the overflow, and is unpadded again
  once it recovers. See [Load-driven shedding](#load-driven-shedding).

### Load-driven shedding

Capacity weighting is static — it says how big a node is, not how busy. The
control loop adds the reactive half: each node reports the packet rate it is
carrying, averaged over ten seconds, and a node measured near its ceiling gets
extra prepends until it recovers.

A node declares its ceiling with `-capacity-pps`. It is separate from
`-capacity` because the ZC inspect path runs out of packets per second long
before it runs out of bits. **A node that does not declare one is never padded
for load** — an unmeasurable node is left alone rather than guessed at.

Three properties keep this from doing more harm than the saturation it is
fixing:

- **Hysteresis.** A node sheds above 80% of its ceiling and recovers below 50%.
  Between the two nothing moves, so a node sitting at its threshold does not
  oscillate.
- **Dwell.** A level holds for at least 30 seconds whatever the load does. BGP
  punishes churn — upstreams damp a route that flaps, and a damped route is
  worse than a saturated node. Load that crosses a watermark repeatedly cannot
  become a stream of updates.
- **Load pads; only death withdraws.** Shedding adds at most 3 prepends, on top
  of the capacity baseline and still bounded at 5 in total. A saturated node is
  never withdrawn: pulling it entirely would dump its whole share on its
  neighbours and can cascade the saturation across the fabric. It keeps
  scrubbing whatever still reaches it.

Counters that stop arriving hold the level where it is. Acting on a
measurement from minutes ago is worse than not acting.

Each step takes one dwell, so shedding ramps rather than jumps:

```
t=12s  offered=152000  scrub-a prepends=1   # crossed 80% of its 100k ceiling
t=44s  offered=171000  scrub-a prepends=2   # still saturated, one dwell later
t=+20s offered=0       scrub-a prepends=1   # recovering
t=+70s offered=0       scrub-a prepends=0   # back to full preference
```

`scrubline_steering_escalation{node}`, `scrubline_steering_load_ratio{node}`
and `scrubline_offered_pps{node}` show the loop working; without them a
deliberate shed is indistinguishable from a misconfiguration.

A policy can override the default posture per prefix:

```json
"steering": [
  {"prefix": "203.0.114.10/32", "regions": ["iad", "fra"], "communities": ["65000:100"]}
]
```

`regions` is a hard boundary, not a preference: a node outside them neither
announces the prefix nor inspects traffic for it, which is how a prefix is kept
inside a jurisdiction. Everything else is softer — a node that is *withdrawing*
still enforces policy on the prefix, because BGP takes time to converge and
traffic still arriving should be scrubbed rather than waved through.

Scrubline does not speak BGP itself. It compiles the plan, the same way it
compiles TCAM, FPGA, and ZC programs, and the agent serves it for the speaker
running beside it. `GET /bgp` on a node returns the plan as JSON;
`GET /bgp?format=exabgp` returns it as ExaBGP commands:

```
announce route 203.0.113.0/24 next-hop 198.51.100.3 as-path [ 65001 65001 65001 ]
announce route 203.0.114.10/32 next-hop 198.51.100.1 community [ 65000:100 ]
withdraw route 203.0.113.0/24 next-hop 198.51.100.1
```

Give the agent `-local-as` so it can pad the path, and `-bgp-next-hop` when the
address upstreams should route to differs from the one peers reach the node on.
Communities are validated when the policy is saved, not at the speaker: these
lines are written into a routing daemon's control pipe, so an unchecked value
would be a command injection into the thing that decides where the internet
sends traffic.

`scrubctl bgp` prints the fabric's current posture:

```
PREFIX           NODE     REGION  STATE     PREPENDS  NEXT HOP      WHY
203.0.113.0/24   scrub-a  iad     announce  0         198.51.100.1  anycast member at full preference
203.0.113.0/24   scrub-b  fra     announce  1         198.51.100.2  anycast member padded 1 to weight for capacity
203.0.113.0/24   scrub-c  sin     withdraw  -         198.51.100.3  node has not heartbeated within its TTL
```

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
export SCRUBLINE_ENROLL_TOKEN=dev-scrubline-enroll
go test ./...
go run ./cmd/scrub-api -addr 127.0.0.1:8080
```

In other shells (see [Credentials](#credentials); the agent never holds the
operator token):

```sh
export SCRUBLINE_ENROLL_TOKEN=dev-scrubline-enroll
export SCRUBLINE_NODE_API_TOKEN=dev-scrubline-node
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
SCRUBLINE_API_TOKEN=dev-scrubline-token \
SCRUBLINE_ENROLL_TOKEN=dev-scrubline-enroll \
SCRUBLINE_NODE_API_TOKEN=dev-scrubline-node \
  docker compose -f deploy/docker-compose.yml up --build
```

The compose file passes `-insecure`, because the compose network is not
loopback and these containers carry no certificates. That is for the demo; a
deployment mounts a certificate and drops the flag.

The control API is published on 8080 and the three node dataplanes on 9091,
9092, and 9093:

```sh
curl -H "Authorization: Bearer dev-scrubline-node" \
  -d '{"dst_ip":"203.0.113.10","proto":"tcp","dport":443,"pps":10}' \
  http://127.0.0.1:9091/decide
```

## Observability

Both binaries expose Prometheus metrics at `/metrics`. The exposition carries
rule IDs and traffic volumes, so the control plane's takes the operator
credential and each agent's takes that agent's local one. `/health` stays open for
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
- `scrubline_unowned_flows_total{node}` — flows for a prefix the node does not carry. A rising value means the steering layer and the fabric disagree about who scrubs what.
- `scrubline_bgp_announced{node,prefix}` and `scrubline_bgp_prepends{node,prefix}` — the steering posture. A prefix with no node at 1 is attracting no traffic to the fabric at all.
- `scrubline_offered_pps{node}` and `scrubline_dropped_pps{node}` — current packet rates, averaged over the node's load window. These are rates, not totals: they are what load-driven shedding reacts to.
- `scrubline_steering_escalation{node}`, `scrubline_steering_load_ratio{node}` and `scrubline_node_capacity_pps{node}` — the shedding loop. A node at a non-zero escalation is deliberately leaning away from traffic.
- `scrubline_rate_buckets{node}` against `scrubline_rate_buckets_max{node}` — at the bound, the ZC behavioral cap has stopped tracking every source.
- `scrubline_report_age_seconds{node}` — how stale the control plane's copy of a node's counters is.

Counters survive a reprogram for rules that stay in the policy, so a poll every
two seconds does not reset the series. A rule that is removed, or moved to
another stage, takes its series with it.

The control plane also reports its own view: `scrubline_nodes{status}`,
`scrubline_announcements`, `scrubline_programs`, `scrubline_node_prefixes{node}`
(zero means the node is enforcing nothing), `scrubline_fabric_recompiles_total`,
the published model's holdout metrics, and
`scrubline_api_requests_total{route,status}`.

```sh
curl -H "Authorization: Bearer $SCRUBLINE_API_TOKEN"      http://127.0.0.1:8080/metrics
curl -H "Authorization: Bearer $SCRUBLINE_NODE_API_TOKEN" http://127.0.0.1:9091/metrics
```

## Credentials

Three secrets, three blast radii. A scrubbing node sits at the edge in someone
else's datacentre, so it never holds a credential that can change the fabric.

| Secret | Held by | Can do |
| --- | --- | --- |
| `SCRUBLINE_API_TOKEN` | operators, `scrubctl` | everything: policy, deploy, ML, fabric, `/metrics` |
| `SCRUBLINE_ENROLL_TOKEN` | every node agent | register, and collect a credential. Nothing else |
| `SCRUBLINE_NODE_API_TOKEN` | the agent, and whatever scrapes it | that agent's own `/decide`, `/metrics`, `/bgp` |

Registering is also credential issue. The control plane mints a 256-bit
credential scoped to that node, returns it once, and keeps only its hash, so a
dump of the control plane hands nobody a working key. Re-enrolling rotates it,
and the superseded credential stops working immediately — a restarted agent
never leaves a second key behind. An agent that is told its credential is no
longer valid enrols again rather than failing in place.

What a node credential buys, and nothing more:

- heartbeat **as itself**, and report its own counters
- fetch **its own** program
- read the published model, which it installs

It cannot read another node's program, heartbeat as another node, list the
fleet, read the fabric, scrape the control plane, write a policy, deploy, or
touch the classifier. The enrollment credential cannot do any of those either:
on its own it only enrols. It is still a shared bootstrap secret, so protect
it — but a scrubber that is taken over yields a key scoped to one node, not
the control plane.

## Transport

Both binaries serve TLS with `-tls-cert` and `-tls-key`, and **refuse to serve
a routable address without it**. Credentials crossing a network in the clear
should be something an operator asks for, not something they get by leaving a
flag off; `-insecure` is that ask. Loopback is exempt so the single-host demo
stays simple.

Agents and `scrubctl` verify the control plane with the system roots, or with
`-ca` for a private CA. Verification is never disabled anywhere: an unverified
TLS connection is a plaintext connection that looks safe.

Throwaway certificates for trying it locally:

```sh
make certs
export SCRUBLINE_API_TOKEN=op-secret SCRUBLINE_ENROLL_TOKEN=enroll-secret
go run ./cmd/scrub-api -addr 127.0.0.1:8080 -tls-cert certs/server.pem -tls-key certs/server-key.pem
```

```sh
export SCRUBLINE_ENROLL_TOKEN=enroll-secret SCRUBLINE_NODE_API_TOKEN=node-local-secret
go run ./cmd/scrub-node -api https://127.0.0.1:8080 -ca certs/ca.pem \
  -name scrub-a -region iad -capacity 100 -capacity-pps 100000 \
  -listen 127.0.0.1:9091 -advertise 198.51.100.1:9091 -local-as 65001
go run ./cmd/scrubctl -api https://127.0.0.1:8080 -ca certs/ca.pem fabric
```

Listeners carry read, write, header and idle timeouts, so a handful of idle
connections cannot hold one open.

## API

Policies are validated on save. A prefix or match CIDR that does not parse is rejected rather than compiled into a rule that silently never matches, and flow records are rejected if `pps` is negative or a port falls outside 0..65535.

- `POST /v1/nodes/register` node name, region, capacity (`capacity_gbps` and `capacity_pps`), backends; returns the node and the credential issued to it
- `GET /v1/nodes`
- `POST /v1/policies` protected prefixes, stage rules, and per-prefix steering
- `POST /v1/policies/{id}/deploy` compile the ASIC, FPGA, and ZC programs and the fabric's BGP plan
- `POST /v1/nodes/{id}/heartbeat` keep a node live; the body optionally carries the node's datapath counters
- `GET /v1/nodes/{id}/stats` the counters a node last reported
- `GET /v1/fabric` the BGP announcement plan and the compiled programs
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

The node agent also takes `-local-as`, `-bgp-next-hop` and `-capacity-pps` for
steering; see [Steering](#steering).
