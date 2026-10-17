# API

Two HTTP APIs, on different ports, with different credentials:

| | Served by | Spec | Guards |
| --- | --- | --- | --- |
| **Control plane** | `scrub-api` | [`api/openapi.yaml`](../api/openapi.yaml) | `SCRUBLINE_API_TOKEN`, `SCRUBLINE_ENROLL_TOKEN`, per-node credentials |
| **Node agent** | `scrub-node` | [`api/node-openapi.yaml`](../api/node-openapi.yaml) | `SCRUBLINE_NODE_API_TOKEN` |

The specs are the contract — schemas, status codes and which credential reaches
what. This page is the guide: how the pieces fit, and the behaviours that
surprise people. Every response below is copied from a real run.

## Credentials

Three secrets, three blast radii. A scrubbing node sits at the edge in someone
else's datacentre, so it never holds one that can change the fabric.

| Credential | Held by | Reaches |
| --- | --- | --- |
| `SCRUBLINE_API_TOKEN` | operators, `scrubctl` | everything |
| `SCRUBLINE_ENROLL_TOKEN` | node agents | `POST /v1/nodes/register`, and nothing else |
| node credential | one scrubber | its own heartbeat, program and counters, plus `GET /v1/ml/model` |
| `SCRUBLINE_NODE_API_TOKEN` | the agent and its scraper | that agent's `/decide`, `/metrics`, `/bgp` |

A node credential is issued at registration, scoped to that node, 256 bits,
kept only as a hash, and rotated whenever the node enrols again. An unset
credential never matches: an empty token is a misconfiguration, not a way to
open the control plane.

## Status codes

| Code | Means |
| --- | --- |
| `400` | A field will not validate. The message names the offending index and why. |
| `401` | No credential, or one the control plane does not know. |
| `403` | The credential is valid but not allowed here. **Not** `404` — the API tells you it exists and you cannot have it. |
| `404` | The thing genuinely is not there. |
| `409` | A conflict: a duplicate live node, no live nodes to deploy onto, or a write sent to a replica. |
| `413` | The sample batch would push the training set past its limit. |
| `503` | Durable state could not be written. **The change was rolled back and did not take effect.** |

`503` is the one worth internalising: a write is durable before it is
acknowledged, so a caller is never told a policy was saved that the control
plane will forget.

```console
$ curl -H "Authorization: Bearer $NODE_CREDENTIAL" $API/v1/fabric
{"error":"the operator credential is required for this endpoint"}     # 403

$ curl -H "Authorization: Bearer nope" $API/v1/nodes
{"error":"missing or invalid bearer token"}                           # 401
```

## A walkthrough

### 1. Is it up, and is it the primary?

`/health` is the only unauthenticated endpoint. It carries no policy detail.

```console
$ curl $API/health
{"datapath":"asic-tcam+fpga+pfring-zc+ml","mode":"primary","product":"scrubline-cloud","status":"ok"}
```

A replica answers every read and refuses every write with `409`. Check `mode`
before wondering why a deploy was rejected.

### 2. Enrol a node

Registration is also credential issue. The token comes back **once** and is
never served again; re-registering rotates it and the previous one stops
working immediately.

```console
$ curl -H "Authorization: Bearer $ENROLL_TOKEN" -H 'Content-Type: application/json' \
    -d '{"name":"scrub-doc","region":"sin","capacity_gbps":40,"capacity_pps":400000,
         "advertise":"198.51.100.3:9091"}' \
    $API/v1/nodes/register
{
  "node": {
    "id": "node-9b2b54b605a7eb06", "name": "scrub-doc", "region": "sin",
    "capacity_gbps": 40, "capacity_pps": 400000,
    "backends": ["asic","fpga","zc"],
    "last_seen": "2026-10-17T10:59:40.680760921Z",
    "status": "ready", "advertise": "198.51.100.3:9091"
  },
  "token": "0121db9f57113b4c6b60742d26745a41207f196cdcd035305b0c2811bde2b42c"
}
```

- `capacity_gbps` weights AS-path prepends against the rest of the fabric.
- `capacity_pps` is what load-driven shedding measures against. **A node that
  declares none is never padded for load** — an unmeasurable node is left alone
  rather than guessed at.
- `advertise`'s host becomes the BGP next hop.

Node ids derive from name and region, so two scrubbers sharing both collapse
onto one identity. Registering over a node that is still live, from a different
address, is refused with `409`.

### 3. Save a policy

Saving does not deploy.

```json
{
  "name": "game-edge",
  "protected": ["203.0.113.0/24"],
  "pulse_floor_pps": 50000,
  "steering": [{"prefix": "203.0.113.0/24", "regions": ["iad","fra"], "communities": ["65000:100"]}],
  "games": [{"id":"bedrock","dst_cidr":"203.0.113.10/32","proto":"udp","dport":19132,"profile":"raknet"}],
  "rules": [
    {"id":"tcam-bogon","stage":"asic","action":"drop","priority":100,
     "match":{"src_cidr":"0.0.0.0/8","dst_cidr":"203.0.113.0/24"}},
    {"id":"fpga-udp","stage":"fpga","action":"rate_limit","priority":300,"pps":500000,
     "match":{"dst_cidr":"203.0.113.0/24","proto":"udp"}}
  ]
}
```

```console
$ curl -H "Authorization: Bearer $API_TOKEN" -H 'Content-Type: application/json' \
    -d @policy.json $API/v1/policies
{
  "id": "pol-1", "name": "game-edge", "version": 1, "pulse_floor_pps": 50000,
  "challenge_secret": "e31bd08ee2a140a6a8f36f157640b7b916c92ba23aa092f28d6547fa12bc4d94",
  "updated_at": "2026-10-17T10:59:56.036038266Z"
}
```

A policy carrying game filters is issued a `challenge_secret`, shared across the
fabric so a challenge cookie minted by one scrubber verifies on another — under
anycast a source's packets land on different nodes.

Everything is validated here rather than on fifty scrubbers:

```console
$ curl ... -d '{"name":"bad","protected":["203.0.113.0/24"],
                "rules":[{"id":"c","stage":"zc","action":"count","pps":10,"match":{}}]}'
{"error":"rules[0] (c): a count rule is observe-only and must not carry pps"}
```

### 4. Deploy

Compiles the ASIC, FPGA and ZC programs **and** the BGP announcement plan.
Agents pick theirs up on the next poll.

```console
$ curl -H "Authorization: Bearer $API_TOKEN" -X POST $API/v1/policies/pol-1/deploy
{
  "policy_id": "pol-1", "version": 1, "nodes": 3, "ml_ready": false,
  "datapath": "asic/tcam + fpga + pf_ring zc + ml",
  "announcements": [
    {"prefix":"203.0.113.0/24","node_id":"node-2db467ca3091c106","node_name":"scrub-b",
     "region":"fra","state":"announce","prepends":1,"communities":["65000:100"],
     "next_hop":"198.51.100.2","reason":"anycast member padded 1 to weight for capacity"},
    …
  ]
}
```

The plan covers **every registered node**, not only the live ones: a node that
stopped answering needs an explicit withdrawal, and one that comes back finds
its program already compiled.

### 5. What a node installs

```console
$ curl -H "Authorization: Bearer $API_TOKEN" $API/v1/nodes/$NODE/program
{
  "node_id": "node-469acf20d30b58d4", "policy_id": "pol-1", "version": 1,
  "prefixes": ["203.0.113.0/24"],
  "asic": [{"priority":100,"action":"drop",
            "match":{"src_cidr":"0.0.0.0/8","dst_cidr":"203.0.113.0/24"},
            "rule_id":"tcam-bogon",
            "tcam_key":"v4 src=0.0.0.0/8 dst=203.0.113.0/24 proto=* dport=0 sport=0 pri=100"}],
  "fpga": [{"table":"scrub_meter","priority":300,"meter_pps":500000,"action":"rate_limit",
            "rule_id":"fpga-udp","match":{"dst_cidr":"203.0.113.0/24","proto":"udp"}}],
  "announcements": [{"prefix":"203.0.113.0/24","state":"announce","prepends":0,
                     "next_hop":"198.51.100.1","reason":"anycast member at full preference", …}],
  "games": [{"id":"bedrock","dst_cidr":"203.0.113.10/32","proto":"udp","dport":19132,"profile":"raknet"}],
  "challenge_secret": "e31bd08ee2a1…", "pulse_floor_pps": 50000,
  "compiled_at": "2026-10-17T10:59:56.066780193Z"
}
```

`prefixes` is what the node **enforces**, which includes prefixes it is
currently withdrawing: BGP takes time to converge, and traffic still arriving
should be scrubbed rather than waved through.

`compiled_at` changes on every recompile, including one that reassigns prefixes
without bumping the policy version. **Key your reload on it**, not on
`version` alone.

### 6. Ask what a policy would do

```console
$ curl -H "Authorization: Bearer $API_TOKEN" -H 'Content-Type: application/json' \
    -d '{"node_id":"'$NODE'","flow":{"src_ip":"198.51.100.9","dst_ip":"203.0.113.10",
         "proto":"udp","dport":19132,"pps":40000,"payload":"hAECAw=="}}' \
    $API/v1/decide
{"action":"drop","stage":"zc","filter":"bedrock","node_id":"node-469acf20d30b58d4",
 "reason":"game filter raknet: packet id 0x84 from a source that has not completed the handshake"}
```

`payload` is base64 and only the ZC stage sees it. Rate and session state
accumulate across calls, so repeated calls can trip a behavioural cap or clear
a game filter's gate.

### 7. The classifier

```console
$ scrubctl ml-load configs/ml.samples.json
{"stored":40}

$ scrubctl ml-train
{"ready":true,"accuracy":1,"precision":1,"recall":1,"validation":8,"samples":40,
 "threshold":0.65,"epochs":300}
```

`accuracy`, `precision` and `recall` are measured on the **holdout**, not on the
samples the model was fitted on. One in five is held out; sets under ten samples
are too small to split and report `validation: 0`.

Watch precision rather than accuracy: a false positive here is dropped customer
traffic.

```console
$ curl -X DELETE -H "Authorization: Bearer $API_TOKEN" $API/v1/ml/model
{"ready":false,"withdrawn":true}
```

`withdrawn` is an explicit signal. Agents clear their installed copy when they
see it — the zero model cannot say this, because it is indistinguishable from
"never trained".

## The node agent

```console
$ curl -H "Authorization: Bearer $NODE_API_TOKEN" 'http://node:9091/bgp?format=exabgp'
announce route 203.0.113.0/24 next-hop 198.51.100.1 community [ 65000:100 ]
```

Scrubline does not speak BGP. It compiles the plan, the way it compiles the
TCAM, FPGA and ZC programs, and serves it here for the speaker running beside
the agent. Drop `?format=exabgp` for JSON, which also carries an `error` field
set when the plan could not be rendered — the datapath keeps running, but that
node is advertising something other than what the control plane decided.

The agent's `/decide` runs against the state **real traffic is being judged
against**, unlike the control plane's, which is why it is useful for confirming
a live node's behaviour.

## Things that surprise people

**The game filter never drops a packet it was given no payload for.** A
datapath not supplying payloads would otherwise blackhole a customer in
silence. It passes, and a counter climbs:

```console
$ curl -H "Authorization: Bearer $NODE_API_TOKEN" -H 'Content-Type: application/json' \
    -d '{"src_ip":"192.0.2.7","dst_ip":"203.0.113.10","proto":"udp","dport":19132,"pps":100}' \
    http://node:9091/decide
{"action":"permit","stage":"asic","reason":"no matching drop rule", …}

$ curl -H "Authorization: Bearer $NODE_API_TOKEN" http://node:9091/metrics | grep uninspectable
scrubline_game_uninspectable_total{…,filter="bedrock",profile="raknet"} 1
```

The decision says nothing about it; the counter is where you see it. A rising
`uninspectable` means the filter is doing nothing.

**`pps` is refused where it would be ignored.** Only an `fpga` `rate_limit`, and
a `zc` `rate_limit` or `inspect`, consume it. Set it on a `count` rule and the
policy is rejected rather than the value quietly dropped — a `count` rule that
silently metered was a real bug here once.

**`count` is observe-only and never drops.** It records the match and leaves the
verdict to a later rule.

**`*_pps_total` metrics sum per-flow rates.** They are a volume *weighting*, not
packet counters: `rate()` over them is not pps. `offered_pps` and `dropped_pps`
in `Stats` are moving averages over `load_window_seconds`, not totals.

**Under a burst train, shedding is judged on the peak.** A pulse attack keeps
its mean under the watermark on purpose, so `offered_pps` can read zero on a
node being knocked over. `pulsing`, `pulse_peak_pps` and the `pulse` array are
the real picture.

**`403` is not `404`.** An endpoint you cannot reach says so.

## Reading the specs

Both are OpenAPI 3.0.3 and resolve standalone:

```sh
# Render
docker run --rm -p 8081:8080 -e SWAGGER_JSON=/s/openapi.yaml -v "$PWD/api:/s" swaggerapi/swagger-ui

# Generate a client
openapi-generator-cli generate -i api/openapi.yaml -g go -o ./client
```

`make spec-check` verifies that every `$ref` resolves, every operation declares
responses and security, and — the part that matters — that the documented routes
match the dispatch switch in the code exactly, in both directions.
