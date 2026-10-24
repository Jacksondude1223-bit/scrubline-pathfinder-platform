# API

Two HTTP APIs, on different ports, with different credentials:

| | Served by | Spec | Guards |
| --- | --- | --- | --- |
| **Control plane** | `scrub-api` | [`api/openapi.yaml`](../api/openapi.yaml) | `SCRUBLINE_API_TOKEN`, `SCRUBLINE_ENROLL_TOKEN`, per-node credentials |
| **Node agent** | `scrub-node` | [`api/node-openapi.yaml`](../api/node-openapi.yaml) | `SCRUBLINE_NODE_API_TOKEN` |

The specs are the contract — schemas, status codes and which credential reaches
what. This page is the guide: how the pieces fit, and the behaviours that
surprise people. Every response below is copied from a real run.

To try these against something live rather than reading them, `make up` brings
up a seeded fabric with traffic running through it and prints two customers'
credentials; [`deploy/README.md`](../deploy/README.md) covers putting it on a
URL you can reach from elsewhere.

## Credentials

Three secrets, three blast radii. A scrubbing node sits at the edge in someone
else's datacentre, so it never holds one that can change the fabric.

| Credential | Held by | Reaches |
| --- | --- | --- |
| `SCRUBLINE_API_TOKEN` | operators, `scrubctl` | everything |
| `SCRUBLINE_ENROLL_TOKEN` | node agents | `POST /v1/nodes/register`, and nothing else |
| node credential | one scrubber | its own heartbeat, program and counters, plus `GET /v1/ml/model` |
| tenant credential | one protected customer | `GET /v1/analytics/*`, for their own prefixes only |
| `SCRUBLINE_NODE_API_TOKEN` | the agent and its scraper | that agent's `/decide`, `/egress`, `/metrics`, `/bgp`, `/tunnels`, `/sessions`, `/reputation` |

A node credential is issued at registration, scoped to that node, 256 bits,
kept only as a hash, and rotated whenever the node enrols again. A tenant
credential works the same way and is the narrowest thing the platform issues:
read-only, and blind to the fleet, the policy and every other customer. An
unset credential never matches: an empty token is a misconfiguration, not a way
to open the control plane.

## Status codes

| Code | Means |
| --- | --- |
| `400` | A field will not validate. The message names the offending index and why. |
| `401` | No credential, or one the control plane does not know. |
| `403` | The credential is valid but not allowed here. **Not** `404` — the API tells you it exists and you cannot have it. |
| `404` | The thing genuinely is not there. |
| `409` | A conflict: a duplicate live node, no live nodes to deploy onto, a tunnel address another node holds, a tunnel change with no deployed policy, a customer a tunnel is still allocated to, or a write sent to a replica. |
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

A game filter with an `http` block judges the requests sent to its address,
on TCP to its port or the block's own `ports`. With
`{"path": "/players.json", "rate_per_source": 1}` among its paths, a second
request for the player list inside a second is dropped:

```console
$ curl -H "Authorization: Bearer $API_TOKEN" -H 'Content-Type: application/json' \
    -d '{"node_id":"'$NODE'","flow":{"src_ip":"198.51.100.9","dst_ip":"203.0.113.20",
         "proto":"tcp","dport":30120,"pps":1,
         "payload":"R0VUIC9wbGF5ZXJzLmpzb24gSFRUUC8xLjENCkhvc3Q6IDIwMy4wLjExMy4yMDozMDEyMA0KDQo="}}' \
    $API/v1/decide
{"action":"drop","stage":"zc","filter":"fivem-30120","node_id":"node-469acf20d30b58d4",
 "reason":"game filter http: GET /players.json: more than 1 request a second to this path from this source"}
```

The README's [game filtering](../README.md#http-on-the-servers-own-address-layer-7)
section covers the rules.

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

### 8. Customer analytics

A customer buys protection for a prefix, not for a node. Under anycast that
prefix is carried by every scrubber at once, so nothing under `/v1/analytics`
is reported per node: it is keyed by prefix and summed across the fabric.

Onboard the customer, then issue their credential:

```console
$ curl -X POST -H "Authorization: Bearer $API_TOKEN" $API/v1/tenants -d '{
    "name":"Northwind Games","prefixes":["203.0.113.0/24"],
    "contact":"noc@northwind.example"}'
{"id":"ten-3699abaf8b8b4cf5","name":"Northwind Games","prefixes":["203.0.113.0/24"],
 "contact":"noc@northwind.example","created_at":"2026-10-17T11:35:58Z",
 "updated_at":"2026-10-17T11:35:58Z"}

$ scrubctl tenant-token ten-3699abaf8b8b4cf5
{"tenant_id":"ten-3699abaf8b8b4cf5","token":"<64 hex characters>"}
this credential is shown once; only its hash is kept
```

An entitlement covers everything **inside** it, so a customer who brings a /22
and has it protected as four /24s is entitled once rather than on every split.
Containment, not equality — a /24 entitlement never opens up the /22 around it.
Prefixes must be written masked; `203.0.113.5/24` is refused with the form to
use instead, because the entitlement is matched against what was written.

Now the customer's own view, with their own credential:

```console
$ curl -H "Authorization: Bearer $TENANT_TOKEN" "$API/v1/analytics/overview?window=1h"
{"window":"1h0m0s","resolution":"1m0s","retention":"24h0m0s",
 "generated":"2026-10-17T11:35:59Z",
 "tenant":{"id":"ten-3699abaf8b8b4cf5","name":"Northwind Games"},
 "prefixes":[
   {"prefix":"203.0.113.0/24","from":"2026-10-17T10:35:00Z","to":"2026-10-17T11:35:59Z",
    "flows":42000,"flows_dropped":40000,
    "offered":33000000,"dropped":32000000,"delivered":1000000,"challenged":240,
    "mitigated_pct":96.97,
    "peak_pps":2230000,"peak_dropped_pps":1600000,
    "offered_pps":1650000,"dropped_pps":1600000,
    "nodes":2,"under_attack":true,"pulsing":false,
    "attacks":1,"attack_seconds":1.04}]}
```

`nodes` is how many scrubbers are carrying this prefix right now. Under anycast
that is the fabric absorbing the attack — a customer seeing `1` during a flood
is seeing a problem, not a quiet day.

`delivered` is `offered - dropped`. It is a subtraction rather than its own
counter because the datapath only knows what it stopped.

#### The attack log

"You were attacked" on its own is not something a customer can act on, so every
event names what stopped it:

```console
$ scrubctl attacks 1h
STARTED               PREFIX          FOR           PEAK PPS  SCRUBBED PPS  SHAPE  STOPPED BY
2026-10-17T11:35:58Z  203.0.113.0/24  1s (ongoing)  2230000   1600000       flood  dns-amp(asic) mc-survival(zc)
```

```console
$ curl -H "Authorization: Bearer $TENANT_TOKEN" "$API/v1/analytics/events?window=1h"
{"window":"1h0m0s","events":[
  {"prefix":"203.0.113.0/24","started_at":"2026-10-17T11:35:58Z","ongoing":true,
   "seconds":1.04,"peak_pps":2230000,"peak_dropped_pps":1600000,
   "dropped":32180000,"flows":41800,"pulse":false,
   "vectors":[
     {"rule_id":"dns-amp","stage":"asic","flows":40000,"dropped":32000000},
     {"filter_id":"mc-survival","stage":"zc","flows":1800,"dropped":180000}]}]}
```

`ended_at` is **absent** while an attack is running, rather than a zero time.
When it closes it is dated to the moment the traffic stopped, not to the end of
the window spent confirming it: a customer is not under attack for the two
minutes it takes to be sure they are not.

An event opens when a meaningful share of a prefix's traffic is being scrubbed
— above a floor, so a stray packet against a quiet prefix is not billed as an
attack — or when the burst detector recognises a pulse train. It does **not**
close on the first quiet poll. A burst train is quiet between bursts by design,
and closing early would record one attack as fifty, which is exactly the
reporting the attacker's interval is paying for. `pulse: true` marks the ones
that were latched that way.

#### Over time

```console
$ curl -H "Authorization: Bearer $TENANT_TOKEN" \
    "$API/v1/analytics/series?prefix=203.0.113.0/24&window=10m&step=5m"
{"prefix":"203.0.113.0/24","window":"10m0s","step":"5m0s","points":[
  {"at":"2026-10-17T11:25:00Z","flows":0,"offered":0,"dropped":0,"delivered":0,
   "peak_pps":0,"offered_pps":0,"dropped_pps":0,"pulsing":false},
  {"at":"2026-10-17T11:30:00Z","flows":42000,"flows_dropped":40000,
   "offered":33000000,"dropped":32000000,"delivered":1000000,"challenged":240,
   "peak_pps":2230000,"offered_pps":1650000,"dropped_pps":1600000,"pulsing":false}]}
```

Each point reports the **heaviest moment inside it**, not an average over it.
An average is precisely what a burst attack is shaped to hide. Points are
aligned to the step, so two reads of the same dashboard line up.

#### What a tenant cannot reach

```console
$ curl -H "Authorization: Bearer $TENANT_TOKEN" \
    "$API/v1/analytics/series?prefix=198.51.100.0/24"      # another customer
{"error":"this credential is not entitled to that prefix"}            # 403

$ curl -H "Authorization: Bearer $TENANT_TOKEN" $API/v1/nodes
{"error":"listing the fleet requires the operator credential"}        # 403

$ curl -H "Authorization: Bearer $TENANT_TOKEN" $API/metrics
{"error":"the operator credential is required to scrape the control plane"}  # 403
```

The refusal for an unentitled prefix is the same whether or not that prefix
exists. A customer must not be able to map the platform's other customers by
watching which prefixes answer differently.

Offboarding takes the credential with it — one that outlived its tenant would
authenticate to an empty entitlement rather than to nothing:

```console
$ scrubctl tenant-rm ten-3699abaf8b8b4cf5
{"deleted":"ten-3699abaf8b8b4cf5"}
```

#### The operator's view

The same endpoints with the operator credential span every customer, and
`scrubctl analytics` renders them:

```console
$ scrubctl analytics 1h
PREFIX           OFFERED   SCRUBBED  MITIGATED  PEAK PPS  NOW PPS  NODES  ATTACKS  STATE
198.51.100.0/24  240000    0         0.0%       0         2400     2      0        clear
203.0.113.0/24   33000000  32000000  97.0%      2230000   1650000  2      1        UNDER ATTACK

over the last 1h0m0s
```

Per-node detail stays on `/metrics`, where the new `scrubline_prefix_*` series
break each node's traffic down by the prefix it was aimed at:

```
scrubline_prefix_offered_pps{node="…",name="edge-lhr",region="us-east",prefix="203.0.113.0/24"} 940000
scrubline_prefix_offered_pps{node="…",name="edge-fra",region="eu-central",prefix="203.0.113.0/24"} 710000
scrubline_prefix_dropped_pps{node="…",name="edge-lhr",region="us-east",prefix="203.0.113.0/24"} 910000
```

### 9. Getting the clean traffic back

BGP attracts the customer's traffic to the fabric. It cannot send it back:
once the scrubbers are announcing the prefix, a normal route toward it comes
straight back to the scrubbers. Clean traffic is encapsulated to the
customer's own edge instead, and that return path is declared in the policy:

```json
{
  "name": "delivered protection",
  "protected": ["203.0.113.0/24"],
  "tunnels": [{
    "id": "northwind",
    "remote": "198.51.100.1",
    "prefixes": ["203.0.113.0/24"],
    "key": 42
  }],
  "sessions": [{
    "id": "northwind",
    "peer_ip": "198.51.100.1", "peer_as": 64512,
    "prefixes": ["203.0.113.0/24"],
    "password": "s3cret-md5", "multihop": 2
  }]
}
```

Each node terminates the tunnel on its own address, which is per node, not
per tunnel. An operator assigns it through the API (below); a node can also
register with `tunnel_src`, or the agent be started with `-tunnel-src`, and
an operator's assignment takes precedence over both.

#### Each node's own address

The customer's GRE tunnel runs straight to the scrubbing node, so each node
needs an address the customer's edge can reach. Assign it per node:

```console
$ curl -X PUT -H "Authorization: Bearer $API_TOKEN" -H 'Content-Type: application/json' \
    $API/v1/nodes/node-20c0e739603a7b60/tunnel-endpoint -d '{"address":"192.0.2.1"}'
{"id":"node-20c0e739603a7b60","name":"edge-lhr","region":"lhr","status":"ready",
 "tunnel_src":"192.0.2.1","tunnel_endpoint_assigned":true,…}
```

The fabric recompiles on the spot, and the agent builds its tunnels from that
address on its next poll. The assignment belongs to the operator: it survives
the node re-registering, so a node cannot move its own tunnels. It reaches the
agent in its program; registration answers with what the node registered.

Two nodes on one address are refused with a `409`, since each would take the
other's customer replies. That covers assigning, registering, and `DELETE` on
the same path, which returns the node to what it registered with unless that
address has since gone to another node. A node that has stopped heartbeating
keeps an address an operator assigned it, but not one it only registered
with, so a replacement box can take the old one's address. If the old one
comes back to find its address given away, the stronger claim keeps it (an
operator's assignment, then a live node over a quiet one) and the other
withdraws its tunnels' prefixes until it has an address of its own;
`GET /v1/tunnels` says so. An address that is a deployed tunnel's customer
end, or that sits inside a protected prefix (which the fabric anycasts), is
refused with a `400`, and a node whose address ends up that way by another
route, registering with it or a policy coming to protect it, withdraws the
tunnels' prefixes instead of building them.

The same address is what the node peers customer BGP sessions from.

Scrubline does not put the address on the box. It must be one the node
already owns and that is routed to it; a node told to build tunnels from an
address it does not have builds tunnels nothing reaches. Upgrade agents before
assigning endpoints: an agent from before this release takes no endpoint from
its program and keeps peering customer sessions from the address it started
with. Upgrade replicas before their primary, too: a control plane from before
this release drops the assignments from the state it follows.

#### One tunnel per customer, at the location you choose

Pin a tunnel to a node and the customer holds one GRE tunnel, to that node's
address. Moving it is one call, which is what a panel offering a choice of
location makes:

```console
$ curl -X PUT -H "Authorization: Bearer $API_TOKEN" $API/v1/tunnels/northwind/location \
    -d '{"node":"node-20c0e739603a7b60"}'
{"policy_id":"p","version":4,"tunnel":{"id":"northwind","remote":"198.18.0.9","key":42,
 "prefixes":["203.0.113.0/24"],"node":"node-20c0e739603a7b60",…}}
```

The location must be in the steering regions of every prefix the tunnel
carries, or it could never announce them; a node outside them is refused, as
is deploying a policy that pins a tunnel to one. Naming the node a tunnel is
already at changes nothing.

Traffic for the customer goes to that location: it alone announces their
prefixes while it copes. The rest of the fabric stands by:

```console
$ scrubctl bgp
PREFIX          NODE  REGION  STATE     PREPENDS  WHY
203.0.113.0/24  fra   eu      withdraw  -         standing by: return tunnel northwind is at lhr, and this node announces only while that one is overloaded or down
203.0.113.0/24  lhr   eu      announce  0         anycast member at full preference
```

When the location passes 80% of its `-capacity-pps`, the same mark that pads
it for load, or stops heartbeating, the other nodes carrying the prefixes
announce them too, and anycast spreads the attack across them. They scrub what
they attract and forward the clean traffic to the location over node-to-node
GRE (`sbh-*` interfaces), which delivers all of it down the customer's one
tunnel. Help holds for five minutes after the location was last measured
overloaded: help takes load off it, and ending help the moment it recovers
would put the traffic straight back and flap the routes with every swing.

The node-to-node tunnels stay up while the others stand by, so help starts the
moment BGP moves traffic, and traffic still arriving after it moves back is
delivered rather than dropped. What a node receives over them must be
addressed to a customer pinned there:

```console
$ curl -H "Authorization: Bearer $NODE_API_TOKEN" 'http://lhr:9091/tunnels?format=iproute2'
ip link add scr-northwind type gre local 192.0.2.1 remote 198.18.0.9 key 42
ip link set scr-northwind mtu 1472 up
ip route replace 203.0.113.0/24 dev scr-northwind
ip link add sbh-b981c02c78d type gre local 192.0.2.1 remote 192.0.2.2
ip link set sbh-b981c02c78d mtu 1476 up
nft add rule inet scrubline forward oifname "scr-northwind" tcp flags syn tcp option maxseg size set 1432
nft add rule inet scrubline forward oifname "sbh-b981c02c78d" tcp flags syn tcp option maxseg size set 1436
nft add rule inet scrubline forward iifname "sbh-*" ip daddr != { 203.0.113.0/24 } drop
nft add rule inet scrubline forward iifname "sbh-*" meta nfproto ipv6 drop
…
tc qdisc replace dev scr-northwind root tbf rate 1000000kbit burst 1250000 latency 50ms

$ curl -H "Authorization: Bearer $NODE_API_TOKEN" 'http://fra:9091/tunnels?format=iproute2'
ip link add sbh-6deacd5f1df type gre local 192.0.2.2 remote 192.0.2.1
ip link set sbh-6deacd5f1df mtu 1476 up
ip route replace 203.0.113.0/24 dev sbh-6deacd5f1df
…
```

If the location cannot deliver (its tunnel is reported down, it has no
endpoint, the tunnel is disabled there), the others withdraw too, since they
would have nowhere to forward to. A location that stops heartbeating is still
helped: if its box is forwarding, the others reach the customer through it;
if it is gone, so is the customer's only tunnel, and help only absorbs the
attack. After the control plane restarts, or a replica is promoted, a node it
has not heard from yet counts as down only once the 30-second heartbeat
timeout has passed, so the first node to check in does not announce for all
the others. For a customer that must ride out losing a location, fan the
tunnel out instead.

`GET /v1/tunnels` gives each tunnel's `node`, `location` name and whether it is
in `overflow`, and each node's `role`: `location`, or `helper` with
`standing_by` and the node-to-node interface it forwards over.

#### Or one tunnel per node

A tunnel with no `node` fans out. The fabric is anycast, every eligible node
announces every protected prefix, and each of them holds its own tunnel to the
customer's one endpoint, from its own address. Ten scrubbers protecting one
customer is ten tunnels at the customer's end.

```console
$ curl -H "Authorization: Bearer $NODE_API_TOKEN" 'http://node-a:9091/tunnels?format=iproute2'
# Northwind primary return path
ip link add scr-northwind type gre local 192.0.2.1 remote 198.18.0.9 key 42
ip link set scr-northwind mtu 1472 up
ip route replace 203.0.113.0/24 dev scr-northwind
nft add rule inet scrubline forward oifname "scr-northwind" tcp flags syn tcp option maxseg size set 1432
nft add rule inet scrubline forward iifname "scr-northwind" ip saddr != { 203.0.113.0/24 } drop
nft add rule inet scrubline forward iifname "scr-northwind" meta nfproto ipv6 drop
nft add rule inet scrubline forward iifname "scr-northwind" tcp flags syn tcp option maxseg size set 1432
tc qdisc replace dev scr-northwind root tbf rate 1250000kbit burst 1562500 latency 50ms

$ curl -H "Authorization: Bearer $NODE_API_TOKEN" 'http://node-b:9091/tunnels?format=iproute2'
# Northwind primary return path
ip link add scr-northwind type gre local 192.0.2.2 remote 198.18.0.9 key 42
...
```

Same customer endpoint, different local end. As with `/bgp`, the agent only
compiles the configuration and serves it. The provisioner that
[`scripts/install.sh`](install.md) installs beside it applies it to the box
every few seconds (building, rebuilding and removing interfaces, routes,
rules and shapers to match) and reports which customer tunnels it built.
Bring your own instead with `--no-provision`.

#### Replies come back up the same tunnel

By default a tunnel carries traffic both ways: clean traffic goes down it to
the customer, and the customer's replies come back up it to the node, which
forwards them to the internet. That is what lets a customer run with no
transit of its own. The agent renders the rules for that half too:

```console
$ curl -H "Authorization: Bearer $NODE_API_TOKEN" 'http://node-a:9091/tunnels?format=iproute2'
# Northwind primary return path
ip link add scr-northwind type gre local 192.0.2.1 remote 198.18.0.9 key 42
ip link set scr-northwind mtu 1472 up
ip route replace 2001:db8::/32 dev scr-northwind
ip route replace 203.0.113.0/24 dev scr-northwind
nft add rule inet scrubline forward oifname "scr-northwind" tcp flags syn tcp option maxseg size set 1412
nft add rule inet scrubline forward iifname "scr-northwind" ip saddr != { 203.0.113.0/24 } drop
nft add rule inet scrubline forward iifname "scr-northwind" ip6 saddr != { 2001:db8::/32 } drop
nft add rule inet scrubline forward iifname "scr-northwind" tcp flags syn tcp option maxseg size set 1412
```

Only sources inside the tunnel's own prefixes may come back up it, per
address family. Without that the tunnel is an open relay for anything the
customer's edge sends into it, spoofed or not. That is every prefix of the
tunnel, including any steered away from this node, since a customer routes its
replies up whichever tunnel it likes. A more specific prefix of another tunnel
belongs to that customer, as routing goes by the most specific prefix, so it
is refused even inside one of this tunnel's, whether or not that tunnel is
built on this node. SYNs coming up are clamped like the ones going
down, so the far side's segments fit the tunnel too. The rules assume the
`inet scrubline` table and its `forward` chain exist, as the MSS clamp always
has.

`"direction": "return"` on the tunnel is for customers whose replies leave by
their own transit: the tunnel then only carries clean traffic out, and
nothing that comes up it is forwarded
(`nft add rule inet scrubline forward iifname "scr-northwind" drop`).

#### The tunnel firewall

Each node accepts GRE and IPIP (IP protocols 47 and 4) only from the
addresses it has tunnels with: every other node's tunnel endpoint, for
node-to-node forwarding, and the customer end of each tunnel it builds.
Neither is accepted over IPv6.

```
nft add rule inet scrubline input meta l4proto { 47, 4 } ip saddr != { 192.0.2.2, 198.18.0.9 } drop
nft add rule inet scrubline input meta nfproto ipv6 meta l4proto { 47, 4 } drop
```

The list is compiled from the fabric, so when a server is installed and
enrols, every node accepts its tunnels on the next compile, and when one goes,
it is dropped.

#### Controlling tunnels from the API

Tunnels belong to the deployed policy, so they can be changed in place
without saving and deploying a whole policy. Each change is validated with the
whole policy, saved as its next version, and compiled onto the fabric straight
away. They need a deployed policy; with none, they answer `409`.

```console
$ curl -H "Authorization: Bearer $API_TOKEN" $API/v1/tunnels
{"policy_id":"p","version":1,"tunnels":[{"id":"northwind","type":"gre","direction":"both",
  "remote":"198.18.0.9","key":42,"prefixes":["203.0.113.0/24","2001:db8::/32"],"disabled":[],
  "nodes":[{"node_id":"node-20c0e739603a7b60","name":"edge-lhr","region":"lhr","status":"ready",
            "endpoint":"192.0.2.1","endpoint_assigned":true,"enabled":true,"state":"unreported",
            "interface":"scr-northwind","mtu":1472,"mss_clamp":1412,
            "prefixes":["203.0.113.0/24","2001:db8::/32"],
            "announced":["2001:db8::/32","203.0.113.0/24"],"withdrawn":[]}]}]}
```

Every node carrying a tunnel's prefixes is listed with the address it
terminates on, what its provisioner last reported and what the fabric is
announcing from it. A node with a `problem` is not delivering those prefixes,
and the problem says why — usually that it has no endpoint yet.

| Call | What it does |
| --- | --- |
| `PUT /v1/tunnels/{id}` | Add a tunnel, or replace it whole. The id comes from the path. |
| `DELETE /v1/tunnels/{id}` | Remove it. Its prefixes are announced without a return path, like any prefix that never had one. |
| `POST /v1/tunnels/{id}/disable` | `{"nodes":["…"]}`: those nodes stop building it and withdraw its prefixes. |
| `POST /v1/tunnels/{id}/enable` | `{"nodes":["…"]}`: undo that. |
| `PUT /v1/tunnels/{id}/rate` | `{"rate_mbps":1000}`: change only its clean-traffic allowance. |
| `PUT /v1/tunnels/{id}/location` | `{"node":"node-…"}`: pin it to the node the customer's one tunnel ends on; `""` fans it out again. |

`GET /v1/tunnels?tenant=ten-…` lists only the tunnels allocated to one
customer.

Disabling is for maintenance on one site's path, or taking a misbehaving one
out without touching the rest of the fabric:

```console
$ curl -X POST -H "Authorization: Bearer $API_TOKEN" $API/v1/tunnels/northwind/disable \
    -d '{"nodes":["node-20c0e739603a7b60"]}'
{"policy_id":"p","version":2,"tunnel":{"id":"northwind","remote":"198.18.0.9",
 "prefixes":["203.0.113.0/24","2001:db8::/32"],"key":42,
 "disabled":["node-20c0e739603a7b60"],…}}

$ scrubctl bgp
PREFIX           NODE      REGION  STATE     PREPENDS  WHY
203.0.113.0/24   edge-lhr  lhr     withdraw  -         return tunnel northwind is disabled on this node
```

#### Allocating a tunnel to a customer, with a speed

A tunnel is allocated to a customer by naming their tenant id. Name its
`prefixes` and each must lie within the customer's own prefixes, so a tunnel
can never hand one customer's clean traffic to another's edge. Leave them out
and it carries the protected prefixes that are the customer's own and that no
other tunnel already carries. A reseller's tunnel does not pick up a prefix
that one of its customers, also a tenant, covers more specifically, though it
may still carry it when named.

```console
$ curl -X PUT -H "Authorization: Bearer $API_TOKEN" $API/v1/tunnels/northwind -d '{
    "remote": "198.18.0.9", "key": 42,
    "tenant": "ten-706ac6846f855fa4", "rate_mbps": 1000,
    "comment": "Northwind primary return path"}'
{"policy_id":"p","version":2,"tunnel":{"id":"northwind","remote":"198.18.0.9","key":42,
 "prefixes":["203.0.113.0/24","2001:db8::/32"],"tenant":"ten-706ac6846f855fa4",
 "rate_mbps":1000,"comment":"Northwind primary return path"}}
```

`rate_mbps` is how much clean traffic the customer receives down the tunnel,
in Mbit/s, **in total**, at most 2500 (2.5 Gbit/s). A tunnel without one is
held to that maximum, so no tunnel is ever unlimited. Changing only the speed:

```console
$ curl -X PUT -H "Authorization: Bearer $API_TOKEN" $API/v1/tunnels/northwind/rate \
    -d '{"rate_mbps":2000}'
{"policy_id":"p","version":3,"tunnel":{…,"rate_mbps":2000,…}}

$ curl -X PUT -H "Authorization: Bearer $API_TOKEN" $API/v1/tunnels/northwind/rate \
    -d '{"rate_mbps":5000}'
{"error":"rate_mbps must be within 1..2500 (2.5 Gbit/s); 0 takes the maximum"}
```

A tunnel that fans out runs from every node carrying the customer's prefixes,
and the allowance is split evenly across the nodes announcing them. Two nodes
sending a 2000 Mbit/s tunnel get 1000 Mbit/s each,
which `GET /v1/tunnels` shows per node as `rate_kbps`, and each node shapes
what it sends down the tunnel to its share:

```
tc qdisc replace dev scr-northwind root tbf rate 1000000kbit burst 1250000 latency 50ms
```

A shaper rather than a policer, so TCP sees queueing it backs off from rather
than drops. When a node stops announcing (withdrawn, disabled, or gone quiet)
the others' shares grow to cover the whole allowance on the next recompile.
A withdrawing node keeps the same share for the traffic BGP has yet to move
away, so for the seconds a withdrawal takes to converge the total can briefly
run over by the withdrawing nodes' shares. With no node announcing, the live
nodes still building the tunnel split it between them.
`scrubline_tunnel_rate_limit_bits_per_second` on each node's `/metrics` is
the share it is enforcing.

A pinned tunnel has none of this to work out: all of the customer's clean
traffic leaves through its location, so the location shapes to the whole
allowance, and the cap is exact.

For a fanned-out tunnel the split is even, not by where the traffic lands.
Anycast rarely spreads a customer's traffic evenly across the fabric, so the
node nearest most of their users can be held to its share while others sit
under theirs, and the customer then receives less than the allowance in total.
Give such a tunnel headroom over what the customer's link needs, steer its
prefixes to fewer nodes, or pin it.

A customer with a tunnel allocated cannot be deleted, or have their prefixes
changed so the tunnel carries something outside them; both answer `409`
naming the tunnel.

#### The MTU and the clamp are not decoration

| Encapsulation | Overhead | MTU | MSS clamp |
| --- | --- | --- | --- |
| GRE | 24 | 1476 | 1436 |
| GRE with a key | 28 | 1472 | 1432 |
| IPIP | 20 | 1480 | 1440 |

Both are derived unless you set them, and an MTU that does not fit the
encapsulation is refused with the largest one that does. A tunnel pinned to a
location also clamps to what node-to-node GRE carries (1436, or 1416 with IPv6
prefixes), since the traffic other nodes scrub for it reaches the location over
that: a pinned IPIP tunnel clamps to 1436. The clamp is the
part people skip: a tunnel with a correct MTU still hangs for any customer
whose path drops the ICMP that path-MTU discovery depends on. The handshake
completes, the first full-size segment does not, and the connection sits
there looking like a scrubbing fault.

#### A dead return path withdraws the prefix

This is the failure worth designing for. A node announcing a prefix it cannot
deliver attracts the customer's traffic and drops all of it — and it looks
healthy from every other angle: the datapath counters are fine, the
announcements are up, the customer is simply offline.

So whatever provisions the tunnels reports back, and that reaches the plan:

```console
$ curl -X POST -H "Authorization: Bearer $NODE_API_TOKEN" http://node-a:9091/tunnels \
    -d '{"tunnels":[{"tunnel_id":"northwind","state":"down","detail":"peer unreachable"}]}'
{"accepted":1}
```

The agent forwards it on its next heartbeat and the fabric recompiles:

```console
$ scrubctl bgp
PREFIX           NODE      REGION  STATE     PREPENDS  WHY
198.51.100.0/24  edge-lhr  lhr     announce  0         anycast member at full preference
198.51.100.0/24  edge-fra  fra     announce  0         anycast member at full preference
203.0.113.0/24   edge-lhr  lhr     withdraw  -         return tunnel northwind is down
203.0.113.0/24   edge-fra  fra     announce  0         anycast member at full preference
```

One node withdrawn, one prefix, named cause. The other customer on the same
node is untouched, and the rest of the fabric picks the traffic up — this is
a shed, not an outage. It comes back when the tunnel does.

**Silence is not treated as failure.** A tunnel that has never reported does
not withdraw anything: absence of a report usually means nothing is reporting,
and inferring failure from silence would blank the fabric of anyone who has
not wired a provisioner up yet. `"required": true` on the tunnel reverses that
judgement for operators who would rather drop traffic than black-hole it.

`scrubline_tunnel_up` follows the same rule — a never-reported tunnel is
**absent** from that series rather than reading `0`, so an alert on it does
not fire across a fleet that simply is not reporting.
`scrubline_tunnel_reported` is how you tell the two apart.

#### Customer sessions

For customers who announce their own prefixes rather than having them typed
into a policy. Rendered as BIRD, not as the ExaBGP commands `/bgp` serves:
announcing is an imperative act, which is what a command pipe is for, while
peering is a standing configuration with a filter and a limit on it.

```console
$ curl -H "Authorization: Bearer $NODE_API_TOKEN" 'http://node-a:9091/sessions?format=bird'
protocol bgp cust_northwind {
    description "Northwind Games edge";
    local 192.0.2.1 as 65000;
    neighbor 198.18.0.9 as 64512;
    password "s3cret-md5";
    multihop 2;
    ipv4 {
        import filter { if net ~ [ 203.0.113.0/24+ ] then accept; reject; };
        import limit 8 action restart;
        export none;
    };
}
```

The filter admits the policy's prefixes and anything more specific inside
them, because customers de-aggregate under attack and a filter that refused
that would drop the announcement at the moment it mattered most.

**Routes learned from a customer do not add themselves to the protected set.**
The policy still decides what the fabric defends. A peer that leaked a
supernet would otherwise have you announcing address space nobody asked you
to protect, on the say-so of the peer.

Sessions are scoped with `nodes` or `regions` — a customer peers where they
have a path, not with the whole fabric. Leaving both empty means everywhere,
which is rarely what anyone wants.

### 10. Source reputation

Two tiers, both keyed on what a source has already proved.

```json
"reputation": {"fast_pass": "challenge", "penalty_box": true}
```

`penalty_box` is off unless asked for; `fast_pass` defaults to `challenge`.
Walking a real A2S client through it:

```console
# 1. An unverified query is challenged.
{"action":"challenge","reason":"game filter a2s: unverified source challenged"}

# 2. It echoes the cookie back and is admitted.
{"action":"permit","reason":"PF_RING ZC inspect pass"}

# 3. Every packet after that takes the short path.
{"action":"permit","reason":"verified source, fast path"}
```

The short path skips the gate and the classifier, because clearing the gate
already established what they would say. **980 → 695 ns per packet.**

It does not skip the behavioural cap or the signature check — so junk
spoofing that verified address is still dropped, and the real player is
unaffected:

```console
# Junk claiming to be the verified player.
{"action":"drop","reason":"game filter a2s: packet carries none of this protocol's magic sequences"}

# The real player, immediately after.
{"action":"permit","reason":"verified source, fast path"}
```

That is the property worth testing in your own deployment. Source addresses
are attacker-controlled, so a penalty box that acted on them would let anyone
get a real player banned. Strikes against a trusted source are counted as
`shielded` and not acted on.

#### The penalty box

Four failures inside thirty seconds and an unverified source is boxed — a
minute, then ten, then an hour — and dropped at the top of the pipeline:

```console
{"action":"drop","reason":"source is in the penalty box"}
```

**1389 → 203 ns per packet, and the allocations go to zero.** During an
attack most of the packets are the attacker's, which is where the headroom
comes from.

The escalation decays after an hour of clean time measured from the *end* of
the last penalty, not the last strike — otherwise serving a sentence counts
as good behaviour.

#### Seeing it, and undoing it

```console
$ curl -H "Authorization: Bearer $NODE_API_TOKEN" node:9091/reputation
{"node":"node-…","stats":{"tracked":2,"trusted":1,"penalised":1,"fast_passed":3,
 "boxed":1,"promotions":1,"demotions":1,"strikes":11,"shielded":10,"full":0},
 "sources":[{"source":"198.51.100.9","state":"penalised","proof":"none",
             "expires_in_seconds":59.2,"level":1}, …]}

$ curl -X POST -H "Authorization: Bearer $NODE_API_TOKEN" node:9091/reputation \
    -d '{"release":["198.51.100.9"]}'
{"released":1}
```

A boxed source cannot promote itself out — it is dropped before it reaches a
gate — so this is the only way back, and it is an operator's call. The
escalation level survives a release: the next offence should not start from
scratch because this one was forgiven.

### 11. Return-traffic confirmation

Every other gate reasons about inbound packets, where the source address is
written by whoever sent it. Return traffic is the other direction, and it
needs no protocol knowledge: if the origin is answering an address at length,
the service considers it a client.

The datapath reports replies separately from decisions, because a reply is
not being judged:

```console
$ curl -X POST -H "Authorization: Bearer $NODE_API_TOKEN" node:9091/egress \
    -d '{"src_ip":"203.0.113.10","dst_ip":"192.0.2.50","proto":"udp","sport":30000,"pps":10}'
{"observed":true}
```

The flow is the reply: source is the protected address, destination is the
client. Ten packets across three 250 ms ticks confirms it — distinct ticks
rather than a count, because a burst in one instant is an origin bouncing
errors at a flood.

```console
# Before the origin has answered, with no dissector for this protocol:
{"action":"permit","reason":"PF_RING ZC inspect pass"}

# After sustained replies, with "fast_pass":"egress":
{"action":"permit","reason":"verified source, fast path"}
```

#### Lockdown

```json
"egress": {"lockdown": "limit", "lockdown_pps": 500, "grace_millis": 500}
```

While the prefix is pulsing, a source the origin has never answered is held
back — but only once it is past its grace:

```console
# A stranger arrives mid-attack. Its first packets get through.
{"action":"permit","reason":"PF_RING ZC inspect pass"}

# A second later, unconfirmed and out of grace:
{"action":"drop","reason":"no return traffic confirms this source while the prefix is under attack"}
```

Meanwhile the confirmed client keeps playing throughout.

The grace is load-bearing. Without it lockdown cannot be escaped: a new
client is unconfirmed, so it is held back, so its packets never reach the
origin, so the origin never answers. `limit` is the safer mode — an
unconfirmed source is capped rather than silenced.

**It never fires on a prefix whose return path is not visible.** With direct
server return there are no replies to see, and treating that as "nobody is
confirmed" would hold back every real player.

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

**Return traffic confirms a client, and it is weaker than a challenge.** The
order is handshake < egress < challenge: a handshake can be sent blind, a
challenge proves the address can receive, and return traffic proves the
service treats the address as a client — which an attacker can arrange by
spoofing a victim's address into a service that replies to anything.

**Lockdown needs a grace window or it is a trap with no exit.** An unconfirmed
client is held back, so its packets never reach the origin, so the origin
never answers, so it is never confirmed. Every new source gets 500 ms.

**Lockdown never fires on a prefix whose return path is invisible.** With
direct server return there is nothing to confirm against, and holding back
every client because of that is the outage the attacker wanted. Watch
`scrubline_egress_visibility`.

**A verified source skips the gate and the classifier, never the rate cap or
the signature check.** The cap is what bounds a verified source — without it,
clearing one challenge would be the whole attack — and it costs about four
nanoseconds, so there was nothing to save. The signature check stays because
the source address on a packet is written by whoever sent it.

**A trusted source is never put in the penalty box.** Acting on a stateless
signal would let anyone get a real player banned by spoofing their address.
Those strikes are counted as `shielded` instead; the junk is still dropped,
the player stays online. Alert on `scrubline_reputation_shielded_total`.

**A prefix has exactly one return path.** Two tunnels carrying one prefix is
refused: backup paths are not modelled, so there would be no answer to which
one is authoritative. Redundancy comes from the fabric — other nodes keep
announcing when one node's tunnel dies.

**Tunnel ids are interface names.** At most 11 characters, lowercase, and the
limit is enforced rather than left to the kernel, which truncates a long name
silently — two tunnels truncating to the same name is one tunnel.

**`403` is not `404`.** An endpoint you cannot reach says so. The one
deliberate exception is an analytics prefix a credential is not entitled to:
that answers `403` whether or not the prefix exists, so a customer cannot map
the platform's other customers by watching which ones answer differently.

**Analytics history is in memory, and is not durable.** It is derived from
reports that keep arriving, so a restarted control plane rebuilds it within a
couple of heartbeats — which beats carrying stale numbers across the gap. The
durable half (customers, entitlements, credential hashes) does survive.

**Nodes report cumulative counters; the control plane deltas them.** That is
deliberate. A counter that only counts up survives a report being missed, and
one that goes backwards is read as a node that restarted rather than as
negative traffic.

**An event's `dropped` is the sum over its vectors**, which can exceed the
prefix's own `dropped` total: a rule guarding several prefixes has its volume
attributed to each of them, marked `shared`. Read the prefix total when the two
disagree.

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
