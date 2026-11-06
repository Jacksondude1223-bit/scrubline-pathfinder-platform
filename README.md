# Scrubline Cloud

> **Rust implementation:** The control plane, node agent, packet-processing pipeline, CLI, demo traffic generator, and Vercel test adapter now run Rust. See [migration notes](docs/rust-migration.md) for compatibility and deployment details.

Distributed denial-of-service scrubbing for SecNov. Multi-node, API-controlled, and built on ASIC/TCAM ACLs, FPGA meters, and PF_RING ZC. This is the cloud fabric, not the XDP host filter.

Attack traffic is steered onto scrubbing nodes by anycast. Each node drops in hardware first, then meters in the FPGA, then hands residual flows to a PF_RING ZC userspace inspect path. Clean traffic goes back to the customer's own edge over a GRE or IPIP tunnel, because once the scrubbers announce a prefix there is no ordinary route back to it. The control API compiles one policy into all three datapath programs, the fabric's BGP posture, the return paths, and any BGP sessions the customer peers over.

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

### Burst attacks

A pulse attack sends short heavy bursts on a repeating interval instead of a
steady flood, and it beats a volumetric defence twice over. The average stays
low, so a mean never crosses a watermark: one second at five times capacity
every twenty seconds averages to a quarter of it. And the burst is over before
mitigation engages, so a defence that reacts to load and then relaxes spends
the attack chasing its own tail — which is the behaviour the attacker is
paying for.

Three things answer that.

**Traffic is measured at a resolution short enough to see a burst**, in
250ms buckets over a minute, per protected prefix, and judged on its *shape*
rather than its average: peak against mean, and how much of the horizon is
quiet. A train is three or more distinct bursts with a crest factor of four or
more and a duty cycle under a half.

Shape alone is not enough, because a sparse trickle has exactly the same shape
as an attack. A burst only counts if it clears `pulse_floor_pps`, which
belongs to the deployment — set it from what the protected service actually
carries.

**A recognised train latches.** Once a prefix is known to be under one, the
flag stands through the quiet stretches, and every further burst pushes the
lapse out. Nothing disengages between bursts, so the attacker's interval buys
them nothing. Staying flagged asks less than becoming flagged did, so
stretching the interval until the detector cannot see a train no longer clears
it either.

**Shedding is judged on the peak while the flag stands.** This is what makes
the attack visible to the steering loop at all. From a live run, measured at a
moment between bursts:

```
offered_pps (10s mean): 0        ->   0% of a 1M pps ceiling
pulse peak:             4000000  -> 400% of a 1M pps ceiling
pulsing: true
  -> scrub-a  announce  prepends 2  "padded 2, shedding measured load"
```

The mean says the node is idle. Judged on it, nothing would happen at all —
and the padding would unwind during every gap.

### Desynchronising our own cadences

Every repeating interval in the fabric is a schedule an attacker can learn. A
burst timed to land between two samples and stop before the next is measured
as nothing, and a fleet polling in lockstep hands out that schedule for free,
identically on every node.

The node heartbeat and the control plane's reconcile are therefore spread ±20%
around their nominal intervals, drawn from the system entropy source rather
than a seeded generator — a schedule recoverable from a node's start time
would be no better than a fixed one. A train tuned to one interval drifts into
the next sample instead of hiding between them, and no two nodes are blind at
the same moment. A surge does not wait for the schedule at all (see [How fast
the fabric reacts](#how-fast-the-fabric-reacts)), and nodes do not poll for
instructions: each program is handed over as it is compiled.

The ZC behavioural cap was a fixed window that reset wholesale, which let a
source send its whole allowance at the end of one window and again at the
start of the next: twice the cap, and exactly the shape a pulse sends. It now
counts over a trailing second built from 250ms slots. Those slots hold exact
counts rather than the usual weighted estimate of the previous window, because
that estimate assumes traffic is spread evenly through it and would drop a
flow sitting honestly at its cap.

`scrubline_pulse_active`, `_peak_pps`, `_mean_pps`, `_crest`, `_duty_cycle`,
`_bursts` and `_hold_seconds` carry this per prefix. Peak against mean is the
pair to watch: a wide gap is the attack.

### Load-driven shedding

Capacity weighting is static — it says how big a node is, not how busy. The
control loop adds the reactive half: each node reports the packet rate it is
carrying, and a node measured near its ceiling gets extra prepends until it
recovers.

It reports that rate twice: averaged over ten seconds, and over the last second
alone. Shedding goes by whichever is higher, so it starts within a second of a
flood arriving rather than once the flood has filled the ten-second mean.
Recovery waits for both to come down, so letting go is as slow as before.

A node declares its ceiling with `-capacity-pps`. It is separate from
`-capacity` because the ZC inspect path runs out of packets per second long
before it runs out of bits. **A node that does not declare one is never padded
for load** — an unmeasurable node is left alone rather than guessed at.

Three properties keep this from doing more harm than the saturation it is
fixing:

- **Burst trains hold.** While a prefix is flagged (see [Burst
  attacks](#burst-attacks)) the padding never unwinds, whatever the gaps look
  like, and the ratio is taken from the peak rather than the mean.
- **Hysteresis.** A node sheds above 80% of its ceiling and recovers below 50%.
  Between the two nothing moves, so a node sitting at its threshold does not
  oscillate.
- **Dwell.** A level holds for at least 30 seconds whatever the load does. BGP
  punishes churn — upstreams damp a route that flaps, and a damped route is
  worse than a saturated node. Load that crosses a watermark repeatedly cannot
  become a stream of updates. The exception is a node at twice its ceiling or
  more: it steps up again 5 seconds after its last change, since it is dropping
  at least half of what reaches it, which costs more than an extra update.
  Stepping down always waits the full 30.
- **Load pads; only death withdraws.** Shedding adds at most 3 prepends, on top
  of the capacity baseline and still bounded at 5 in total. A saturated node is
  never withdrawn: pulling it entirely would dump its whole share on its
  neighbours and can cascade the saturation across the fabric. It keeps
  scrubbing whatever still reaches it.

Counters that stop arriving hold the level where it is. Acting on a
measurement from minutes ago is worse than not acting.

Each step takes one dwell, so shedding ramps rather than jumps:

```
t=0.6s  last second=91200   mean=9120    scrub-a prepends=1   # crossed 80% of its 100k ceiling
t=31s   last second=171000  mean=171000  scrub-a prepends=2   # still saturated, one dwell later
t=+20s  last second=0       mean=0       scrub-a prepends=1   # recovering
t=+70s  last second=0       mean=0       scrub-a prepends=0   # back to full preference
```

A flood many times the ceiling takes the short dwell instead:

```
t=0.1s  last second=120000   scrub-a prepends=1   # a flood at 1.2M pps, 0.1s in
t=5s    last second=1200000  scrub-a prepends=2   # at twice its ceiling or more, 5s a step
t=10s   last second=1200000  scrub-a prepends=3
```

`scrubline_steering_escalation{node}`, `scrubline_steering_load_ratio{node}`,
`scrubline_offered_pps{node}` and `scrubline_surge_pps{node}` show the loop
working; without them a deliberate shed is indistinguishable from a
misconfiguration.

### How fast the fabric reacts

From the first packets of a flood bigger than a node can take to every node
holding its new instructions is under a second, and BGP propagation is all that
comes after it:

1. **The node sees it within the second.** The last-second rate crosses 80% of
   `-capacity-pps` after 0.8 × ceiling ÷ flood rate seconds: 0.4 s for a flood
   at twice the ceiling, 0.08 s at ten times. The ten-second mean alone took
   ten times as long.
2. **It tells the control plane at once.** The agent heartbeats the moment its
   last-second rate crosses that mark, rather than at its next heartbeat, up to
   two seconds away. It does so once per surge, and at most once a second however
   often surges start.
3. **The control plane decides on that heartbeat.** It moves the node's level
   and recompiles the fabric while answering it.
4. **Every node gets its program as it is compiled.** Agents do not poll for
   instructions: each keeps a request open at the control plane, answered as
   soon as its program changes. The helpers announce the node's pinned
   customers, and the node pads its own route, within milliseconds of the
   heartbeat.

[`scripts/reaction-time.py`](scripts/reaction-time.py) runs a control plane
and two nodes, floods one, and times it; CI holds it to under a second. On one
machine, with debug builds and the same flood run three times against each:

| Flood | Before | Now |
| --- | --- | --- |
| twice the ceiling | 4.2–5.8 s | 0.39–0.43 s |
| ten times the ceiling | 1.7–3.8 s | 0.08–0.09 s |

Nearly all of what is left is the last second filling to 80% of the ceiling.
From there to the other nodes holding their new programs took about a
millisecond on one machine; across a network it is two round trips more, the
heartbeat and the answer to each node's waiting request.

That is time to the routes a node serves its BGP speaker; how long the internet
takes to act on them is up to BGP.

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
address upstreams should route to differs from the one peers reach the node on,
or when `-advertise` is a hostname: only an address can be a next hop, so a
hostname leaves it off the commands and the agent warns at startup. An address
is a next hop only for routes of its own family: a node with an IPv4 next hop
announces its IPv6 prefixes without one, as it does for a hostname, rather
than with one a peer without extended next hops would refuse.
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

## Game filtering

A UDP flood aimed at a game server is trivially distinguishable from play:
the flood has the right destination port and nothing else right. The ASIC and
the FPGA cannot see that, because neither matches on payload, so the game
filter runs on the ZC stage where the packet is already in userspace. It sits
in front of the ZC rules, so a packet that is not the protocol its port
speaks dies before it reaches the behavioral cap or the classifier.

Nothing here is bound to a list of games the platform knows about. A filter
is bound to **a port on a protected address**, and the profile is either a
built-in or a signature written in the policy:

```json
"games": [
  {"id": "bedrock-19132", "dst_cidr": "203.0.113.10/32", "proto": "udp", "dport": 19132,
   "profile": "raknet"},
  {"id": "queries-27015", "dst_cidr": "203.0.113.10/32", "proto": "udp", "dport": 27015,
   "profile": "a2s"},
  {"id": "inhouse-30120", "dst_cidr": "203.0.114.10/32", "proto": "udp", "dport": 30120,
   "observe": true,
   "custom": {"min_len": 8, "max_len": 1400,
              "magic": [{"offset": 0, "hex": "deadbeef"}],
              "gate": "handshake", "opener_ids": [1, 2], "complete_ids": [2]}}
]
```

A filter only reaches nodes that carry the address it protects, and only
nodes that advertised a `zc` backend. `observe` records what a filter would
have done without acting on it, which is how a binding is rolled out.

A packet goes to the first filter bound to it, in policy order, so a policy is
refused when an earlier filter takes every packet a later one is bound to (a
whole prefix on every port ahead of one address on one port), or when an
earlier filter's HTTP rules cover every request a later one's would judge: put
the narrower one first. A `dst_cidr` outside every protected prefix is refused
too, since no node carries it. A node handed a program compiled before these
checks still loads it, and the filter that takes the packets judges them.

### Gates

Validating framing stops junk. It does not stop a flood of *well-formed*
packets from sources that never connected, so a profile can also gate on
the protocol's own handshake:

- **`raknet`** (Minecraft Bedrock and other RakNet engines). Offline messages
  carry a fixed 16-byte magic, and a source must complete the RakNet opening
  sequence before it may send connected datagrams. RakNet's connected framing
  is deliberately permissive — encapsulated payloads can be arbitrary bytes —
  so the gate, not the signature, is what protects an established port.
- **`a2s`** (the Valve query protocol). Every query is prefixed `0xFFFFFFFF`,
  and the protocol has a real challenge: the server answers with a four-byte
  number the client must repeat. The filter answers it and admits a source
  once it echoes back.

The cookie is a keyed hash of the source, the destination and a rotating
epoch, so no state is needed to mint one and a spoofed source cannot guess
it. The key is generated per policy and shipped to **every** node, because
under anycast a source's packets land on different scrubbers and a cookie
minted by one has to verify on another. The previous epoch is also accepted,
so a client answering a moment late is not refused.

A custom signature can gate on a handshake but cannot configure a challenge:
answering one means emitting protocol-correct bytes, and a wrong guess at
that framing breaks every client rather than failing closed. Challenge gates
come from built-in profiles only.

### HTTP on the server's own address (layer 7)

Plenty of game servers answer HTTP on the address players connect to, often on
the game's own port. FiveM, for one, serves its server info, player list and
resource downloads over TCP on its game port, along with any handler a script
registers under its resource's name. That is where application abuse lands: a
flood of well-formed requests for the player list, a bot hammering a script's
handler, a downloader pulling the same resource over and over. Every one of
those is valid HTTP, so no stage before this one can tell it from players.

A filter's `http` block holds that traffic to rules, and **the filter's own
binding decides what the rules look at**: TCP to the filter's `dst_cidr`, on
its `dport`, or on the block's own `ports` if it names some. A `profile` or
`custom` signature on the same filter keeps judging the game traffic beside it;
without one the filter carries HTTP rules alone.

```json
"games": [
  {"id": "fivem-30120", "dst_cidr": "203.0.113.20/32", "dport": 30120,
   "http": {
     "rate_per_source": 30,
     "paths": [
       {"path": "/players.json", "rate_per_source": 1, "rate_total": 400},
       {"path": "/info.json", "rate_per_source": 2},
       {"path": "/dynamic.json", "rate_per_source": 2},
       {"path": "/client", "methods": ["POST"], "user_agents": ["CitizenFX/"],
        "max_body_bytes": 8192, "rate_per_source": 5},
       {"prefix": "/files/", "methods": ["GET", "HEAD"], "rate_per_source": 50},
       {"prefix": "/myresource/", "methods": ["POST"], "rate_per_source": 2},
       {"prefix": "/myresource/admin/", "action": "drop"}
     ]}}
]
```

A request's path picks its rule: an exact `path` first, otherwise the longest
matching `prefix`. A rule either drops everything it covers or narrows what is
allowed there: `methods`, `user_agents` (prefixes a client's User-Agent must
start with, in any case), `max_body_bytes`, `rate_per_source` in requests a
second, and `rate_total`, a budget of requests a second from everyone together.
Whatever a rule leaves unset comes from the block, whose own defaults are GET,
HEAD and POST, any client, any body and no rate. `"default": "drop"`
turns the rules into an allow list, so a path no rule names is dropped; that
is what stops a flood aimed at handlers nobody thought to list.

- **Paths match the way a server might read them**: percent-decoded, with
  backslashes as slashes, runs of slashes and dot segments resolved, and
  without regard to case. `/files/../%70layers.JSON` is `/players.json` here,
  so spelling a path another way gets no request past its rule.
- **Rates are per source**, over the last second, for each rule and for the
  block as a whole. A verified source is held to them as well: trust skips a
  game's gate, not the HTTP rules.
- **A budget is for everyone together.** A flood spread across enough
  addresses keeps every one of them under `rate_per_source`, so `rate_total`
  counts every request that got past its own source's rates. Past it, a request
  from a source the fabric has not verified is dropped, and one from a source
  that cleared a gate, answered a challenge or had its return traffic confirmed
  in the last five minutes still gets through. Being turned away for what
  everyone else sent does not count against the source. See
  [Attacks that adapt](#attacks-that-adapt).
- **What no client sends is dropped**: a malformed request line, folded
  headers, Content-Length headers that disagree, or one beside
  Transfer-Encoding. So is cleartext HTTP/2, by preface or by upgrade, since
  its binary frames would carry requests no rule could read; a WebSocket
  upgrade passes.
- **A drop counts against the source** like any other the filter makes, a
  budget's and the request model's apart, so with `penalty_box` on, a source
  that keeps abusing an endpoint loses its game traffic for a while too. `observe` works here as
  everywhere: the rules record what they would have dropped and drop nothing.
- **What the rules allow, the request model then judges**, once one is
  published: a request it scores at its threshold drops the segment, with a
  reason such as `GET /players.json: scored 0.97 by the request model, which
  drops at 0.70`. It catches what no rule names, such as a client that sends
  none of a browser's headers, or asks for HTTP/1.0 with a fresh query string
  on every request. See [The classifiers](#the-classifiers).

The rules read requests packet by packet, without reassembling TCP streams. A
request is judged in the segment that carries its request line: at the start
of a segment, pipelined behind other requests in it, or after a line break in
a segment that continues a body. The rest of a request passes, and so does
TLS, which the filter cannot read; `scrubline_game_http_other_total` counts
those segments. A request line cut short in a short segment is dropped, since
a client writes a line whole and only someone hiding a path splits it. But a
client that controls its own segmentation can still split a request line where
the filter cannot see it whole, and a rule that needs a User-Agent needs it in
the segment that starts the request. For HTTPS, or for an attacker that crafts
its own segments, terminate the connections in a proxy instead.

`scrubline_game_http_requests_total{filter}`, `_dropped_total`,
`_rate_limited_total`, `_budget_dropped_total` and `_other_total` say what the
rules are doing.
`scrubline_game_http_windows` against `_max` shows the rate table; at the bound
a new source goes unlimited rather than another being forgotten. Judging a
request costs about half a microsecond on top of the rest of the pipeline.

### What it will not do

The filter never drops a packet it was given no payload for. A datapath that
is not supplying payloads would otherwise blackhole a customer silently;
instead it passes and `scrubline_game_uninspectable_total` climbs, which is
the signal that the filter is doing nothing. The control plane's own
`/v1/decide` sends no payload unless you put one in the flow record, so it
reports `uninspectable` rather than pretending to judge.

A bound filter costs roughly 380ns a packet on top of the rest of the
pipeline, with no allocations; a policy that binds none pays nothing, which
`make bench` guards with a case either way.

Per-filter counters —`scrubline_game_dropped_total{filter,profile}`,
`_challenged_total`, `_inspected_total` — say which binding is doing the work.
`scrubline_game_sessions` against `_max` shows the gate's source table; at the
bound it admits without tracking rather than evicting connected players.

## Datapath

Within a stage the first matching rule decides: `drop` and `permit` are both terminal, so a `permit` rule acts as an allow-list that exempts a source from the stages behind it. A TCAM entry carries no meter, so `rate_limit` is rejected on the `asic` stage.

The allow list holds wherever a source is judged, not only in the stages. When the first `asic` rule that drops or permits a flow, or failing one there the first `fpga` rule, is a `permit`, the flow passes the penalty box, lockdown and an idle on-demand tunnel's HTTP rules as well, and a verified source's permit ends evaluation as anyone's does. A permit written for a source already in the box takes effect on its next packet.

Each TCAM key names the table it belongs in: `v4` or `v6` by the addresses the rule matches, or `any` for a rule matching no address, which a switch installs in both. A rule whose source and destination are different families would match nothing and is refused, as is one whose `dst_cidr` is outside every protected prefix.

Rules are ordered by `priority` on every stage, not just the ASIC, and the ordering is stable, so rules sharing a priority keep policy order and compile identically on every node. A node is only given entries for the backends it advertised at registration.

Payload inspection belongs to the ZC stage alone; see
[Game filtering](#game-filtering). `count` is observe-only and never drops: it records the match and leaves the verdict to a later rule. Only two stage/action pairs consume `pps` — an `fpga` `rate_limit` meter, and the `zc` behavioral cap on `rate_limit` or `inspect`. A policy carrying `pps` anywhere else is rejected rather than accepted and ignored.

1. ASIC / TCAM ACL. Longest-prefix and port ACLs. Terminal drops never leave the chip.
2. FPGA. Line-rate meters and flag matches for what the TCAM did not already drop.
3. PF_RING ZC. Zero-copy userspace inspect for residual traffic. No XDP redirect, no eBPF drop path. The game filters and their HTTP rules run here, and the classifiers trained from the control API have the last word (see [The classifiers](#the-classifiers)).

Hardware programming is represented as compiled programs the node agent pulls. A node without a switch ASIC, FPGA, or PF_RING license still enforces the same decision order in the software pipeline so the control plane can be tested. On an appliance, the agent writes the TCAM key, FPGA table, and `zc:<node>` cluster from that program.

The fabric recompiles all the time, so a reload keeps what each source has spent: of an FPGA meter, of a ZC behavioral cap and of lockdown's trickle, for every rule the new program keeps. A recompile hands nobody a fresh allowance, and a game filter's sessions and an HTTP rule's rate windows carry over the same way.

### The classifiers

Two logistic models are trained from one labelled set and published together:

- **The flow model** judges what every packet carries: its rate, protocol,
  ports and TCP flags.
- **The request model** judges the HTTP requests a game filter's [layer-7
  rules](#http-on-the-servers-own-address-layer-7) allow: the method and
  version, how long and deep the path and query are, how many headers there
  are and which of a browser's usual ones it sends (User-Agent, Accept,
  Accept-Language, Accept-Encoding, Cookie, Referer), the body it declares,
  how far into a pipelined segment it sits, and the rate it arrives at.

A sample whose payload is an HTTP request trains the request model, and every
other sample trains the flow model. What makes an HTTP sample an attack may be
in the request, where the flow model cannot see it, so it is kept out of the
flow model's fit. The request model is published once the set holds clean and
attack requests both.

**By default they judge everything the rest of the datapath lets through:**

- a flow that a zc `inspect` or `rate_limit` rule sends the flow model;
- a flow that a game filter passes, and one that no rule decides, before it is
  let through;
- every request that a filter's HTTP rules allow, where a request scored at the
  threshold drops the segment carrying it.

A `permit` rule on the asic or fpga stage ends evaluation before either has a
say. One on the zc stage comes after the game filters, so it spares a flow the
flow model but not the HTTP rules or the request model. A verified source skips
the flow model; the request model judges verified sources too, as the HTTP
rules do. A drop by either is no strike against the source: a score proves
nothing, and the penalty box would turn one wrong score into every packet from
that source dropped for up to an hour. Scoring costs about 40 ns a flow and
60 ns a request.

The policy says where they run and whether they drop:

```json
"ml": {"scope": "all", "mode": "observe"}
```

`"scope": "inspect"` keeps the flow model to what zc `inspect` and
`rate_limit` rules send it, with the request model off, which is how the
classifier worked before it judged the rest. `"mode": "observe"` scores
everything and drops nothing: a decision reads `PF_RING ZC ml score 0.93,
observed only`, and `scrubline_ml_observed_total` and
`scrubline_ml_http_observed_total` count what would have been dropped. That is
how a model is tried before it is trusted. A filter's own `observe` does the
same for the request model on that filter's traffic.

**A model being probed tightens for that target.** Traffic changed until a model
lets it through stops changing at the first variant that passes, so it scores
just under the threshold. For each protected prefix the node keeps ten seconds
of what both models scored there. When 20 or more of those flows landed within
0.1 under the threshold, and they are a quarter or more of all of them, both
models drop 0.1 lower for that prefix, and 0.2 lower if it happens again; each
step lapses five minutes after the probing that set it was last seen. A
decision reads `PF_RING ZC ml score 0.47, over the 0.40 this target is held to
while it is being probed`, and other prefixes keep the published thresholds.
Each model goes no further under its threshold than its `max_cut`: as far as
training showed it can go and still drop no more clean traffic than its limit,
and no known-good sample. A model published before that was measured has a
`max_cut` of 0 and never tightens. `"probing": "ignore"` keeps the thresholds
where they are.

Train with labelled samples, then nodes pull both models on their next poll.
An HTTP sample is a TCP flow whose `payload` is the request, base64-encoded as
any payload is; [`configs/ml.samples.json`](configs/ml.samples.json) has both
kinds. One sample in five is held out of each fit, an HTTP sample with all the
requests in it, and the reported `accuracy`, `precision`, and `recall` are
measured on that holdout. Watch precision: a false positive here is dropped
customer traffic. Sets below ten samples are too small to split and report
training metrics with `validation: 0`. `DELETE /v1/ml/model` retires both
models; agents clear their copy on the next poll, which is the only way to pull
a bad model without restarting the fleet.

**A model that would drop clean traffic is not published.** Each model reports
its `false_positive_rate`, the share of the clean samples it was measured on
that it drops. Training refuses one over 1%, or one that drops any sample marked
`"known_good": true`. Mark a false positive you have seen that way, or traffic
the models must never touch. The answer is `422`, with the model that would
have been published, and the one already published stays. Set
`"max_false_positive_rate"` in the training request for another limit, or
`"force": true` to publish it all the same, in which case it is never tightened
past what the limit allows.

`scrubline_ml_scored_total`, `_drops_total`, `_passes_total` and
`_observed_total` count the flow model's verdicts on each node, and
`scrubline_ml_http_scored_total`, `_http_drops_total` and
`_http_observed_total` the request model's. `scrubline_ml_near_misses_total`
and `_tightened_total` count the probing, and
`scrubline_prefix_ml_threshold_cut{prefix}` says how far under its thresholds a
prefix is held. `scrubline_ml_model_ready` and
`scrubline_ml_http_model_ready` say which a node has installed. The control
plane reports each published model's holdout metrics as
`scrubline_control_ml_*` and `scrubline_control_ml_http_*`, its
`_false_positive_rate` and `_max_cut` among them.

## Attacks that adapt

An attack run by software, AI-driven or otherwise, does not have to repeat what
failed. It can watch what gets through and change: learn the thresholds and
holds it has to beat, tune its traffic until a classifier lets it pass, and
spread a flood over so many addresses that each one stays under its rate.
Every fixed setting is something it can learn, so three defences make learning
them pay less.

**Coming back costs more every time.** An on-demand tunnel's mitigation lasts
five minutes after its traffic was last at a threshold. An attacker that has
measured that can start each wave just as the last mitigation ends, and have
the start of every wave let through. So a mitigation that starts within an hour
of the last one ending counts as that attack's next wave, and holds twice as
long as the last one did: five minutes, then ten, twenty, forty, and an hour
from then on. After an hour without one, the next is a first wave again. See
[On-demand mitigation](#on-demand-mitigation).

**Probing a classifier tightens it.** Traffic tuned against a model stops
changing at the first variant that gets through, so it scores just under the
threshold, where ordinary traffic has no reason to gather. When that is where
much of a customer's traffic lands, both models drop lower for that customer's
prefix, a step at a time, until the probing stops, and each only as far as its
training showed it can without dropping clean traffic. See
[The classifiers](#the-classifiers).

**A flood spread thin runs into a budget for everyone.** A botnet with enough
addresses keeps each one under `rate_per_source`, and a client written to look
like a browser sends every header a browser would, so neither the rate nor the
request model tells it from players. `rate_total` caps what a path, or a whole
filter, takes from all sources together. Past it, only sources the fabric has
verified get through: ones that cleared a game's gate, answered a challenge or
had their return traffic confirmed in the last five minutes. A botnet's fresh
addresses have done none of that, and every one of them would have to. See
[HTTP on the server's own address](#http-on-the-servers-own-address-layer-7).

None of this catches traffic that cannot be told from your players, arriving at
the rate your players do. Past the budget that is load, and what the budget
decides is who is served first.

`scrubline_tunnel_mitigation_wave{tunnel}`, `scrubline_ml_tightened_total`,
`scrubline_prefix_ml_threshold_cut{prefix}` and
`scrubline_game_http_budget_dropped_total{filter}` show each defence at work.

## Crafted packets

Some attacks need no volume. One packet built wrong can crash the stack that
receives it, and a trickle of them can wedge one, so no rate, threshold or
classifier would ever notice them. Every node holds each packet to the rules
its own headers state, before anything else judges it, and drops what no
legitimate stack sends. None of the checks needs tuning: what they catch is
never real traffic.

A datapath that hands the node whole packets puts each one in a flow record as
`packet`, base64, from its IP header on. The node reads the addresses,
protocol, ports, flags and payload from the headers, which take the place of
the record's own fields, so the rules and filters judge what the packet says
about itself:

```json
{"packet": "RQAAKBI0QABABiqQwAACAcsAcQqcQAG7AAAAAQAAAABQAv//AAAAAA==", "pps": 1}
```

A record without one is held to what its fields can show: where it comes from,
whether that is where it goes, its TCP flags, and the size of its payload.

### What the checks catch

They fall into three classes. **Stack** packets are built to crash or wedge the
stack that receives them, **protocol** packets break the rules of the protocol
they claim to be, and **buffer** packets are sized to overrun a buffer or a
reassembly table.

| Class | Check | Drops | Known as |
| --- | --- | --- | --- |
| stack | `land` | a source that is also the destination | LAND |
| stack | `tcp_flags` | SYN with FIN or RST, FIN with RST, none of SYN, ACK, FIN, RST, PSH and URG, and anything but a SYN or a bare RST without ACK | SYN-FIN, NULL, FIN and Christmas tree scans |
| stack | `martian_source` | a source no packet from the internet can have: 0.0.0.0/8, loopback, link-local, multicast, 240.0.0.0/4 and broadcast, and IPv6's unspecified, loopback, link-local, multicast and IPv4-mapped | spoofed impossible sources |
| stack | `source_route` | IPv4 loose and strict source routes, IPv6 type 0 routing headers | source-routed spoofing, RH0 (RFC 5095) |
| stack | `low_mss` | a SYN offering an MSS of 500 bytes or less | SACK Panic (CVE-2019-11477) |
| stack | `fragment_overlap` | a fragment over bytes another of its datagram already carried, or past where the last one ended it, and a TCP fragment 8 bytes in | Teardrop, Bonk, Nestea, RFC 1858 |
| protocol | `ip_header` | a version other than 4 or 6, a header under 20 bytes, a total length under the header's, the reserved flag bit, a bad checksum | |
| protocol | `ip_options` | an IPv4 option that claims under 2 bytes or runs past the header | |
| protocol | `extension_headers` | hop-by-hop anywhere but first, two fragment headers, more than eight extension headers | header chains built to hide the transport header |
| protocol | `tcp_header` | a data offset under 20 bytes, an option that runs past the header, an MSS, window scale, SACK or timestamp option of the wrong length | |
| protocol | `udp_header` | a UDP length under 8 bytes, or short of the datagram it heads | data hidden from whatever reads the length |
| protocol | `icmp` | ICMP shorter than its header, and messages that never leave their own link: redirects, router and neighbour discovery, multicast listener messages, and deprecated types | Bad Neighbor (CVE-2020-16898) |
| protocol | `port_zero` | TCP or UDP from or to port 0 | |
| protocol | `fragment` | a fragment before the last whose size is not a multiple of 8 | |
| buffer | `length` | a length that claims more than arrived (the IP total or payload length, a header, the UDP length), or bytes past it beyond a link's padding | buffer over-reads |
| buffer | `oversize` | a fragment reaching past the 65,535 bytes an IP datagram holds, and a record's payload larger than any packet | Ping of Death, Jolt2 |
| buffer | `tiny_fragment` | a fragment before the last under 256 bytes, a first fragment too short for its transport header, an IPv6 first fragment without its whole header chain | FragmentSmack (CVE-2018-5391), tiny fragments (RFC 1858, RFC 7112) |

The HTTP rules hold requests to what servers hold them to. A request line or
header line over 8 KiB, or more than 100 header lines, is dropped: nginx and
Apache refuse those by default, so no request a server would accept is lost,
and the overlong lines buffer overflows are built from never reach one. The
game profiles bound each datagram's size the same way.

### Where they sit

**First, for everyone.** The checks run before the penalty box, lockdown and
the stages. An operator's permit and a verified source both vouch for an
address, and a crafted packet forges its address as easily as the rest of
itself, so neither exempts one.

**On an idle on-demand tunnel too.** A tunnel watched until it is attacked
lets traffic under its thresholds through unfiltered, and a crafted packet
never reaches a threshold. The checks drop it anyway, and the tunnel's meter
still counts it, so an attack that mixes crafted packets with a flood starts
mitigation on its whole volume.

**Nobody is boxed for one.** A crafted packet's source address is as likely to
be the forgery as anything else in it, so its drop is not a strike. The packet
is dropped every time regardless.

A packet too broken to say where it is going belongs to no customer, and is
dropped rather than passed as someone else's.

### Fragments

Telling one datagram's fragments from another's takes memory, so the node
keeps the fragments of up to 4,096 datagrams, by source, destination,
protocol and identification, for the 30 seconds a host holds them for
reassembly. When the table is full the oldest datagram is forgotten, so a
flood of fragments costs the node only its oldest entries, and a pair of
overlapping fragments sent together is still caught. The same fragment twice
is a network duplicating a packet, and passes.

A fragment after the first carries no transport header, so it has no ports and
no flags. The checks still hold it to the rules fragments keep, and rules on
addresses and protocol still apply to it, but rules on ports and the game
filters cannot see it.

### Flags compare as sets

`tcp_flags` in a rule, and `flags` in a record, name flags separated by `,`,
`|` or `+`. They compare as sets: the four that say what a segment is (SYN,
ACK, FIN and RST) must be exactly the rule's, and any other flag the rule
names must be set. A SYN meter therefore meters a SYN with ECN or PSH set too,
and never a SYN-ACK, so setting a spare bit slips past no rule. The flow
model's SYN feature reads flags the same way. A value the vocabulary does not
name compares as text, as it always did.

### Rolling them out

```json
"crafted": {"mode": "observe"}
```

`observe` counts what the checks would drop and drops nothing, and `off` does
not look. `enforce` is the default.

Each drop says why: the decision carries the check as `check`, and its reason
names the class and the rule broken, for example `crafted packet (stack): SYN
and FIN set together, which no stack sends`. The node counts every check in
`scrubline_crafted_dropped_total{check,class}`, and each customer's attack
shows the class that stopped part of it, `crafted-stack` say, beside the rules
and filters.

A packet that trips a bug in the node costs that request its answer. The node
carries on with the state the request left, rather than taking its players'
sessions and its sources' reputation down with it.

### What they will not do

They do not verify TCP and UDP checksums: a stack discards a segment whose
checksum is wrong, so it can do no harm there. They do not reassemble
datagrams or track TCP connections; out-of-order floods built to make a host
do that work are volumetric, and the rest of the pipeline meets them. And they
need the whole packet: a datapath that captures only the start of each one
would have every long packet read as one that lies about its length.

Checking a flow record costs about 25 ns, and reading and checking a whole
packet about 400 ns more, most of it filling the record from the headers;
`make bench` measures both.

## Reflection attacks

A reflection attack has servers on the internet do the attacking. The attacker
sends them small requests with the protected address forged as the source,
and they send their answers there, many times larger. The answers come from
real servers at real addresses, so no rule on sources stops them. What gives
them away is that nobody at the protected address asked.

### CLDAP

Connectionless LDAP (CLDAP) runs on UDP port 389, and domain controllers
expose it to the internet by the tens of thousands. A rootDSE query of about
50 bytes gets an answer of several kilobytes back. An answer that size arrives
in fragments, and only the first fragment carries the port.

Every node drops CLDAP answers at its protected addresses:

- **The answer:** UDP from port 389 that opens the way an LDAP answer to a
  search does. That means a BER `SEQUENCE`, a message ID, then a search entry,
  reference or done. A packet from port 389 that opens any other way is not
  CLDAP, and passes. A player whose NAT happens to map them to port 389 is
  sending the game's own packets. A flow record without its payload is judged
  by its port alone.
- **The rest of it:** a source caught reflecting is remembered for 30
  seconds after its last answer, as long as a host holds fragments for
  reassembly. Its later fragments, which carry no port, are dropped with it.
  The node remembers up to 65,536 such sources. When the table is full of
  sources still reflecting, a new one is counted in
  `scrubline_reflection_sources_untracked_total` and not remembered.

Two things let an answer through:

- **The server asked for it.** If the protected server sent an address a CLDAP
  query, an LDAP search to its port 389, in the last 30 seconds, an answer
  from that address answers it. A Windows server finding its domain
  controller gets its answer. Nothing else the server sends counts. An
  attacker can forge a game query from a reflector's address, and the server
  would answer it. This is known only where the server's own traffic passes
  the node. Behind direct server return, the node sees no queries, so every
  answer is dropped unless a permit covers its source.
- **An operator's permit** on the `asic` or `fpga` stage that covers the
  source, such as your own directory server's address.

A player's trust and the penalty box speak for neither: a reflector is no
player. Nor is a reflector boxed for it. It is somebody's server, put to work
by the attacker. Like the rest of mitigation, the guard holds off on an idle
on-demand tunnel, whose meter counts the answers until they start mitigation.

```json
"reflection": {"cldap": "observe"}
```

`enforce` is the default, `observe` counts what would be dropped and drops
nothing, and `off` does not look. A drop carries `"reflection": "cldap"` and a
reason that says which part of an answer it was. The node counts them in
`scrubline_reflection_dropped_total{vector}` and
`scrubline_reflection_fragments_dropped_total{vector}`, and the answers let
through because the server asked in `scrubline_reflection_asked_total`. A
customer's attack shows the vector as `reflection-cldap`, beside the rules and
filters that stopped the rest of it.

## GRE and ACK floods

IoT botnets such as Mirai flood with more than UDP. Two of their attacks get
past filters that judge TCP and UDP by their ports: GRE floods and ACK floods.
Every node runs a guard for each, after the reflection guard and before the
penalty box, trust and lockdown.

### GRE and other protocols

A game server receives TCP, UDP and ICMP. Mirai's GRE floods wrap junk in GRE,
protocol 47, so that a filter on ports never sees it. Every node drops GRE
sent to a protected address, and every other IP protocol but TCP, UDP and
ICMP, at the `asic` stage. A drop carries `"guard": "protocol"`.

A customer who does receive another protocol, such as a VPN server, gets it in
one of two ways. The policy can let a protocol in for every protected
address, by name (`gre`, `esp`, `ah`, `sctp`, `ipip`, `ipv6`) or number:

```json
"protocols": {"allow": ["esp", "ah"]}
```

Or a permit rule can let it in for one address. Rules take those names as
`proto`, with no ports:

```json
{"id": "vpn-gre", "stage": "asic", "action": "permit",
 "match": {"proto": "gre", "dst_cidr": "203.0.113.50/32"}}
```

### ACK floods

Every segment of a TCP connection but the opening SYN comes from an address
the server has sent TCP to. The server's SYN-ACK starts each connection it
accepts, and it acknowledges what it is sent. An ACK flood is TCP for
connections that do not exist: ACKs, and RSTs, FINs and SYN-ACKs, from sources
the server never spoke to. The node knows whom the server sends TCP to from
the server's own traffic, the same way
[return-traffic confirmation](#return-traffic-confirmation) does. So it drops
TCP from a source the server has not sent TCP to in the last two minutes, at
the `zc` stage. A drop carries `"guard": "ack_flood"`.

It does so only while all three of these hold:

- **The node sees the server's own traffic**, as it does when replies come
  back up the tunnel. Behind direct server return it does not, and the guard
  does nothing.
- **It has seen that traffic for two minutes**, with no gap of over 30
  seconds. That is as long as the table keeps a connection that has gone
  quiet, so the node knows every connection that was open when it started
  watching. A node that has just started drops nobody's connection.
- **The prefix is flooded:** it is taking more than 5,000 packets a second of
  such TCP, or was within the last minute. Below that, a stray segment passes.

The node keeps up to 65,536 addresses the server sends to. When that table
is full, a connection opened since may have gone unrecorded, so the guard
stands down rather than drop it.

`"ack_flood": {"engage_pps": 20000}` sets the threshold. An operator's permit
vouches for what it covers. A player's trust does not, because trust says an
address once proved itself, not that it has a connection.

The guard stops what Mirai's `ack` attack sends. It does not stop Mirai's
`stomp` attack, which opens real connections from the bots' own addresses and
floods those. Rate limits, behavioural caps and the penalty box are what meet
that.

### Rolling them out

Both guards take a `mode`: `enforce`, the default, `observe`, which counts
what would be dropped and drops nothing, or `off`:

```json
"protocols": {"mode": "observe"}, "ack_flood": {"mode": "observe"}
```

The node counts their drops in `scrubline_protocol_dropped_total{protocol}`
and `scrubline_ack_flood_dropped_total`.
`scrubline_ack_flood_engaged_prefixes` and
`scrubline_prefix_ack_flood_engaged{prefix}` show where the ACK flood guard is
engaged, and each guard has a mode gauge. A customer's attack shows
`protocol-gre` or `ack-flood` beside the rules and filters that stopped the
rest of it.

## Keeping false positives down

A false positive is a customer's own traffic dropped, which can hurt them as
much as the attack would have. So every judgement that can be wrong is held
back from doing more harm than it must:

- **A model that would drop clean traffic is not published.** Training refuses
  a model that drops more than 1% of the clean samples it is measured on, or
  any sample marked `"known_good": true`, and the published one stays. See
  [The classifiers](#the-classifiers).
- **The classifiers tighten only as far as training showed is safe.** A target
  being probed holds each model at most its `max_cut` under its threshold: as
  far as it stays within that 1% and clear of every known-good sample.
- **A score never puts a source in the penalty box.** Only what a rule, a gate
  or a source's own rate proved does, so a model's mistake costs the flow it
  scored and not everything the source sends. A budget for everyone does not
  box anyone either.
- **The box releases real clients.** A trusted source cannot be boxed, and a
  boxed one the origin keeps answering is released at once. An operator can
  release any other. See [Clearing a false positive](#clearing-a-false-positive).
- **New judgements can be watched before they act.** `"mode": "observe"` for
  the classifiers, and `observe` on a game filter, count what they would drop
  and drop nothing.
- **Nothing is dropped for want of a look.** A game filter given no payload
  passes the packet and counts it as uninspectable.
- **Your own traffic can be taken out of the question.** A `permit` rule on the
  asic stage takes a source past every stage behind it, and past the penalty
  box, lockdown and an idle on-demand tunnel's HTTP rules too.
- **The crafted-packet checks judge only what no stack sends.** None of them
  needs a threshold, and `"crafted": {"mode": "observe"}` counts what they would
  drop first. See [Crafted packets](#crafted-packets).

When one gets through anyway, mark it `known_good` among the samples and
retrain: no model that would drop it again can be published.

## Run

On servers, [`scripts/install.sh`](docs/install.md) installs the control
plane, or a scrubbing node with the provisioner that applies its tunnels, as
systemd services:

```sh
sudo scripts/install.sh api                       # the control plane
sudo scripts/install.sh node --api https://10.0.0.5:8080 --ca ca.pem \
    --enroll-token <token> --name lhr-1 --region lhr   # each scrubbing node
```

To try it on one machine instead:

```sh
export SCRUBLINE_API_TOKEN=dev-scrubline-token
export SCRUBLINE_ENROLL_TOKEN=dev-scrubline-enroll
cargo test --locked --all-targets
cargo run --release --bin scrub-api -- -addr 127.0.0.1:8080 -state scrubline-state.json
```

In other shells (see [Credentials](#credentials); the agent never holds the
operator token):

```sh
export SCRUBLINE_ENROLL_TOKEN=dev-scrubline-enroll
export SCRUBLINE_NODE_API_TOKEN=dev-scrubline-node
cargo run --release --bin scrub-node -- -name scrub-a -region iad -capacity 100 -listen 127.0.0.1:9091
cargo run --release --bin scrub-node -- -name scrub-b -region fra -capacity 80 -listen 127.0.0.1:9092
cargo run --release --bin scrub-node -- -name scrub-c -region sin -capacity 40 -listen 127.0.0.1:9093
sh scripts/demo.sh
cargo run --release --bin scrubctl -- fabric
```

### Every feature on one node

[`configs/policy.everything.json`](configs/policy.everything.json) turns on
everything a policy can at once: TCAM, FPGA and ZC rules with a permit for
monitoring, RakNet, A2S and custom game filters, HTTP rules with budgets, IPv4
and IPv6 prefixes with communities, three tunnels (one on-demand, one IPv6
whose replies leave by the customer's own transit), a customer BGP session,
the penalty box, return-traffic confirmation with lockdown, and both
classifiers enforcing and tightening under probing.
[`tests/node.rs`](tests/node.rs) deploys it to one node through the API and
checks that the features decide together, report together, render together
and survive a policy change; the real binaries do the same, through the API
restarting from its state:

```sh
cargo build --release --bins
PATHFINDER_BIN_DIR=target/release python3 scripts/everything-e2e.py
```

### A demo fabric in containers

```sh
make up
```

That brings up a control plane, three scrubbers in three regions, a seeded
policy protecting two customers, and a generator driving traffic through the
datapath — then prints both customers' credentials. `make creds` reprints
them, `make logs` follows everything, `make down` stops it.

The generator matters more than it sounds. Without traffic the whole stack
reports zeros, which is indistinguishable from a stack that is broken, so
trying the analytics API against an idle fabric teaches nothing. It posts flow
records to each agent's `/decide`, which runs them through the real pipeline:
steady legitimate traffic, a flood every few minutes, and a burst train whose
average stays under every watermark on purpose.

```sh
curl -H "Authorization: Bearer $NORTHWIND" localhost:8080/v1/analytics/overview | jq
curl -i -H "Authorization: Bearer $NORTHWIND" localhost:8080/v1/nodes   # 403
```

The control API is published on 8080 and the three node dataplanes on 9091,
9092 and 9093, all bound to loopback:

```sh
curl -H "Authorization: Bearer $SCRUBLINE_NODE_API_TOKEN" \
  -d '{"dst_ip":"203.0.113.10","proto":"tcp","dport":443,"pps":10}' \
  http://127.0.0.1:9091/decide
```

The compose file passes `-insecure`, because the compose network is not
loopback and these containers carry no certificates. That is for the demo; a
deployment mounts a certificate and drops the flag. Which is why the published
ports bind to loopback and not `0.0.0.0` — putting this on a routable address
puts credentials on the wire in the clear.
**[`deploy/README.md`](deploy/README.md)** covers reaching it on a real URL
without doing that.

## Sizing for a 16 GB server

Every server Scrubline runs on needs 16 GB of memory: the control plane's,
each scrubbing node's, or one running both. Everything either keeps has a
ceiling, and at the most it is built to hold both fit with room to spare.
[`tests/memory.rs`](tests/memory.rs) builds each part at those bounds and
holds it to its share, and [`tests/load.rs`](tests/load.rs) runs the largest
fabric against one control plane; CI runs both on every change
(`cargo test --release --test memory --test load -- --nocapture` prints how
they went).

What it is built to hold:

- a fabric of **128 nodes**;
- **32 policies**, each of up to **1024 protected prefixes, 1024 rules, 1024
  tunnels, 256 game filters and 256 BGP sessions**;
- **4096 tenants** with 16384 prefixes between them;
- a training set of **200000 samples** with 64 MiB of payloads and packets.

A write past one is refused with what it hit (`413`, or `400` for a policy).
A node that is gone for good gives its place back with `DELETE /v1/nodes/{id}`,
and an old policy with `DELETE /v1/policies/{id}`.

At those bounds, as the allocator counts it:

| Part | Holds at the most | Of which |
| --- | --- | --- |
| Node agent | 276 MiB | every table full (65536 sources each in the rate, reputation, return-traffic, reflection, game session and HTTP tables): 79 MiB; request bodies 64 MiB; 1024 connections at an allowance of 128 KiB each, 128 MiB |
| Control plane, 128 nodes | 3.0 GiB | programs and the plan 205 MiB, node and tunnel reports 64 MiB, a day of analytics 922 MiB, policies, training set and tenants 140 MiB; writing the state out 332 MiB; metrics scrapes, four at a time, 26 MiB; the largest answer still being sent, the whole fabric, 109 MiB; request bodies 256 MiB; 8192 connections at 128 KiB each, 1 GiB |

Each part grows with what the policy holds multiplied by the nodes: every node
is compiled the whole policy and reports counters for every prefix, rule,
tunnel and filter in it, and the control plane keeps both for each of them.

### Talking to the control plane

The limits are set by time as much as by memory: every node heartbeats every
couple of seconds, and the control plane takes each one under the lock that
also guards its recompiles. So it does as little as it can there:

- A heartbeat's body is read before the lock is taken, once its credential
  checks out, and analytics reads the counters as they arrive rather than
  through a copy several times their size.
- Whether anything a recompile depends on has changed is told from a digest of
  each node's tunnel reports, not from every report written out again.
- A recompile that takes long is paced: changes arriving within a few of its
  own lengths of the last are folded into the next, so a fabric checking in at
  once after a restart costs a few recompiles, not one for each node.
- Programs are shared with the requests that answer with them, and written out
  after the lock is let go; so are the reads that carry the whole state,
  fabric, training set or every policy, and every metrics scrape.

[`tests/load.rs`](tests/load.rs) holds it to that at the bounds: 128 agents
heartbeating every two seconds with everything they can report, every tunnel's
state among it, each holding a request open for its program, an operator
deploying a new version of the policy every ten seconds, and a scraper. No
heartbeat fails and no node goes stale; half are answered within about 10 ms
and the slowest, waiting on a recompile, in about a second, well within the
five seconds an agent waits; every node has each new program within a second;
a scrape takes about 30 ms.

[`scripts/install.sh`](docs/install.md) gives each service a share to match:
the control plane is reclaimed from past 8G and restarted at 10G, the agent
past 1536M and at 2G, and the kernel kills the agent last when the server runs
out, since the scrubbing goes with it. The installer warns on a server with
less than 16 GB. Both report what they hold: `scrubline_resident_bytes{node}`
for each node and `scrubline_control_resident_bytes` for the control plane.

## Observability

Both binaries expose Prometheus metrics at `/metrics`. The exposition carries
rule IDs and traffic volumes, so the control plane's takes the operator
credential and each agent's takes that agent's local one. `/health` stays open for
liveness probes.

A node counts what its datapath did and attaches those counters to the
heartbeat it already sends every couple of seconds, so the control plane has a
fleet view without a second round trip. Both ends render the same metric names.
The control plane's `/metrics` carries each node as a whole: its totals, stages,
crafted-packet checks, reputation and return-traffic tables, and how many of its
tunnels are up. A node's series for each prefix, rule, filter and tunnel are on
that node's own view, `/metrics?node=<id>` on the control plane or the agent's
`/metrics`: a large fabric has millions of them, more than one scrape can carry.
A scraper that cannot reach the agents, which listen on loopback once installed,
takes one target for each node from the control plane.

The counters that answer "is mitigation working, and which rule is doing the
work":

- `scrubline_prefix_announcers{prefix}` — on the control plane, how many nodes announce each protected prefix. Zero means nothing is drawing that customer's traffic to the fabric.
- `scrubline_node_tunnels{node,state}` — on the control plane, how many of a node's tunnels its provisioner last reported up, down or unknown. Each tunnel's own series are on the node's view.
- `scrubline_rule_matches_total{node,stage,rule}` and `scrubline_rule_drops_total{...}` — per rule. A rule with matches and no drops is seeing traffic it is not acting on; a rule with neither is dead weight in the policy.
- `scrubline_stage_dropped_total{node,stage}` and `scrubline_stage_permitted_total{...}` — where in the pipeline traffic is being decided. Work moving from `asic` toward `zc` means the cheap stages are missing it.
- `scrubline_*_pps_total` — the same counts weighted by the per-flow rate reported on each decision. A volume indicator, not a packet counter.
- `scrubline_unowned_flows_total{node}` — flows for a prefix the node does not carry. A rising value means the steering layer and the fabric disagree about who scrubs what.
- `scrubline_bgp_announced{node,prefix}` and `scrubline_bgp_prepends{node,prefix}` — the steering posture. A prefix with no node at 1 is attracting no traffic to the fabric at all.
- `scrubline_offered_pps{node}` and `scrubline_dropped_pps{node}` — current packet rates, averaged over the node's load window. These are rates, not totals.
- `scrubline_surge_pps{node}` — the offered rate over the last second. Load-driven shedding reacts to it or to `scrubline_offered_pps`, whichever is higher, so it moves within a second of a flood arriving.
- `scrubline_steering_escalation{node}`, `scrubline_steering_load_ratio{node}` and `scrubline_node_capacity_pps{node}` — the shedding loop. A node at a non-zero escalation is deliberately leaning away from traffic.
- `scrubline_rate_buckets{node}` against `scrubline_rate_buckets_max{node}` — at the bound, the ZC behavioral cap has stopped tracking every source.
- `scrubline_resident_bytes{node}` — what the agent's process holds in memory. Its tables are bounded, so it levels off under load; one that keeps climbing is a fault. The control plane reports its own as `scrubline_control_resident_bytes`.
- `scrubline_prefix_offered_pps{node,prefix}` and `scrubline_prefix_dropped_pps{node,prefix}` — the same rates broken down by the protected prefix the traffic was aimed at. The node-wide pair cannot answer "which customer is being attacked": a scrubber carries many prefixes at once.
- `scrubline_prefix_flows_total{node,prefix}`, `scrubline_prefix_flows_dropped_total{...}`, `scrubline_prefix_offered_total{...}` and `scrubline_prefix_dropped_total{...}` — the cumulative per-prefix counters the customer-facing analytics are deltaed from.
- `scrubline_egress_visibility{node,prefix,state}` — whether this node sees a prefix's return path. `asymmetric` means the return-traffic layer is standing down for it.
- `scrubline_egress_confirmed{node}` and `scrubline_egress_locked_down_total{node}` — clients the origin has vouched for, and ingress held back for want of one.
- `scrubline_reputation_trusted{node}` and `scrubline_reputation_penalised{node}` — how many sources are on the short path and how many are in the box.
- `scrubline_reputation_boxed_total{node}` — packets dropped at the top of the pipeline, which is the load the rest of the stages did not have to carry.
- `scrubline_reputation_shielded_total{node}` — strikes that landed on an already-verified source and were not acted on. Alert on this: it is a spoofing attempt against a real player, or a verified client misbehaving.
- `scrubline_reputation_freed_total{node}` — boxed sources released because the origin kept answering them. Every one is a false positive the box made and undid; a steady rate means something is boxing real clients.
- `scrubline_crafted_dropped_total{node,check,class}` — packets built to harm the stack that receives them, by the rule each broke. Any of them rising is an attack no rate would show. `scrubline_crafted_mode{node,mode}` at `off` means nothing is stopping them; alert on it.
- `scrubline_crafted_fragments{node}` against `scrubline_crafted_fragments_max{node}`, and `scrubline_crafted_fragments_untracked_total{node}` — the table of fragments in reassembly. A steadily rising untracked count is a flood of fragments cycling it.
- `scrubline_prefix_ml_threshold_cut{node,prefix}` and `scrubline_ml_tightened_total{node}` — a customer whose traffic is gathering just under the classifiers' thresholds, which is what tuning an attack against them looks like. A cut that never lapses on ordinary traffic means the model scores that traffic too close to its threshold.
- `scrubline_tunnel_up{node,tunnel,remote}` — 1 when a return path is reported carrying traffic, 0 when reported down. A never-reported tunnel is **absent**, not zero: `scrubline_tunnel_reported` is how you tell "nothing is reporting" from "it is broken".
- `scrubline_tunnel_mtu_bytes{node,tunnel}` and `scrubline_tunnel_mss_clamp_bytes{...}` — the derived encapsulation numbers, so a hung-TCP complaint can be checked against them rather than guessed at.
- `scrubline_tunnel_rate_limit_bits_per_second{node,tunnel}` — the share of the tunnel's clean-traffic allowance this node shapes to.
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
curl -H "Authorization: Bearer $SCRUBLINE_API_TOKEN"      "http://127.0.0.1:8080/metrics?node=$NODE_ID"
curl -H "Authorization: Bearer $SCRUBLINE_NODE_API_TOKEN" http://127.0.0.1:9091/metrics
```

## Source reputation

Two tiers, pulling in opposite directions, both keyed on what a source has
already proved.

**A verified client takes a shorter path.** Once a source has cleared a
protocol gate, re-challenging it and re-scoring it per packet tells you what
the gate already established, so it skips both. Measured on an admitted A2S
client: **980 → 695 ns per packet**.

It does **not** skip two things:

- **The behavioural cap.** It is the only thing bounding what a verified
  source can send. Without it, clearing one challenge would be the whole
  attack — and the cap costs about four nanoseconds, so there was never
  anything to save.
- **The signature check.** The source address on a packet is written by
  whoever sent it, so skipping this would make spoofing a verified player's
  address a way to have junk forwarded. It is the cheap half of the filter:
  lengths and magic bytes, no session state.

**A repeat offender is dropped at the top.** Four failures inside thirty
seconds and a source goes into a penalty box — a minute, then ten, then an
hour — and is dropped before it walks any stage. During an attack most of the
packets are the attacker's, so this is where headroom comes from: **1389 →
203 ns per packet, and the allocations go to zero**.

The escalation decays after an hour of clean time, measured from the *end* of
the last penalty rather than the last strike — otherwise serving a sentence
counts as good behaviour and the longest penalty decays itself the moment it
expires.

```json
"reputation": {"fast_pass": "challenge", "penalty_box": true}
```

Both default off-ish: `penalty_box` is off unless asked for, and `fast_pass`
defaults to the stricter `challenge`. With the box off, strikes and would-be
demotions are still counted, which is how you size it before switching it on.

### A trusted source cannot be demoted

This is the part worth being careful about. The obvious design — anything
that trips a check goes in the box — turns the box into a weapon. Source
addresses in a UDP flood are written by the attacker, so anyone could send a
packet claiming to be a real player and have that player banned. The
mitigation becomes a better denial of service than the attack.

So demotion applies only to sources that are not currently trusted. Strikes
against a trusted source are counted as `shielded` and not acted on: the junk
is still dropped by the signature check, and the player whose address it
claimed stays online. `scrubline_reputation_shielded_total` rising means
either a spoofing attempt or a verified client genuinely misbehaving, and
both want a human rather than an automatic ban.

That is not a loophole for an abusive verified client: trust never skips the
rate cap, so the worst one can do is use its full allowance.

### Not all proof is equal

Answering a challenge means echoing a value that could only have come from a
reply sent to that address — the address answers for itself. Completing a
handshake can be done blind, so a spoofer can clear it for any address.

`fast_pass` therefore defaults to `challenge`. Widening it to `handshake` is
reasonable for a protocol that defines no challenge (RakNet does not), but it
is a decision, not a default.

### Two-stage table admission

Unverified sources used to occupy the same 65 536-slot session table as
connected players, on the strength of one opening packet — and those entries
were never read to decide anything. A flood of openers filled the table, and
once full the filter admits without tracking, so a flood of addresses that
completed nothing pushed real players off the protected path. Measured: 24 577
junk entries, from sources that never finished a handshake.

Sources part-way through a gate now live in a small ring instead. Eviction is
overwriting the oldest slot — no scan, no decision about who to drop — so a
flood churns its own entries and never reaches the sessions of people who
actually connected. The same flood now leaves exactly one entry in the
session table: the player.

### Clearing a false positive

A boxed source cannot promote itself out — it is dropped before it reaches a
gate. That is only defensible if an operator can, so the agent serves the
list and the way back:

```sh
curl -H "Authorization: Bearer $SCRUBLINE_NODE_API_TOKEN" node:9091/reputation
curl -X POST -H "Authorization: Bearer $SCRUBLINE_NODE_API_TOKEN" node:9091/reputation \
  -d '{"release":["198.51.100.9"]}'
```

Releasing leaves the escalation level alone: the next offence should not start
from scratch because this one was forgiven.

**Return traffic releases one on its own.** A boxed client that the origin keeps
answering, as a game server keeps sending to a connected player, is confirmed
like any other client and released at once: an address the origin talks to at
length belongs to a real client, and once trusted it could never have been
boxed. So is one that answers a challenge. A completed handshake releases
nobody, since a spoofer can complete one blind. `scrubline_reputation_freed_total`
counts these releases, and each one is a penalty that was cutting off a real
client.

## Return-traffic confirmation

Every other gate here reasons about the packets arriving, which is the hard
direction: a source address on an inbound packet is written by whoever sent
it, so proving anything about it needs a round trip the attacker cannot fake.
That only works for protocols that define a challenge.

Return traffic is different evidence and needs no protocol knowledge at all.
If the origin is sending a stream of packets to an address, the service has
decided that address is a peer worth answering — whatever it speaks, whatever
its handshake looks like. That works for a game nobody has written a
dissector for.

Confirmation is **ten packets across at least three 250 ms ticks**. Distinct
ticks rather than a count, because a burst of replies in one instant is what
an origin sends when it is bouncing errors at a flood; a conversation is
spread out. The datapath reports replies to the agent's `/egress`, which is a
separate endpoint from `/decide` because a reply is not being judged —
nothing about it is permitted or dropped. It is evidence.

### It is weaker than a challenge, and the order matters

| Proof | What it establishes |
| --- | --- |
| `handshake` | the source speaks the protocol — but an opening sequence can be sent blind |
| `egress` | the service treats this address as a client — but an attacker can arrange that by spoofing a victim's address into a service that replies to anything |
| `challenge` | the address can receive, because it echoed something only a reply could have taught it |

So `fast_pass` still defaults to `challenge`. Setting it to `egress` is a
deliberate widening, and the right one for a protocol with no challenge to
issue:

```json
"reputation": {"fast_pass": "egress"}
```

### Lockdown

While a prefix is under a recognised attack, a source the origin has never
answered can be held back:

```json
"egress": {"lockdown": "limit", "lockdown_pps": 500, "grace_millis": 500}
```

Four things have to line up, and each is a way it does not fire: the operator
asked for it, the prefix is actually pulsing, this node can see the return
path, and the source has neither proved itself nor been answered — and is
past its grace.

**The grace window is not a nicety.** Without it lockdown is a trap with no
exit: a new client is unconfirmed, so it is held back, so its packets never
reach the origin, so the origin never answers, so it is never confirmed.
Every new source gets 500 ms in which the origin can vouch for it.

`limit` is the mode to reach for: an unconfirmed source is held to a trickle
rather than silenced, so a client the origin has not got round to answering
is slowed, not cut off. It is off by default either way — during an attack it
holds back clients whose only fault is being new, and that is a deployment's
call.

### Asymmetric paths

Some deployments never route the return path through the scrubber at all:
with direct server return the origin answers the client straight out. A
prefix showing ingress and no replies is recognised as asymmetric, and
everything depending on return traffic stops applying to it. Reading "we
cannot see the replies" as "nobody is confirmed" would hold back every real
player on the service — the outage the attacker wanted.

`scrubline_egress_visibility{prefix,state}` is worth a dashboard panel: a
prefix reading `asymmetric` is one where this whole layer is not running,
which is correct, and is not something to discover mid-incident.

## Return paths

BGP gets a customer's traffic to the fabric. It cannot get it back: once the
scrubbers are announcing the prefix, a route toward it leads to the
scrubbers. Clean traffic is encapsulated to the customer's own edge instead,
and that return path is part of the policy rather than something arranged
alongside it.

```json
"tunnels": [{"id":"northwind","remote":"198.51.100.1","prefixes":["203.0.113.0/24"],"key":42}]
```

The local end is each node's own address, because it is per node, not per
tunnel: the customer's tunnel runs straight to the scrubbing node. An operator
assigns it with `PUT /v1/nodes/{id}/tunnel-endpoint`; a node can also supply
one with `-tunnel-src`, and the operator's assignment wins and survives the
node re-registering. No two nodes may hold one address, and the address must
already be one the node owns: Scrubline does not configure it.

### One location per customer

Pin a tunnel to the node it should end on, and the customer holds a single
GRE tunnel, to that node's address:

```json
"tunnels": [{"id":"northwind","remote":"198.51.100.1","prefixes":["203.0.113.0/24"],"node":"node-a1b2c3d4e5f60718"}]
```

`PUT /v1/tunnels/{id}/location` with `{"node":"..."}` moves it, which is what
a panel offering a choice of location calls. Only that node announces the
customer's prefixes while it copes. When it passes 80% of its `-capacity-pps`
over the last second or the last ten, or stops heartbeating, the other nodes
carrying the prefixes announce them
too, as anycast, to take the load; they forward what they scrub to the
location over node-to-node GRE, and it delivers everything down the
customer's one tunnel. Help holds for five minutes after the location was last
measured overloaded, so the routes do not flap with every swing of an attack.
The other nodes keep their node-to-node tunnels up while they stand by, so
help starts the moment BGP moves traffic.

A tunnel with no `node` fans out instead: every node carrying the prefixes
holds its own tunnel to the one customer endpoint, and all of them announce.

The agent serves the compiled result at `/tunnels`, the way it serves the
announcement plan at `/bgp`; the provisioner that [`scripts/install.sh`](docs/install.md)
installs beside it applies that to the box and reports which tunnels it
built. The MTU and the TCP MSS clamp are derived from the
encapsulation's overhead (1476/1436 for GRE, 1472/1432 with a key,
1480/1440 for IPIP, which pinned to a location clamps to the 1436 that
node-to-node GRE carries) and an MTU that does not fit is refused with the one
that does. The clamp is the part people skip: without it, a customer whose
path drops the ICMP that path-MTU discovery needs sees TCP complete its
handshake and then hang, which reads as a scrubbing fault.

### Both directions

A tunnel carries traffic both ways by default: clean traffic down to the
customer, and the customer's replies back up it to the node, which forwards
them to the internet. The agent renders forwarding rules for that half that
admit only sources inside the tunnel's own prefixes, per address family, so
the tunnel cannot relay anything else the customer's edge sends into it; SYNs
coming back up are MSS-clamped too. `"direction": "return"` is for customers
whose replies leave by their own transit, and forwards nothing that comes up
the tunnel.

Every node's firewall accepts GRE and IPIP only from the other nodes' tunnel
addresses and the customer end of each tunnel it builds. The list is compiled
from the fabric, so a node that joins is accepted everywhere on the next
compile, and one that leaves is dropped.

### Controlling tunnels from the API

Operators change tunnels on the deployed policy in place: `GET /v1/tunnels`
shows every tunnel on every node carrying it (the address it terminates on,
what was last reported, what is being announced and why), `PUT` and `DELETE
/v1/tunnels/{id}` add, replace or remove one, and `POST
/v1/tunnels/{id}/disable` or `/enable` with `{"nodes":[...]}` takes it down or
brings it back on particular nodes, which withdraw its prefixes meanwhile.
Each change is validated with the whole policy, saved as its next version and
deployed straight away. See [docs/api.md](docs/api.md#9-getting-the-clean-traffic-back).

### Customers and clean-traffic speed

A tunnel is allocated to a customer with `"tenant"`: its prefixes must lie
within that customer's own (and default to them), and the customer cannot be
deleted while it is allocated. `"rate_mbps"` caps the clean traffic the
customer receives down it, in total across the fabric, at most 2500 (2.5
Gbit/s); a tunnel without one is held to that maximum. A pinned tunnel carries
all of the customer's clean traffic out of its location, so the location
shapes it to the whole allowance with a `tc` token bucket. A fanned-out one
splits it evenly across the nodes announcing its prefixes, each shaping to its
share; since anycast rarely spreads traffic evenly, a node can be held to its
share while others sit under theirs. `PUT /v1/tunnels/{id}/rate` changes only
the speed.

The shaper keeps a game's packets from waiting behind bulk traffic. Under the
token bucket, `fq_codel` keeps the queue. Each flow waits in its own queue, so
a game's small, steady packets go out ahead of a download, or what is left of
a flood, filling the allowance. A queue that stands for longer than 5 ms is cut
back. A single shared queue would hold every packet behind whatever is filling
the allowance. The queue's memory is held to about 100 ms at the rate, and
never less than 128 KiB. On a kernel without `fq_codel`, the token bucket keeps
the rate over a short queue of its own. The tunnel stays up, and the
provisioner's status says what failed.

### On-demand mitigation

By default a node filters a customer's traffic all the time. A tunnel can
instead be mitigated on demand, so that each node holding it watches the
customer's traffic and only applies the rest of its policy once an attack
starts. A game filter's HTTP rules stay on throughout:

```json
"tunnels": [{"id":"northwind","remote":"198.51.100.1","prefixes":["203.0.113.0/24"],
             "node":"node-a1b2c3d4e5f60718","rate_mbps":1000,
             "mitigation":"on_demand","attack_pps":150000,"attack_mbps":400}]
```

- **Each node watches only the tunnels it holds.** For a pinned customer that
  is their location; for a fanned-out one, every node holding the tunnel, each
  against its share of the thresholds, split the way `rate_mbps` is. A node
  helping another with a pinned customer holds no tunnel for them, so it
  watches nothing for them and filters what it scrubs for them from the first
  packet.
- **Until the traffic reaches a threshold it is only watched,** except by the
  game filters' [HTTP rules](#http-on-the-servers-own-address-layer-7), and
  the request model behind them, which hold all the time: application abuse
  takes a few requests a second, far under any attack threshold. Nothing else
  is dropped, not even what a rule would drop, and decisions read `watching
  only: tunnel northwind is under its attack thresholds`. The other game
  filters still see the traffic, so a player who connects in the meantime is
  known when mitigation starts and is not dropped as a stranger.
- **The first flow that takes the traffic to `attack_pps` or `attack_mbps`**,
  over the last second, starts mitigation, and the node's whole policy applies
  from that flow on: the rules, the game filters, the classifiers and the
  penalty box, which also counts what the HTTP rules dropped while idle. It lasts until the traffic has stayed under
  both thresholds for five minutes, since attacks come in waves and stopping
  between them would let the start of every wave through. The fabric
  recompiling does not interrupt it.
- **An attack that keeps coming back is held longer each time.** A mitigation
  that starts within an hour of the last one ending is that attack's next wave,
  and holds twice as long as the last one did, up to an hour: five minutes,
  then ten, twenty, forty and sixty. An attacker that times its waves to the
  hold gets less through with each one. See
  [Attacks that adapt](#attacks-that-adapt).
- **Unset, the thresholds are half the clean-traffic allowance**, and the
  packet rate that is at 512-byte packets, so a flood of small packets reaches
  the packet threshold long before the bandwidth one. A flow record's `bps`
  gives its bit rate; without one a node counts the packets' headers and
  payload.

The trade-off is what passes while a tunnel is idle: beyond the HTTP rules, an
attack smaller than its thresholds is never filtered, and nor is the traffic
of an attack in the moments before it reaches a threshold.

`PUT /v1/tunnels/{id}/mitigation` with `{"mitigation":"on_demand"}`, and any
thresholds, switches a tunnel without restating it. The node heartbeats as soon
as a mitigation starts, and `GET /v1/tunnels` shows on each node's row whether
it is `mitigating`, since when, which wave it is and how long it holds, and what
reaches it. On the node,
`scrubline_tunnel_mitigating{tunnel}`, `scrubline_tunnel_ingress_pps`,
`_ingress_bits_per_second`, `_attack_pps`, `_attack_bits_per_second`,
`_mitigation_wave`, `_mitigation_hold_seconds`, `_mitigations_total` and
`_unfiltered_total` say the same.

### A dead tunnel withdraws the prefix

This is the failure the design is actually for. A node announcing a prefix it
cannot deliver attracts the customer's traffic and drops all of it — and it
looks healthy from every angle that normally matters: datapath counters fine,
announcements up, customer offline.

So whatever provisions the tunnels reports back to the agent, the agent
carries that on the heartbeat it already sends, and the compiler treats a
dead return path the way it treats a dead node:

```
203.0.113.0/24   edge-lhr  lhr     withdraw  -   return tunnel northwind is down
203.0.113.0/24   edge-fra  fra     announce  0   anycast member at full preference
```

One node withdrawn, one prefix, named cause; the rest of the fabric picks the
traffic up. A shed, not an outage, and it reverses when the tunnel recovers.

A tunnel that has never reported does **not** withdraw anything. Absence of a
report usually means nothing is reporting, and inferring failure from silence
would blank the fabric of anyone who has not wired a provisioner up yet.
`"required": true` reverses that for operators who would rather drop traffic
than black-hole it. `scrubline_tunnel_up` follows the same rule: a
never-reported tunnel is absent from the series rather than reading zero, so
an alert on it does not fire across a fleet that simply is not reporting.

### Customer BGP sessions

For customers who announce their own prefixes rather than having them typed
into a policy:

```json
"sessions": [{"id":"northwind","peer_ip":"198.51.100.1","peer_as":64512,
              "prefixes":["203.0.113.0/24"],"password":"...","regions":["lhr"]}]
```

These render as BIRD at the agent's `/sessions`, not as the ExaBGP commands
`/bgp` serves. Announcing is an imperative act, which is what a command pipe
is for; peering is a standing configuration with an import filter and a
prefix limit on it. The filter admits the policy's prefixes and anything more
specific inside them, since customers de-aggregate under attack.

Routes learned from a customer do not add themselves to the protected set.
The policy still decides what the fabric defends — otherwise a peer that
leaked a supernet would have you announcing address space nobody asked you to
protect, on the say-so of the peer.

## Customer analytics

Observability above is for the people running the fabric. This is for the
people buying it, and it is a different question.

A customer does not have a node. They have a prefix, and under anycast it is
carried by every scrubber at once, so per-node counters cannot answer "was I
attacked, how big was it, and did you stop it". Everything under
`/v1/analytics` is therefore keyed by **prefix** and summed across the fabric.

The datapath accounts traffic per protected prefix — offered and scrubbed, as
both cumulative volume and a rolling rate. Nodes attach those counters to the
heartbeat they already send, and the control plane deltas them into per-minute
buckets kept for a day. Cumulative counters rather than rates, deliberately: a
counter that only counts up survives a report being missed, and one that goes
backwards is read as a node that restarted rather than as negative traffic.

```sh
scrubctl analytics 1h
```

```
PREFIX           OFFERED   SCRUBBED  MITIGATED  PEAK PPS  NOW PPS  NODES  ATTACKS  STATE
198.51.100.0/24  240000    0         0.0%       0         2400     2      0        clear
203.0.113.0/24   33000000  32000000  97.0%      2230000   1650000  2      1        UNDER ATTACK
```

`NODES` is how many scrubbers are carrying the prefix right now. Under anycast
that is the fabric absorbing the attack: a customer seeing `1` during a flood
is seeing a problem, not a quiet day.

### Attacks, not just numbers

An attack is recorded as an event with a start, an end, a peak, and the rules
and filters that did the stopping — "you were attacked" on its own is not
something a customer can act on.

```
STARTED               PREFIX          FOR           PEAK PPS  SCRUBBED PPS  SHAPE  STOPPED BY
2026-10-17T11:35:58Z  203.0.113.0/24  1s (ongoing)  2230000   1600000       flood  dns-amp(asic) mc-survival(zc)
```

An event opens when a meaningful share of a prefix's traffic is being scrubbed
— above a magnitude floor, so a stray packet against a quiet prefix is not
billed as an attack — or when the burst detector recognises a pulse train. It
does not close on the first quiet poll: a burst train is quiet between bursts
by design, and closing early would report one attack as fifty, which is the
reporting the attacker's interval is paying for. When it does close, it is
dated to when the traffic stopped, not to the end of the time spent confirming
it.

The time series works the same way. Each point reports the heaviest moment
inside it rather than an average over it, because an average is precisely what
a burst attack is shaped to hide.

### Tenants

Showing a customer their traffic used to mean handing them an operator token,
which also reads every other customer's prefixes, the fleet's topology and the
policy behind it. A tenant credential is scoped to the prefixes that customer
is entitled to and is read-only:

```sh
scrubctl tenant-add customer.json      # {"name":"...","prefixes":["203.0.113.0/24"]}
scrubctl tenant-token ten-3699abaf8b8b4cf5
```

A prefix the credential is not entitled to answers `403` whether or not it
exists, so a customer cannot map the platform's other customers by watching
which prefixes answer differently.

History is in memory and is not durable: it is derived from reports that keep
arriving, so a restarted control plane rebuilds it within a couple of
heartbeats rather than carrying stale numbers across the gap. The customers
themselves, their entitlements and their credential hashes are durable, and
replicate to a follower like everything else.

## State and recovery

The control plane keeps its state in one file, named with `-state`. Without
one it runs entirely in memory and loses everything on restart, which it says
loudly at startup.

A write is durable before it is acknowledged. Saving a policy writes the state
to a sibling temp file, flushes it, renames it over the real one and flushes
the directory, so a crash mid-write leaves the previous state intact rather
than a truncated file. If the write fails the change is rolled back and the
call returns `503` — a caller is never told a policy was saved that the
control plane will forget.

What is durable: node registrations and their credential **hashes**, policies,
which policy is deployed, the training set, and the fitted model. What is not:

- **Liveness.** Heartbeats arrive every couple of seconds per node; persisting
  them would mean rewriting the file constantly to save something worthless
  the moment the process stops. Nodes load back stale and are withdrawn from
  anycast until they check in, which is the truth — nobody knows whether they
  are up.
- **Programs, the announcement plan, the steering levels.** All derived.
  Recompiling them from a snapshot would hand the fabric announcements built
  for nodes that may be gone.
- **Reported counters.** A measurement from before the restart is not a
  measurement of now.

Recovery needs no operator. Nodes keep enforcing their last program while the
control plane is down — they only install a program they successfully fetched
— and their credentials survive, so they do not even re-enrol. Once they
heartbeat, the standing policy is recompiled onto the live set automatically:

```
$ kill -9 <control plane>          # nodes keep dropping: drop asic tcam-udp-flood
$ scrub-api -state state.json      # same file
  policies recovered:  pol-1 game-edge v1
  model recovered:     ready, 40 samples, 8 held out
  fabric:              recompiled, both nodes announcing
```

## Replicas

A replica is a second control plane that follows the primary, so a takeover
loses nothing:

```sh
scrub-api -addr 0.0.0.0:8080 -state replica.json \
  -role replica -primary https://primary:8080 -ca ca.pem
```

It pulls `GET /v1/state` on an interval — pulling rather than being pushed, so
a replica that was down catches up on its own — writes what it gets through to
its own file, and serves every read. It **refuses every write** with `409`,
pointing at the primary.

That refusal is the design, not a limitation to work around. Two control
planes accepting writes would compile conflicting announcement plans and flap
the fabric's BGP, and nothing reachable from a replica can tell a dead primary
from an unreachable one. So **promotion is deliberate**:

```sh
curl -X POST -H "Authorization: Bearer $SCRUBLINE_API_TOKEN" https://replica:8080/v1/promote
```

Fence the old primary first. Automatic failover needs a consensus store to
decide who is leader; this does not have one, and inventing one here would be
worse than an operator making the call. `/health` reports which mode a control
plane is in.

A replica holds the whole durable state, including every credential hash, so
it authenticates to the primary with the operator credential. A replica is
part of the control plane, not an edge node.

## Credentials

Three secrets, three blast radii. A scrubbing node sits at the edge in someone
else's datacentre, so it never holds a credential that can change the fabric.

| Secret | Held by | Can do |
| --- | --- | --- |
| `SCRUBLINE_API_TOKEN` | operators, `scrubctl` | everything: policy, deploy, ML, fabric, `/metrics` |
| `SCRUBLINE_ENROLL_TOKEN` | every node agent | register, and collect a credential. Nothing else |
| `SCRUBLINE_NODE_API_TOKEN` | the agent, and whatever scrapes it | that agent's own `/decide`, `/metrics`, `/bgp` |
| tenant credential | one protected customer | read the analytics for their own prefixes. Nothing else |

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

A tenant credential is narrower still, and issued the same way: minted per
customer, returned once, kept as a hash, rotated by issuing again. It is
read-only and reaches `/v1/analytics` for the prefixes that customer is
entitled to, and nothing else — not the fleet, not the policy behind their
protection, not another customer's traffic. Entitlement is by containment, so
a customer who brings a /22 is entitled once however it is later split, but a
/24 entitlement never opens up the /22 around it. Deleting the customer takes
the credential with it.

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
cargo run --release --bin scrub-api -- -addr 127.0.0.1:8080 -tls-cert certs/server.pem -tls-key certs/server-key.pem
```

```sh
export SCRUBLINE_ENROLL_TOKEN=enroll-secret SCRUBLINE_NODE_API_TOKEN=node-local-secret
cargo run --release --bin scrub-node -- -api https://127.0.0.1:8080 -ca certs/ca.pem \
  -name scrub-a -region iad -capacity 100 -capacity-pps 100000 \
  -listen 127.0.0.1:9091 -advertise 198.51.100.1:9091 -local-as 65001
cargo run --release --bin scrubctl -- -api https://127.0.0.1:8080 -ca certs/ca.pem fabric
```

Listeners close a connection that sends nothing for 10 seconds after it is
accepted, take 10 seconds at most over a request's headers, and close one that
has been idle for two minutes, so a handful of idle connections cannot hold one
open.

## API

Full reference and a worked walkthrough: **[`docs/api.md`](docs/api.md)**.
Machine-readable specs: [`api/openapi.yaml`](api/openapi.yaml) for the control
plane, [`api/node-openapi.yaml`](api/node-openapi.yaml) for the node agent.
`make spec-check` verifies both against the routes the code actually serves,
and runs in CI alongside `make test`.

Policies are validated on save. A prefix or match CIDR that does not parse is rejected rather than compiled into a rule that silently never matches, and flow records are rejected if `pps` is negative or a port falls outside 0..65535.

- `POST /v1/nodes/register` node name, region, capacity (`capacity_gbps` and `capacity_pps`), backends; returns the node and the credential issued to it
- `GET /v1/nodes`
- `POST /v1/policies` protected prefixes, stage rules, per-prefix steering, and game filters
- `POST /v1/policies/{id}/deploy` compile the ASIC, FPGA, and ZC programs and the fabric's BGP plan
- `POST /v1/nodes/{id}/heartbeat` keep a node live; the body optionally carries the node's datapath counters
- `GET /v1/nodes/{id}/stats` the counters a node last reported
- `GET /v1/fabric` the BGP announcement plan and the compiled programs
- `GET /v1/state` the durable state a replica follows (operator only)
- `POST /v1/promote` turn a replica into the primary (operator only)
- `GET /metrics` Prometheus exposition for the control plane and the fleet
- `GET /v1/nodes/{id}/program` what a node agent installs
- `POST /v1/decide` run a flow record through a node's pipeline
- `POST /v1/ml/samples` labeled flow records (`label` 0 clean, 1 attack); one whose payload is an HTTP request trains the request model
- `POST /v1/ml/train` fit the flow and request models
- `GET /v1/ml/model` weights the node agent installs
- `POST /v1/ml/score` score a flow, and the HTTP requests it carries
- `DELETE /v1/ml/model` retire the published models; agents clear them on the next poll
- `POST /v1/nodes/{id}/heartbeat` also carries `tunnels`: what this node's provisioner says about its return paths
- `PUT /v1/nodes/{id}/tunnel-endpoint`, `DELETE ...` assign or clear the address a node's tunnels terminate on (operator only)
- `GET /v1/tunnels` every tunnel of the deployed policy, node by node (operator only)
- `PUT /v1/tunnels/{id}`, `DELETE /v1/tunnels/{id}` add, replace or remove a tunnel in the deployed policy, and deploy it (operator only)
- `POST /v1/tunnels/{id}/disable`, `POST /v1/tunnels/{id}/enable` take a tunnel down or bring it back on the listed nodes (operator only)
- `PUT /v1/tunnels/{id}/rate` set a tunnel's clean-traffic allowance, up to 2500 Mbit/s in total (operator only)
- `PUT /v1/tunnels/{id}/location` pin a tunnel to the node the customer's one tunnel ends on (operator only)
- `GET /v1/analytics/overview` per-prefix traffic, mitigation and attack state, summed across the fabric
- `GET /v1/analytics/series` one prefix over time; each point is the heaviest moment inside it, not an average
- `GET /v1/analytics/events` the attack log, each entry naming the rules and filters that stopped it
- `POST /v1/tenants`, `GET /v1/tenants`, `DELETE /v1/tenants/{id}` customers and their entitlements (operator only)
- `POST /v1/tenants/{id}/token` issue or rotate a customer's credential; returned once (operator only)

Example policy: `configs/policy.example.json`. Example training set: `configs/ml.samples.json`.

```sh
cargo run --release --bin scrubctl -- ml-load configs/ml.samples.json
cargo run --release --bin scrubctl -- ml-train
```

The node agent also takes `-local-as`, `-bgp-next-hop` and `-capacity-pps` for
steering; see [Steering](#steering).

