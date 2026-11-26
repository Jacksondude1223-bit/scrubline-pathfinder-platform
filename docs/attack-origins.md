# Attack-origin country telemetry

Pathfinder can attach sampled source-country totals to attack events for the panel's D3 origin view. Sampling is opt-in and runs only on real NFQUEUE inline UDP game-filter `drop` decisions. Simulated `/decide` requests, passive discovery, accepted traffic, protocol challenges, hardware/upstream drops and packets that bypass the inline worker are not included.

Inline game verdicts now update the existing per-prefix offered/dropped counters and packet-rate meter, so real inline attacks can trigger the same attack-event detector as other inspection traffic. Country lookup does not change a packet's verdict.

## Configuration

Use an operator-supplied country MMDB file, for example DB-IP Country Lite or MaxMind GeoLite2 Country. The reader loads up to 64 MiB into memory once at startup. There are no online IP lookups, automatic database downloads or source-IP logs.

Download a current database from its publisher and follow that publisher's license. The DB-IP Lite country database is available at https://db-ip.com/db/lite.php and requires attribution, including a link on web pages using its results. The companion panel country-telemetry update displays that attribution when samples identify DB-IP as their provider. MaxMind downloads and licensing are separate. Test data in tests/data is an artificial MaxMind test database, not a production database.

Add these flags to the existing scrub-node invocation after installing the database:

```sh
-origin-country-db /etc/pathfinder/country.mmdb \
-origin-country-provider dbip \
-origin-longitude -78.87 \
-origin-latitude 42.89 \
-origin-label BUF-ORBITEL-EDGE
```

The coordinates and label above illustrate a Buffalo filtering edge. Set the actual filtering location for each node. Location is optional; omit all three location flags to suppress destination arcs. A location is not inferred from a customer's backend address. Provider must be `dbip`, `maxmind` or `custom`. The existing `-inline-queue` flag is required when country sampling is configured. An unreadable/invalid database or partial location causes a startup configuration error. Without `-origin-country-db`, country sampling remains disabled.

## Bounds and event attribution

The sampler randomly selects roughly one in 128 drop decisions, with at most 2,000 country lookups per node per second. It retains at most 128 protected prefixes and 64 country counters per prefix; extra countries become unknown. Prefixes beyond the budget are omitted and increment the node report's `limited` counter. Samples are not extrapolated to total attack packets and distinct source-IP counts are not collected.

Each node sends cumulative country counters, unknown counts, process and prefix generations, provider and optional filtering location through its existing authenticated heartbeat. The control plane compares consecutive reports only for prefixes in that node's current program. First reports, generation changes, counter rollback, malformed reports and gaps over 30 seconds establish a new baseline without importing old samples. Repeated counters contribute zero. Out-of-order observations cannot roll back a baseline.

A delta attaches only to an open attack whose start precedes the whole reporting interval, while that prefix is still classified as under attack. Samples from before detection, quiet periods and the attack detector's closing hold are omitted. There is no backfill for historical events. Event country storage is capped at 64 countries, with overflow counted as unknown. Retiring a node or removing prefixes clears the corresponding baselines.

Only country totals are retained. Public event metadata uses:

```json
{
  "origin_samples": {
    "basis": "sampled_packets",
    "scope": "inline_game_drop_decisions",
    "providers": ["dbip"],
    "countries": [{ "code": "MX", "packets": 20, "sourceIps": null }],
    "unknownPackets": 5,
    "destination": { "longitude": -78.87, "latitude": 42.89, "label": "BUF-ORBITEL-EDGE" }
  }
}
```

The example is illustrative. Metadata is absent until an event has actual attributable samples. Different or missing reporting-node locations suppress a shared destination rather than choosing one. Existing analytics authorization restricts events to tenant-visible prefixes. Raw node country counters are excluded from fleet summary responses. Country attribution can reflect spoofed or reflected source addresses; it is not attribution to a person or attacker location.

## Rollout and verification

Build and deploy the updated control plane and node binaries, and deploy the companion panel country-telemetry API/web changes. Configure a current licensed database and the actual node location, then restart the node through the normal release workflow. This PR does not deploy binaries, install a database, alter nftables or activate a worker.

Verify that the node's authenticated stats include origin_samples and that the intended inline queue is active. During a controlled test on a test destination, verify per-prefix inspection counters, an open attack event and later country sample deltas. Requests to `/decide` must not populate country counters. Replaying an unchanged heartbeat must not add samples. Check both IPv4 and IPv6 database lookup, unknown-address behavior, restart baselines and another tenant's inability to view the event. Upstream-only attacks should not be represented as inline samples.

The feature tests cover MMDB IPv4/IPv6 reads, unknown countries, explicit configuration, sample budgets, counter reset/replay, stale and unauthorized intervals, destination consistency, simulation exclusion and inline per-prefix telemetry. The Vercel source snapshot is kept in sync.
