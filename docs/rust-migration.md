# Go to Rust migration

Status: **in progress; this branch is not a completed platform conversion.**

The Rust implementation is additive during the migration. Existing `make build`,
Docker Compose, API servers, node agents, and the Vercel snapshot continue to use
the existing Go binaries. No live deployment is changed by this branch.

## Available Rust components

| Component | Status | Validation |
| --- | --- | --- |
| `scrubctl` | All existing commands ported | Request construction, HTTP authorization/errors, file input, report rendering |
| Shared policy/program models | Ported | Go fixtures, null collections/scalars, base64 payloads, timestamps |
| Policy compiler | Ported | 24 Go reference scenarios: region scope, backend capabilities, stale nodes, capacity weighting, load padding, delivery health |
| ExaBGP renderer | Ported | Go output comparison and input validation |
| BIRD customer sessions | Ported | Go output comparison and input validation |
| GRE/IPIP tunnel renderer | Ported | Go output comparison, MTU/MSS validation, endpoint validation |
| Logistic ML classifier | Ported | Go weights, loss, holdout metrics, features, and scores compared with numerical tolerances |
| Load steering | Ported | Go reference rounds covering dwell, burst detection input, stale reports, and recovery |
| Prometheus text renderer | Ported | Escaping, stable output, duplicate/invalid names, nonfinite values |
| TLS client | Ported for `scrubctl` | TLS certificate verification enabled; private bundles replace system roots |

Rust uses empty arrays for empty required collection fields, while Go can emit
`null` for nil slices. The compatibility test normalizes this representation
only. Optional empty fields remain omitted, and the Rust decoder accepts null
collections and scalar zero values from Go. Timestamp and base64 field names
retain the existing wire format.

## Build and run

Install rustup; `rust-toolchain.toml` selects Rust 1.88.0 and installs formatting
and lint tools. `Cargo.lock` pins dependency resolution.

```sh
make rust-build
export SCRUBLINE_API_TOKEN='your-operator-token'
./target/release/scrubctl -api http://127.0.0.1:8080 nodes
./target/release/scrubctl -api https://api.example.com -ca certs/ca.pem bgp
./target/release/scrubctl -api http://127.0.0.1:8080 apply configs/policy.demo.json
./target/release/scrubctl -api http://127.0.0.1:8080 analytics 24h
```

The Rust CLI retains single-dash Go flags (`-api`, `-ca`) and also accepts their
double-dash forms. Global flags precede the command. `ml-train` accepts an
optional JSON file, as before. Invalid JSON files and IDs containing URL path or
query delimiters are rejected before a request is sent. Analytics window values
are encoded as a query value.

```sh
make rust-test
make rust-check
# End-to-end checks against the existing Go API, using an ephemeral loopback port:
go build -o target/go-reference-api ./cmd/scrub-api
python3 scripts/rust-cli-e2e.py
# Requires Go, and refreshes the checked-in compatibility fixtures:
make rust-reference
```

`scripts/rust-reference` calls the current Go implementations to generate
`tests/fixtures/go-reference.json`. CI regenerates it and rejects drift before
running the Rust suite. This gives the next migration steps a reproducible
baseline rather than maintaining separately invented expectations.

## Required before the platform cutover

1. Port game profiles, protocol validation, handshake and challenge cookie gates.
2. Port packet pipeline, pulse detector, source reputation, egress confirmation,
   rate limits, counters, and telemetry.
3. Port durable state, credential hashing/rotation, rollback on failed writes,
   node liveness, reconciliation, and replica synchronization.
4. Port the HTTP API and analytics while preserving every OpenAPI route,
   authorization role, response shape, status code, limit, and tenant boundary.
5. Port `scrub-node`, `scrub-api`, `scrub-traffic`, TLS listeners, timers, signal
   handling, certificate-generation tooling, and corresponding behavioral tests.
6. Replace build and Docker defaults only once the native binaries pass the
   existing behavior contracts. Migrate or explicitly retire the temporary
   `vercel-test` application with a tested hosting plan.
7. Run end-to-end node enrollment, policy deployment, decisions, telemetry,
   tenant analytics, replication/promotion, TLS, and container checks. Remove Go
   production code and its build jobs after those checks pass.

The Rust compiler and renderers currently operate as library components. The Go
servers do not call them. The Rust HTTP transport currently implements client
construction; the shared Go listener and jittered schedules remain to be ported.
The Rust steering controller uses exclusive `&mut self` access; a future shared
server must wrap it in synchronization when multiple tasks can mutate it.
