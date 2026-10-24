# Rust migration

The control plane, node agent, packet pipeline, operator CLI, demo traffic
generator, and Vercel test adapter now use Rust. Production source and build
commands no longer require Go. The existing binary names, flags, environment
variables, OpenAPI routes, policy JSON, and version-one durable state are retained.

## Build and verify

Rust 1.88.0 is selected by `rust-toolchain.toml`; dependency resolution is pinned
in `Cargo.lock`. The Vercel adapter has its own lockfile.

```sh
make build
make test
make rust-check
make spec-check
make runtime-test
make snapshot-check
```

`make build` writes `bin/scrub-api`, `bin/scrub-node`, `bin/scrubctl`, and
`bin/scrub-traffic`. `make certs` uses Python 3 and OpenSSL to generate a development
CA and server certificate. `make bench` benchmarks the ordinary and verified
source paths. `make up` builds the Rust containers and starts the demo fabric.

## Compatibility coverage

- 24 Go-generated routing/compiler scenarios check region constraints, backend
  capabilities, liveness, capacity/load padding, and return-path health.
- Recorded Go packet sequences check decisions and counters for ASIC/FPGA/ZC
  precedence, sliding rate windows, custom framing, RakNet handshakes, A2S HMAC
  challenges, source reputation, observation mode, burst lockdown, egress
  confirmation, ML decisions, and expiry.
- ML weights, loss, evaluation metrics, features, and scores are compared with
  the Go baseline using numerical tolerances.
- A version-one Go snapshot verifies state import, stable node IDs, hashed
  credentials, and stale-on-restart liveness. Failed writes are checked for
  in-memory rollback.
- Native process tests cover API/node/traffic integration, all credential roles,
  tenant prefix boundaries, credential rotation and revocation, attack analytics,
  tunnel health, restart recovery, explicit replica promotion after fencing the
  primary, and verified TLS.
- The OpenAPI checker reads the Rust dispatch and agent router directly.
- CI builds the Rust Docker fabric and the Vercel Rust adapter.

The reference fixtures were captured from Go baseline commit
`3c912dcf84160ab92f560e921f180d9042f8d4c6`. They remain checked in as data; their
original implementation is available in Git history. Empty Go nil slices are
compared semantically with empty Rust arrays. Optional empty fields remain
omitted, and packet bytes retain JSON base64 encoding. State expiry and timer
configuration use millisecond precision; the detector/rate buckets retain their
250ms resolution.

One recording is deliberately not reproduced. Go rendered large communities
(`ASN:value:value`) inside ExaBGP's `community [ ]`, which ExaBGP refuses, so a
policy using one was never announced. They now render as `large-community [ ]`,
and the affected `commands` in `tests/fixtures/go-reference.json` were updated to
match; everything else in that fixture is Go's output unchanged.

## Deployment

Back up the state file and replace the binaries or rebuild the image. A restarted
control plane reads the existing state, marks nodes stale, and recompiles as
agents heartbeat. Existing node and tenant credential hashes survive. The node
agent re-enrolls after an unknown-node or rejected-credential response, keeps a
request for its next program waiting at the control plane, and polls for
explicit model withdrawal.

The Docker runtime uses Debian with the Rust binaries and CA roots. Its default
command is `scrub-api`; Compose selects the correct executable for each service.

The `vercel-test` folder is a self-contained Rust function using Vercel's official
`vercel_runtime` Axum adapter. It retains the temporary app's ephemeral-memory
behavior and test/cache headers. It is a control-plane test target; the long-lived
node agent remains a native process or container. See its README for settings.

No production deployment or merge is performed by preparing this migration.
