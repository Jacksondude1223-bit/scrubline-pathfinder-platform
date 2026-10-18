# Temporary Vercel API test

Self-contained snapshot of the real control-plane API at commit abf05ab791e4ad1da0449bae57f0d27319de3133. Everything needed to build is inside this folder. The original commands, source, and deployment configuration are unchanged.

The copy does not track the parent repository on its own, and it had already fallen three feature commits behind once. `./sync.sh` refreshes it; see [Resync](#resync).

## Deploy

1. Merge this folder into the branch connected to your Vercel project.
2. In Vercel Project Settings, set Root Directory to `vercel-test` and Framework Preset to **Go**. Remove any existing install/build/output overrides so this folder's `vercel.json` supplies the build command.
3. Add `SCRUBLINE_API_TOKEN` and `SCRUBLINE_ENROLL_TOKEN` as environment variables for the deployment environment. Generate two different values with `openssl rand -hex 32`. Keep them private.
4. Redeploy. The API keeps the original paths, including `/health`, `/v1/nodes`, `/v1/policies`, `/v1/decide`, and `/metrics`. `/` returns a small test-instance status object.

## Send requests

Set `API` to your deployment URL, without a trailing slash. Set `API_TOKEN` and `ENROLL_TOKEN` to the values configured in Vercel.

```sh
curl -i "$API/health"
curl -i -H "Authorization: Bearer $API_TOKEN" "$API/v1/nodes"
curl -i -H "Authorization: Bearer $ENROLL_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"name":"test-node","region":"iad","capacity_gbps":10,"capacity_pps":100000,"advertise":"192.0.2.1:9091"}' \
  "$API/v1/nodes/register"
curl -i -H "Authorization: Bearer $API_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"name":"test-policy","protected":["203.0.113.0/24"],"rules":[{"id":"bogon","stage":"asic","action":"drop","priority":100,"match":{"src_cidr":"0.0.0.0/8"}}]}' \
  "$API/v1/policies"
```

Registration returns a node credential once. Use it for that node's heartbeat and program endpoints, as in the main API docs. Keep sending heartbeats if you need a live node for deployment tests; nodes expire after 30 seconds. To deploy a policy, POST to `/v1/policies/<returned-policy-id>/deploy` with the operator token. A successful deploy compiles a plan; this test does not attach hardware or announce routes.

## Limits

- This is the real API implementation with its original validation and authentication, using a disposable in-memory store. There is no shared database. Cold starts, redeployments, and scaling can lose state or route requests to a different empty instance. A saved policy or registered node can therefore disappear between calls. Use Sandbox or the normal container deployment for reliable multi-request lifecycle tests.
- Only the control-plane API runs. The separate node-agent API — `/decide`, `/metrics`, `/bgp`, `/tunnels`, `/sessions`, `/reputation` — is not included.
- Policies carrying `tunnels`, `sessions` or `reputation` are accepted, validated and compiled into programs here, which is what makes their validation testable. Nothing renders or enforces them: return tunnels are rendered by the node agent, customer peerings are configured by it, and the reputation tiers live in its datapath. A policy that compiles cleanly here says the control plane is happy with it, not that a scrubber would do anything with it.
- A return tunnel reported down withdraws its prefixes from a node, and the report arrives on a node heartbeat. With no agent running, nothing reports, and nothing is withdrawn on that basis.
- The continuous fabric reconciliation loop is not started. Explicit policy deployment still compiles programs; periodic membership/load reconciliation is not exercised here.
- The test header `X-Scrubline-Test-Mode: ephemeral-memory` identifies every response. Responses are marked `Cache-Control: no-store`.
- Authentication, 200/400/401/403/404/409 responses and policy evaluation can be inspected here. Durable-write failure responses cannot be tested with this in-memory store.

## Local verification

```sh
go test ./...
SCRUBLINE_API_TOKEN=local-operator SCRUBLINE_ENROLL_TOKEN=local-enroll PORT=3000 go run .
```

## Resync

```sh
./sync.sh
go test ./...
```

It copies the control plane's current source over `internal/`, deriving the
package list from the imports rather than from a list written down here — the
set moves, and two packages appeared the last time this was refreshed. Run it
from a clean checkout of the parent repo, then commit the result.

Nothing outside `internal/` is touched, so `main.go`, `vercel.json` and this
file survive a resync.

## Remove afterward

Delete the entire `vercel-test/` folder and disable/delete the temporary Vercel deployment or restore the project's Root Directory. Nothing outside this folder needs reverting.
