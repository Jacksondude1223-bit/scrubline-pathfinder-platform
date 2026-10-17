# Temporary Vercel API test

Self-contained snapshot of the real control-plane API at commit aeee294cfcf5a33cf5ab5d9719d5ffd44b7a9e73. Everything needed to build is inside this folder. The original commands, source, and deployment configuration are unchanged.

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
- Only the control-plane API runs. The separate node-agent `/decide`, `/metrics`, and `/bgp` API is not included.
- The continuous fabric reconciliation loop is not started. Explicit policy deployment still compiles programs; periodic membership/load reconciliation is not exercised here.
- The test header `X-Scrubline-Test-Mode: ephemeral-memory` identifies every response. Responses are marked `Cache-Control: no-store`.
- Authentication, 200/400/401/403/404/409 responses and policy evaluation can be inspected here. Durable-write failure responses cannot be tested with this in-memory store.

## Local verification

```sh
go test ./...
SCRUBLINE_API_TOKEN=local-operator SCRUBLINE_ENROLL_TOKEN=local-enroll PORT=3000 go run .
```

## Remove afterward

Delete the entire `vercel-test/` folder and disable/delete the temporary Vercel deployment or restore the project's Root Directory. Nothing outside this folder needs reverting. The copied source does not automatically track future changes in the parent repo.
