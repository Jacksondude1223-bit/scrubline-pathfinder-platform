# Running a demo stack

A single-host fabric you can point a client at: a control plane, three
scrubbers in three regions, a policy protecting two customers, and traffic
being driven through the datapath so the analytics have something real to
report.

```sh
cp deploy/.env.example deploy/.env
docker compose -f deploy/docker-compose.yml up --build
```

The API is on `http://127.0.0.1:8080`. First useful numbers appear after about
a minute; the first flood starts roughly twenty seconds in. Before that
everything is honestly zero, which is the point of running the generator at
all — an idle fabric and a broken one look identical.

## What comes up

| | | |
| --- | --- | --- |
| `api` | `127.0.0.1:8080` | the control plane |
| `node-a/b/c` | `:9091`, `:9092`, `:9093` | scrubbers in iad, fra, sin |
| `seed` | runs once | deploys the policy, onboards two customers, prints their credentials |
| `traffic` | continuous | drives flows through each node's `/decide` |

Two customers share the fabric, which is what makes the entitlement boundary
testable rather than theoretical:

- **Northwind Games** — `203.0.113.0/24`, gets attacked
- **Contoso Web** — `198.51.100.0/24`, stays quiet, for contrast

## Credentials

The seeder prints both tenant credentials on startup. If that has scrolled
away:

```sh
docker compose -f deploy/docker-compose.yml logs seed
```

The operator and enrollment tokens are whatever you put in `deploy/.env`.

## Trying it

```sh
NORTHWIND=<token from the seed output>

# What the customer sees
curl -H "Authorization: Bearer $NORTHWIND" localhost:8080/v1/analytics/overview | jq
curl -H "Authorization: Bearer $NORTHWIND" localhost:8080/v1/analytics/events | jq
curl -H "Authorization: Bearer $NORTHWIND" \
  "localhost:8080/v1/analytics/series?prefix=203.0.113.0/24&window=1h&step=1m" | jq

# What they cannot see: another customer's prefix, the fleet, the exposition
curl -i -H "Authorization: Bearer $NORTHWIND" \
  "localhost:8080/v1/analytics/series?prefix=198.51.100.0/24"
curl -i -H "Authorization: Bearer $NORTHWIND" localhost:8080/v1/nodes
curl -i -H "Authorization: Bearer $NORTHWIND" localhost:8080/metrics
```

With the operator token, `scrubctl` renders the same data as tables:

```sh
docker compose -f deploy/docker-compose.yml exec api \
  sh -c 'SCRUBLINE_API_TOKEN=$SCRUBLINE_API_TOKEN scrubctl -api http://127.0.0.1:8080 analytics 1h'
```

Attacks run on a cycle: a flood every four minutes for ninety seconds, and a
burst train every seven minutes for three. The burst train is the interesting
one — it keeps its average under any watermark on purpose, so watch
`pulse: true` on the event and the gap between `peak_pps` and the offered rate.

## Getting a live URL

**The compose stack binds to loopback and runs without TLS.** That is
deliberate: `-insecure` is how `scrub-api` is told to serve a non-loopback
address in the clear, and the demo needs it because the compose network is not
loopback. Publishing that on a routable address would put operator and tenant
credentials on the wire in plaintext. Do not change `BIND_ADDR` to `0.0.0.0`
and call it done.

Two ways to get a real URL, in order of how little can go wrong:

### A tunnel (easiest, and TLS is handled for you)

The service stays on loopback; the tunnel terminates TLS at the edge and
forwards over an authenticated connection.

```sh
cloudflared tunnel --url http://localhost:8080
```

That prints a `https://<random>.trycloudflare.com` URL, usable immediately
with no account. `ngrok http 8080` does the same thing. Pass the resulting URL
back in as `PUBLIC_URL` in `deploy/.env` if you want the seed banner to print
curl lines you can paste directly.

Quick tunnels are public to anyone with the link. The bearer credentials are
the only thing between a visitor and the control plane, so rotate the demo
tokens in `.env` to real ones first:

```sh
openssl rand -hex 32
```

### A host with a public IP

Put a terminating proxy in front and leave the control plane on loopback —
Caddy will get a certificate on its own:

```
scrubline.example.com {
    reverse_proxy 127.0.0.1:8080
}
```

Or skip the proxy and give `scrub-api` the certificate directly, which is the
supported production path: drop `-insecure`, mount the key pair, and pass
`-tls-cert` / `-tls-key`. The agents then need `-ca` pointing at the issuing
bundle, or a certificate from a CA they already trust. `make certs` generates
a throwaway CA and server certificate for trying this locally — not for
deployment.

### Before you expose anything

- Replace all three tokens in `deploy/.env`. The defaults are published in
  this repository.
- The control plane accepts writes: policy changes, deploys, tenant
  management. A leaked operator token is not just a data leak.
- `state.json` lives in a named volume, so `docker compose down -v` is what
  actually resets the demo. Plain `down` keeps the policy, the customers and
  their credential hashes.

## Resetting

```sh
docker compose -f deploy/docker-compose.yml down -v   # forget everything
docker compose -f deploy/docker-compose.yml up --build
```

Re-running the seeder against a stack that is already seeded is safe: the
policy and the customers are keyed by a derived id, so they are updated in
place rather than duplicated. It does reissue the tenant credentials, which
rotates them — the previous pair stops working.
