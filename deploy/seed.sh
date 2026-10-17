#!/bin/sh
# Seeds a demo stack: deploys a policy across whatever nodes have enrolled, and
# onboards two customers so the entitlement boundary is something you can
# actually try rather than read about.
#
# It is idempotent. Policies and tenants are keyed by a derived id, so running
# it again updates them in place rather than stacking duplicates. Credentials
# are reissued, which rotates them — the previous pair stops working.
set -eu

API="${API:-http://api:8080}"
TOKEN="${SCRUBLINE_API_TOKEN:?set SCRUBLINE_API_TOKEN}"
POLICY="${POLICY:-/etc/scrubline/policy.demo.json}"
OUT="${OUT:-/var/lib/scrubline/demo-credentials.env}"
auth="Authorization: Bearer $TOKEN"

echo "seed: waiting for the control plane at $API"
i=0
until curl -sf -o /dev/null "$API/health"; do
  i=$((i + 1))
  [ "$i" -lt 60 ] || { echo "seed: the control plane never came up" >&2; exit 1; }
  sleep 1
done

# Deploying needs at least one live node, and agents enroll a moment after the
# API starts listening. Wait for the fleet rather than losing the race.
echo "seed: waiting for a node to enroll"
i=0
until [ "$(curl -sf -H "$auth" "$API/v1/nodes" | jq 'length')" -gt 0 ] 2>/dev/null; do
  i=$((i + 1))
  [ "$i" -lt 60 ] || { echo "seed: no node enrolled" >&2; exit 1; }
  sleep 1
done

echo "seed: applying the policy"
pid=$(curl -sf -H "$auth" -H 'Content-Type: application/json' \
  --data-binary @"$POLICY" "$API/v1/policies" | jq -r '.id')
[ -n "$pid" ] && [ "$pid" != "null" ] || { echo "seed: could not read the policy id" >&2; exit 1; }

echo "seed: deploying $pid"
curl -sf -H "$auth" -X POST "$API/v1/policies/$pid/deploy" >/dev/null

# Two customers on one fabric, so the thing most worth testing — that one
# tenant's credential cannot see the other's traffic — is one curl away.
onboard() {
  tid=$(curl -sf -H "$auth" -H 'Content-Type: application/json' \
    --data "{\"name\":\"$1\",\"prefixes\":[\"$2\"]}" "$API/v1/tenants" | jq -r '.id')
  [ -n "$tid" ] && [ "$tid" != "null" ] || { echo "seed: onboarding $1 failed" >&2; exit 1; }
  curl -sf -H "$auth" -X POST "$API/v1/tenants/$tid/token" | jq -r '.token'
}

northwind=$(onboard "Northwind Games" "203.0.113.0/24")
contoso=$(onboard "Contoso Web" "198.51.100.0/24")

mkdir -p "$(dirname "$OUT")"
cat > "$OUT" <<CREDS
# Written by deploy/seed.sh. Demo credentials for a demo stack, not secrets.
SCRUBLINE_POLICY_ID=$pid
NORTHWIND_TOKEN=$northwind
CONTOSO_TOKEN=$contoso
CREDS

URL="${PUBLIC_URL:-http://127.0.0.1:8080}"
cat <<BANNER

  seeded: policy $pid deployed, two customers onboarded

  Northwind Games  203.0.113.0/24   the one that gets attacked
    $northwind
  Contoso Web      198.51.100.0/24  the quiet one, for contrast
    $contoso

  Try, as the customer:
    curl -H "Authorization: Bearer $northwind" $URL/v1/analytics/overview
    curl -H "Authorization: Bearer $northwind" $URL/v1/analytics/events
    curl -H "Authorization: Bearer $northwind" "$URL/v1/analytics/series?prefix=203.0.113.0/24&window=1h&step=1m"

  And the boundary. Northwind's credential against Contoso's prefix is a 403,
  as is the fleet and the exposition:
    curl -i -H "Authorization: Bearer $northwind" "$URL/v1/analytics/series?prefix=198.51.100.0/24"
    curl -i -H "Authorization: Bearer $northwind" $URL/v1/nodes

  Traffic builds over the first minute or so, and the first flood starts about
  20 seconds in. Until then the numbers are honestly zero.

BANNER
