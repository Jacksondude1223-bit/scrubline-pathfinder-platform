#!/bin/sh
set -eu
API="${API:-http://127.0.0.1:8080}"
TOKEN="${SCRUBLINE_API_TOKEN:?set SCRUBLINE_API_TOKEN}"
auth="Authorization: Bearer $TOKEN"

echo "register three scrub nodes"
for spec in "scrub-a iad 100" "scrub-b fra 80" "scrub-c sin 40"; do
  set -- $spec
  curl -sf -H "$auth" -H 'Content-Type: application/json' -d "{\"name\":\"$1\",\"region\":\"$2\",\"capacity_gbps\":$3}" "$API/v1/nodes/register"
  echo
done

echo "apply policy"
pol=$(curl -sf -H "$auth" -H 'Content-Type: application/json' --data-binary @configs/policy.example.json "$API/v1/policies")
echo "$pol"
id=$(printf '%s' "$pol" | sed -n 's/.*"id":"\([^"]*\)".*/\1/p')

echo "deploy $id"
curl -sf -H "$auth" -X POST "$API/v1/policies/$id/deploy"
echo
echo "fabric"
curl -sf -H "$auth" "$API/v1/fabric"
echo
