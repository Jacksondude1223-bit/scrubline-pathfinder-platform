#!/bin/sh
set -eu
API="${API:-http://127.0.0.1:8080}"
TOKEN="${SCRUBLINE_API_TOKEN:?set SCRUBLINE_API_TOKEN}"
ENROLL="${SCRUBLINE_ENROLL_TOKEN:?set SCRUBLINE_ENROLL_TOKEN}"
auth="Authorization: Bearer $TOKEN"
# Nodes enroll with the bootstrap credential; the control plane hands each one
# a credential scoped to itself.
enroll_auth="Authorization: Bearer $ENROLL"

# policy_id reads the top-level "id" out of the policy response. A plain greedy
# sed match runs past the object's own fields into the nested rule objects, each
# of which carries an "id" of its own, and picks up the last rule's id instead.
policy_id() {
  if command -v jq >/dev/null 2>&1; then
    printf '%s' "$1" | jq -r '.id'
  elif command -v python3 >/dev/null 2>&1; then
    printf '%s' "$1" | python3 -c 'import json,sys; print(json.load(sys.stdin)["id"])'
  else
    # Fallback: anchor on the start of the object so nested ids cannot match.
    printf '%s' "$1" | sed -n 's/^{"id":"\([^"]*\)".*/\1/p'
  fi
}

# field reads one top-level key out of a JSON object, with the same care
# policy_id takes about nested objects carrying keys of the same name.
field() {
  if command -v jq >/dev/null 2>&1; then
    printf '%s' "$2" | jq -r ".$1"
  elif command -v python3 >/dev/null 2>&1; then
    printf '%s' "$2" | python3 -c "import json,sys; print(json.load(sys.stdin)$3)"
  else
    printf ''
  fi
}

echo "register three scrub nodes"
first=""
for spec in "scrub-a iad 100" "scrub-b fra 80" "scrub-c sin 40"; do
  set -- $spec
  reg=$(curl -sf -H "$enroll_auth" -H 'Content-Type: application/json' -d "{\"name\":\"$1\",\"region\":\"$2\",\"capacity_gbps\":$3,\"capacity_pps\":2000000}" "$API/v1/nodes/register")
  echo "$reg"
  [ -n "$first" ] || first="$reg"
done

echo "apply policy"
pol=$(curl -sf -H "$auth" -H 'Content-Type: application/json' --data-binary @configs/policy.example.json "$API/v1/policies")
echo "$pol"
id=$(policy_id "$pol")
if [ -z "$id" ]; then
  echo "could not read the policy id out of the response" >&2
  exit 1
fi

echo "deploy $id"
curl -sf -H "$auth" -X POST "$API/v1/policies/$id/deploy"
echo
echo "fabric"
curl -sf -H "$auth" "$API/v1/fabric"
echo

# The customer-facing half. A node reports what its datapath did per protected
# prefix; the control plane turns that into the view the customer who owns the
# prefix is entitled to, and nothing else.
node_id=$(field 'node.id' "$first" '["node"]["id"]')
node_token=$(field 'token' "$first" '["token"]')
if [ -n "$node_id" ] && [ -n "$node_token" ]; then
  echo
  echo "report a flood at 203.0.113.0/24"
  curl -sf -H "Authorization: Bearer $node_token" -H 'Content-Type: application/json' \
    -d '{"stats":{"prefixes":[
          {"prefix":"203.0.113.0/24","flows":12000,"flows_dropped":11400,
           "offered":9400000,"dropped":9100000,
           "offered_pps":940000,"dropped_pps":910000,"peak_pps":1250000}],
         "rules":[{"rule_id":"tcam-udp-flood","stage":"asic","matches":11400,"drops":11400,"pps_dropped":9100000}]}}' \
    "$API/v1/nodes/$node_id/heartbeat"
  echo

  echo "onboard the customer who owns it"
  tenant=$(curl -sf -H "$auth" -H 'Content-Type: application/json' \
    -d '{"name":"Northwind Games","prefixes":["203.0.113.0/24"]}' "$API/v1/tenants")
  echo "$tenant"
  tid=$(field 'id' "$tenant" '["id"]')
  ttok=$(field 'token' "$(curl -sf -H "$auth" -X POST "$API/v1/tenants/$tid/token")" '["token"]')

  echo
  echo "what that customer sees, with their own credential"
  curl -sf -H "Authorization: Bearer $ttok" "$API/v1/analytics/overview?window=1h"
  echo
  echo "and what they do not: the fleet"
  curl -s -o /dev/null -w 'GET /v1/nodes -> %{http_code}\n' -H "Authorization: Bearer $ttok" "$API/v1/nodes"
fi
