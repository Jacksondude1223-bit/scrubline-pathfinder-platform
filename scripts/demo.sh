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

echo "register three scrub nodes"
for spec in "scrub-a iad 100" "scrub-b fra 80" "scrub-c sin 40"; do
  set -- $spec
  curl -sf -H "$enroll_auth" -H 'Content-Type: application/json' -d "{\"name\":\"$1\",\"region\":\"$2\",\"capacity_gbps\":$3}" "$API/v1/nodes/register"
  echo
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
