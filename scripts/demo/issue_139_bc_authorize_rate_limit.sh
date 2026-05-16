#!/usr/bin/env bash
# Demo script for issue #139 — bc-authorize rate limiting.
#
# Walks through:
#   1. Register a public OAuth client.
#   2. Fire 12 bc-authorize requests in quick succession.
#   3. Show the first 10 return 200 (within the 10/min per-client cap)
#      and the remaining 2 return 429 + slow_down + Retry-After.
#
# Run zeroid first:    make setup-keys && docker compose up -d
# Then run this:       bash scripts/demo/issue_139_bc_authorize_rate_limit.sh

set -euo pipefail

BASE_URL="${BASE_URL:-http://localhost:8899}"
ACCOUNT_ID="${ACCOUNT_ID:-acct-demo}"
PROJECT_ID="${PROJECT_ID:-proj-demo}"
CLIENT_ID="${CLIENT_ID:-demo-ciba-$(date +%s)}"
LOGIN_HINT="${LOGIN_HINT:-victim@example.com}"

bold()  { printf '\033[1m%s\033[0m\n' "$*"; }
green() { printf '\033[32m%s\033[0m' "$*"; }
red()   { printf '\033[31m%s\033[0m' "$*"; }
gray()  { printf '\033[90m%s\033[0m' "$*"; }

bold "─── 1. Register a public OAuth client ─────────────────────────────────"
echo "POST $BASE_URL/api/v1/oauth/clients"
echo "  X-Account-ID: $ACCOUNT_ID"
echo "  X-Project-ID: $PROJECT_ID"
echo "  client_id:    $CLIENT_ID"
echo
curl -sS -X POST "$BASE_URL/api/v1/oauth/clients" \
  -H "Content-Type: application/json" \
  -H "X-Account-ID: $ACCOUNT_ID" \
  -H "X-Project-ID: $PROJECT_ID" \
  -d "{
    \"client_id\": \"$CLIENT_ID\",
    \"name\": \"issue-139-demo\",
    \"grant_types\": [\"urn:openid:params:grant-type:ciba\", \"client_credentials\"],
    \"backchannel_token_delivery_mode\": \"poll\"
  }" | head -c 400
echo
echo

bold "─── 2. Fire 12 bc-authorize requests as the same client ───────────────"
echo "Per-client cap is 10/min by default → first 10 should pass, last 2 should be rate-limited."
echo "Per-user (login_hint) cap is 5/min, but the per-client check fires first."
echo "(Setting login_hint to a unique value per request to isolate the per-client dimension.)"
echo

successes=0
ratelimits=0

for i in $(seq 1 12); do
  hint="iter-$i-$LOGIN_HINT"
  # -w writes status + Retry-After header to stderr so the loop output stays
  # readable. -D - dumps response headers; we grep just the ones we want.
  response=$(curl -sS -i -X POST "$BASE_URL/oauth2/bc-authorize" \
    -H "Content-Type: application/json" \
    -d "{
      \"client_id\":  \"$CLIENT_ID\",
      \"account_id\": \"$ACCOUNT_ID\",
      \"project_id\": \"$PROJECT_ID\",
      \"login_hint\": \"$hint\",
      \"scope\":      \"openid\"
    }")

  status=$(printf '%s' "$response" | awk 'NR==1 {print $2}')
  retry=$(printf '%s' "$response" | awk 'tolower($1)=="retry-after:" {print $2}' | tr -d '\r')
  body=$(printf '%s' "$response" | awk 'BEGIN{b=0} /^\r?$/ {b=1; next} b')

  case "$status" in
    200)
      successes=$((successes+1))
      printf '  request %2d → %s  ' "$i" "$(green "200 OK")"
      auth_id=$(printf '%s' "$body" | python3 -c 'import json,sys;print(json.load(sys.stdin).get("auth_req_id",""))' 2>/dev/null || true)
      printf 'auth_req_id=%s\n' "$(gray "${auth_id:0:24}…")"
      ;;
    429)
      ratelimits=$((ratelimits+1))
      err=$(printf '%s' "$body" | python3 -c 'import json,sys;print(json.load(sys.stdin).get("error",""))' 2>/dev/null || true)
      printf '  request %2d → %s  error=%s  retry-after=%ss\n' \
        "$i" "$(red "429 Too Many Requests")" "$err" "$retry"
      ;;
    *)
      printf '  request %2d → unexpected status %s\n' "$i" "$status"
      printf '%s\n' "$body" | head -c 300
      ;;
  esac
done

echo
bold "─── 3. Result ─────────────────────────────────────────────────────────"
echo "  successes : $successes  (expected: 10)"
echo "  rate-limits: $ratelimits  (expected: 2)"
echo
if [[ "$successes" -eq 10 && "$ratelimits" -eq 2 ]]; then
  printf '%s issue #139 rate limit is enforced as documented.\n' "$(green '✓')"
  exit 0
else
  printf '%s unexpected — check zeroid logs for the bc_authorize_rate_limited WARN event.\n' "$(red '✗')"
  exit 1
fi
