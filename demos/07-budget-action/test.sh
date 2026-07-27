#!/usr/bin/env bash
# tier: 1
# requires: compose
# summary: the fourth call in an hour is refused and the unbudgeted tool is not
#
# With no JWKS configured the verifier returns a fixed dev identity, so every
# caller here shares one per-identity bucket. That is what makes a three-call
# budget observable from a shell without minting tokens.
#
# The walkthrough used to pass -v to `docker compose up`, which Compose v2
# reads as --verbose rather than a volume mount, so this ran against the
# default policy and never had a budget at all.
set -euo pipefail

cd "$(dirname "$0")/../.."

compose=(docker compose -f docker-compose.yaml -f demos/07-budget-action/compose.override.yaml)
proxy="http://127.0.0.1:9090/mcp"

cleanup() { "${compose[@]}" down -v >/dev/null 2>&1 || true; }
trap cleanup EXIT

pass() { echo "  ok: $1"; }
fail() { echo "FAIL: $1" >&2; exit 1; }

expect() {
  local label="$1" body="$2" want="$3"
  if [[ "$body" == *"$want"* ]]; then
    pass "$label"
  else
    fail "$label -- expected '$want' in: $body"
  fi
}

refute() {
  local label="$1" body="$2" unwanted="$3"
  if [[ "$body" == *"$unwanted"* ]]; then
    fail "$label -- did not expect '$unwanted' in: $body"
  else
    pass "$label"
  fi
}

if ! "${compose[@]}" config | grep -q '07-budget-action/policy.yaml'; then
  fail "this demo's policy is not mounted; the stack would run the default"
fi

"${compose[@]}" up -d --wait >/dev/null

call() {
  curl -sS -X POST "$proxy" -H 'Content-Type: application/json' \
    -d "{\"jsonrpc\":\"2.0\",\"id\":$1,\"method\":\"tools/call\",\"params\":{\"name\":\"$2\",\"arguments\":{}}}"
}

echo
echo "budget decisions:"

for i in 1 2 3; do
  expect "call $i of 3 is within budget" "$(call "$i" github_create_pr)" 'echo-server executed'
done

# -32004 is the rate-limit code. A budget refusal that came back as -32000
# would mean policy denied it for some other reason and the budget never ran.
over="$(call 4 github_create_pr)"
expect "the fourth call is refused"          "$over" '"code":-32004'
expect "the refusal names the budget"        "$over" 'budget exhausted'

# The control. A budget that tripped a global circuit rather than one rule's
# bucket would pass everything above and still be wrong.
expect "an unbudgeted tool still works afterwards" \
  "$(call 5 jira_get_issue)" 'echo-server executed'
refute "and it was not refused"  "$(call 6 jira_get_issue)" '"error"'

echo
echo "budget demo green: the bucket is per-rule, not per-process"
