#!/usr/bin/env bash
# tier: 1
# requires: compose
# summary: a held call waits for a human and resolves either way
#
# The walkthrough used to pass -v to `docker compose up`, which Compose v2
# reads as --verbose rather than a volume mount. This demo therefore ran
# against the default policy, which has no HOLD rule, and could not have shown
# what it claimed to. The mount guard below fails loudly if that regresses.
set -euo pipefail

cd "$(dirname "$0")/../.."

compose=(docker compose -f docker-compose.yaml -f demos/06-hold-action/compose.override.yaml)
proxy="http://127.0.0.1:9090/mcp"
admin="http://127.0.0.1:9091"

work="$(mktemp -d)"
cleanup() {
  "${compose[@]}" down -v >/dev/null 2>&1 || true
  rm -rf "$work"
}
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

# The override has to actually apply. Asserting on behaviour without checking
# this is how the demo passed for four months while proving nothing.
if ! "${compose[@]}" config | grep -q '06-hold-action/policy.yaml'; then
  fail "this demo's policy is not mounted; the stack would run the default"
fi

"${compose[@]}" up -d --wait >/dev/null

call() {
  curl -sS -X POST "$proxy" -H 'Content-Type: application/json' \
    -d "{\"jsonrpc\":\"2.0\",\"id\":$1,\"method\":\"tools/call\",\"params\":{\"name\":\"$2\",\"arguments\":{}}}"
}

# Returns the id of the first pending hold, or empty. The trailing `|| true`
# matters: under `set -o pipefail` a grep that matches nothing fails the whole
# pipeline, and polling for a hold that has not been created yet is the normal
# case here, not an error.
pending_hold() {
  curl -sS "$admin/admin/holds" 2>/dev/null \
    | grep -o '"id":"[^"]*"' \
    | head -1 \
    | cut -d'"' -f4 || true
}

wait_for_hold() {
  local id=""
  for _ in $(seq 1 20); do
    id="$(pending_hold)"
    [[ -n "$id" ]] && { printf '%s' "$id"; return 0; }
    sleep 0.5
  done
  return 1
}

echo
echo "hold decisions:"

expect "an allowed tool runs without waiting" "$(call 1 jira_get_issue)" 'echo-server executed'

# A held call blocks until someone resolves it, so it runs in the background
# while the test plays the human on the other end of the admin API.
call 2 pagerduty_resolve >"$work/approved.json" 2>&1 &
approved_pid=$!

hold_id="$(wait_for_hold)" || fail "the call was never held; /admin/holds stayed empty"
pass "a held tool waits instead of executing"

curl -sS -X POST "$admin/admin/holds/$hold_id/approve" \
  -H 'X-Approver: demo-operator' >/dev/null
wait "$approved_pid" || true
expect "approving releases it to the upstream" "$(cat "$work/approved.json")" 'echo-server executed'

call 3 pagerduty_resolve >"$work/denied.json" 2>&1 &
denied_pid=$!

hold_id="$(wait_for_hold)" || fail "the second call was never held"
curl -sS -X POST "$admin/admin/holds/$hold_id/deny" \
  -H 'X-Approver: demo-operator' >/dev/null
wait "$denied_pid" || true
expect "denying refuses it"            "$(cat "$work/denied.json")" '"code":-32000'
expect "the refusal names the denier"  "$(cat "$work/denied.json")" 'hold denied by demo-operator'

# Registered in examples/tools.yaml and absent from every ALLOW rule here, so
# the refusal comes from policy rather than from the registry.
expect "a registered but unauthorized tool is refused by policy" \
  "$(call 4 github_delete_repo)" '"code":-32000'

echo
echo "hold demo green: held calls wait, and resolve the way the human said"
