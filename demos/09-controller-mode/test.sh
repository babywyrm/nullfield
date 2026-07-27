#!/usr/bin/env bash
# tier: 1
# requires: compose
# summary: the controller sees inventory and decisions, but not yet holds or budgets
#
# Controller mode delivers less than its name suggests, and this demo says so
# out loud. The sidecar registers its inventory and streams every decision to
# the controller, both of which work. Centralized holds and shared budgets do
# not: pkg/hold/remote.go and pkg/budget/remote.go exist and wrap the client
# correctly, but nothing in cmd/ ever constructs them, and HandlerOpts.Holds is
# a concrete *hold.Manager rather than an interface, so the remote one could
# not be substituted even if something tried.
#
# The two gap: lines below assert the absence. They are written to FAIL when
# the feature lands, which forces this demo and its README to be updated rather
# than left overstating what nullfield does.
#
# The demo also used to mount examples/tools.yaml, which registers a GitHub and
# PagerDuty vocabulary and none of the tools this policy names, so every call
# was refused by the registry before policy was consulted. It has its own
# registry now.
set -euo pipefail

# This demo has its own three-service stack, so it runs from its own directory
# rather than the repository root.
cd "$(dirname "$0")"

compose=(docker compose -f docker-compose.yaml)
proxy="http://127.0.0.1:9090/mcp"
controller="http://127.0.0.1:9093"

work="$(mktemp -d)"
cleanup() {
  "${compose[@]}" down -v >/dev/null 2>&1 || true
  rm -rf "$work"
}
trap cleanup EXIT

pass() { echo "  ok:  $1"; }
gap()  { echo "  gap: $1"; }
fail() { echo "FAIL: $1" >&2; exit 1; }

expect() {
  local label="$1" body="$2" want="$3"
  if [[ "$body" == *"$want"* ]]; then
    pass "$label"
  else
    fail "$label -- expected '$want' in: $body"
  fi
}

"${compose[@]}" up -d --wait >/dev/null

call() {
  curl -sS -X POST "$proxy" -H 'Content-Type: application/json' \
    -d "{\"jsonrpc\":\"2.0\",\"id\":$1,\"method\":\"tools/call\",\"params\":{\"name\":\"$2\",\"arguments\":{}}}"
}

# The trailing `|| true` matters: under `set -o pipefail` a grep that matches
# nothing fails the whole pipeline, and an empty result is a normal answer here
# rather than an error.
admin_get() { curl -sS "$controller$1" 2>/dev/null || true; }

echo
echo "what the controller does today:"

expect "the sidecar registers its inventory" "$(admin_get /admin/targets)" '"toolCount":8'
expect "including its rule count"            "$(admin_get /admin/targets)" '"ruleCount":4'

expect "a read-only tool is allowed" "$(call 1 cost.check_usage)" 'echo-server executed'

# Registered on purpose and absent from every ALLOW rule, so this refusal comes
# from policy. Without it, every "no" in the demo would come from the registry.
expect "a registered but unauthorized tool is refused by policy" \
  "$(call 2 tenant.delete_tenant)" '"code":-32000'

expect "an unregistered tool is refused by the registry" \
  "$(call 3 not_in_the_registry)" '"code":-32003'

# Events are streamed, so allow a moment rather than racing the first read.
events=""
for _ in $(seq 1 20); do
  events="$(admin_get /admin/events)"
  [[ "$events" == *"tenant.delete_tenant"* ]] && break
  sleep 0.5
done
expect "decisions reach the controller's event stream" "$events" 'tenant.delete_tenant'
expect "with the gate that made them"                  "$events" '"gate":"policy"'

echo
echo "what it does not do yet:"

# A HOLD rule in controller mode. holdManager is left nil whenever a controller
# client exists, so the hold branch is skipped and the call is denied outright.
held="$(call 4 delegation.invoke_agent)"
if [[ "$held" != *'"code":-32000'* ]]; then
  fail "a HOLD rule no longer denies outright -- controller holds may now be wired, so update this demo and its README"
fi

holds="$(admin_get /admin/holds)"
if [[ "$holds" != "[]"* ]]; then
  fail "a hold appeared on the controller -- centralized holds now work, so turn this gap into an assertion"
fi
gap "a HOLD rule denies immediately instead of parking on the controller"

# Budgets are tracked by a local budget.Tracker even in controller mode, so the
# controller's own budget view stays empty no matter how many calls are made.
for i in 5 6 7; do
  call "$i" llm.generate_summary >/dev/null
done

budgets="$(admin_get /admin/budgets)"
if [[ "$budgets" != "[]"* ]]; then
  fail "the controller is tracking budgets -- shared budgets now work, so turn this gap into an assertion"
fi
gap "budgets are counted locally, so the controller's view stays empty"

echo
echo "controller demo green: inventory and events are central, holds and budgets are not"
