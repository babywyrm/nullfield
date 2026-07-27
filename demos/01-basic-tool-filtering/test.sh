#!/usr/bin/env bash
# tier: 1
# requires: compose
# summary: the registry, circuit, and policy gates in the order they actually run
#
# This is the foundation demo, so it is about gate order as much as outcomes.
# handler.go runs registry, then circuit breaker, then policy, and the error
# code tells you which one answered:
#
#   -32003  registry   the tool is not described at all
#   -32002  circuit    too many calls in this session
#   -32000  policy     the tool is known and not granted
#
# It used to point at camazotz and a policy from another directory, so it could
# not be run without a service that is not in this repository. It runs against
# the compose stack now.
set -euo pipefail

cd "$(dirname "$0")/../.."
compose=(docker compose -f docker-compose.yaml -f demos/01-basic-tool-filtering/compose.override.yaml)
proxy="http://127.0.0.1:9090/mcp"

cleanup() { "${compose[@]}" down -v >/dev/null 2>&1 || true; }
trap cleanup EXIT

pass() { echo "  ok:  $1"; }
fail() { echo "FAIL: $1" >&2; exit 1; }

"${compose[@]}" up -d --wait >/dev/null

# Each call carries a session id so the circuit breaker can be exercised
# deliberately rather than tripping partway through the other assertions.
call() {
  local session="$1" id="$2" tool="$3"
  curl -sS -X POST "$proxy" \
    -H 'Content-Type: application/json' \
    -H "Mcp-Session-Id: $session" \
    -d "{\"jsonrpc\":\"2.0\",\"id\":$id,\"method\":\"tools/call\",\"params\":{\"name\":\"$tool\",\"arguments\":{}}}"
}

# If the override did not apply, the stack falls back to examples/ and every
# assertion below would be testing the wrong policy.
probe="$(call guard 0 ticket.create)"
[[ "$probe" != *'"code":-32003'* ]] \
  || fail "this demo's registry is not mounted -- check the -f compose.override.yaml flag"

echo
echo "the three gates, by the code they return:"

granted="$(call s1 1 cost.check_usage)"
[[ "$granted" == *'echo-server executed'* ]] || fail "tier-1 ALLOW did not reach upstream: $granted"
pass "a granted tool reaches the upstream server"

denied="$(call s1 2 secrets.read_config)"
[[ "$denied" == *'"code":-32000'* ]] || fail "expected a policy denial, got: $denied"
pass "a registered tool denied by policy returns -32000"

unknown="$(call s1 3 nothing.describes_me)"
[[ "$unknown" == *'"code":-32003'* ]] || fail "expected a registry refusal, got: $unknown"
pass "a tool the registry never described returns -32003"

echo
echo "the registry runs before policy:"

# The clearest way to show the ordering. This tool is explicitly DENY in policy
# *and* absent from the registry. If policy ran first it would come back
# -32000. It comes back -32003, so the registry answered and policy was never
# consulted -- which is why an unregistered tool cannot be granted by writing
# an ALLOW rule for it.
both="$(call s1 4 secrets.read_config_v2)"
[[ "$both" == *'"code":-32003'* ]] \
  || fail "expected the registry to answer first, got: $both"
pass "an unregistered tool is refused by the registry, not by policy"

echo
echo "the circuit breaker is per session:"

# A fresh session id gets a fresh budget, which is how a runaway agent is
# contained without taking down every other caller.
tripped=""
calls=0
for i in $(seq 1 12); do
  tripped="$(call s2 "$((10 + i))" cost.check_usage)"
  calls=$i
  [[ "$tripped" == *'"code":-32002'* ]] && break
done
[[ "$tripped" == *'"code":-32002'* ]] \
  || fail "the circuit breaker never opened after 12 calls in one session: $tripped"
pass "a session over its call limit returns -32002"

# The policy asks for 5 and compose.override.yaml sets the environment to 50,
# so tripping on the sixth call is the whole assertion: the policy won. Until
# recently the breaker was built from the environment before the policy was
# even loaded, and spec.circuitBreaker was parsed and dropped.
if (( calls != 6 )); then
  fail "the breaker tripped on call $calls, not 6 -- the policy's limit of 5 is not being honoured over the environment's 50"
fi
pass "the limit came from the policy, not from the environment's looser value"

# onTrip is the half that is still only a label. Nothing in the codebase reads
# it, so DENY and KILL_POD behave identically. Asserted here so the claim is
# checked rather than remembered.
if grep -rqs 'OnTrip' --include='*.go' pkg cmd; then
  fail "something now reads OnTrip -- it is no longer decorative, so update this demo"
fi
echo "  gap: onTrip is parsed and unread, so DENY and KILL_POD do the same thing"

other="$(call s3 30 cost.check_usage)"
[[ "$other" == *'echo-server executed'* ]] \
  || fail "a different session should be unaffected, got: $other"
pass "a different session is unaffected"

echo
echo "every decision is on the record:"

logs="$("${compose[@]}" logs nullfield 2>/dev/null || true)"
for gate in '"gate":"registry"' '"gate":"policy"' '"gate":"circuit"'; do
  [[ "$logs" == *"$gate"* ]] || fail "the audit trail is missing $gate"
done
pass "the audit trail names the gate that made each decision"

# The rule id is what makes a denial reviewable: it points at the line in the
# policy rather than leaving you to infer which rule matched.
[[ "$logs" == *'tier-3-high-risk'* ]] \
  || fail "the audit trail does not name the rule that denied secrets.read_config"
pass "and names the rule, not just the outcome"

echo
echo "basic filtering green: registry, then circuit, then policy"
