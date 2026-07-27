#!/usr/bin/env bash
# tier: 1
# requires: compose
# summary: session binding, token replay, and velocity, with what each one misses
#
# Three patterns that catch a caller misbehaving rather than a caller asking
# for something it was never granted. Policy answers "may you"; these answer
# "is this the same caller, is this the same token, and is this a normal rate".
#
# Each one has a blind spot and the demo asserts those too, because a detection
# you believe in more than it deserves is worse than none.
#
# It was prose with curl snippets against a JWKS nothing served, borrowing
# tokens from demo 02's directory. It mints its own now.
set -euo pipefail

cd "$(dirname "$0")/../.."
here="demos/03-anomaly-detection"
compose=(docker compose -f docker-compose.yaml -f "$here/compose.override.yaml")
proxy="http://127.0.0.1:9090/mcp"

cleanup() { "${compose[@]}" down -v >/dev/null 2>&1 || true; }
trap cleanup EXIT

pass() { echo "  ok:  $1"; }
fail() { echo "FAIL: $1" >&2; exit 1; }

bash "$here/generate-tokens.sh" >/dev/null
tok() { cat "$here/.generated/$1"; }

"${compose[@]}" up -d --wait >/dev/null

# call <token-file> <session-id> <request-id> [tool]
call() {
  local token session id tool
  token="$(tok "$1")"; session="$2"; id="$3"; tool="${4:-cost.check_usage}"
  curl -sS -X POST "$proxy" \
    -H 'Content-Type: application/json' \
    -H "Authorization: Bearer $token" \
    -H "Mcp-Session-Id: $session" \
    -d "{\"jsonrpc\":\"2.0\",\"id\":$id,\"method\":\"tools/call\",\"params\":{\"name\":\"$tool\",\"arguments\":{}}}"
}

probe="$(call alice-1.txt probe-session 0)"
[[ "$probe" != *'"code":-32003'* ]] \
  || fail "this demo's registry is not mounted -- check the -f compose.override.yaml flag"

echo
echo "a session belongs to whoever opened it:"

first="$(call alice-2.txt session-A 1)"
[[ "$first" == *'echo-server executed'* ]] || fail "alice could not open her own session: $first"
pass "the first caller on a session id is accepted"

# Mallory's token is perfectly valid -- correctly signed, unexpired, right
# issuer and audience. It is refused for being the wrong principal on someone
# else's session, which is a different failure from an invalid token.
stolen="$(call mallory-1.txt session-A 2)"
[[ "$stolen" == *'"code":-32001'* ]] \
  || fail "a second identity on the same session should be refused: $stolen"
pass "a valid token for a different subject is refused on that session"

own="$(call mallory-1.txt session-B 3)"
[[ "$own" != *'"code":-32001'* ]] \
  || fail "mallory should be able to open her own session: $own"
pass "and the same caller is fine on a session of its own"

echo
echo "a token is good once:"

replayed="$(call alice-2.txt session-A 4)"
[[ "$replayed" == *'"code":-32001'* ]] \
  || fail "alice's already-used token should be refused on replay: $replayed"
pass "reusing a token that has already been seen is refused"

fresh="$(call alice-3.txt session-A 5)"
[[ "$fresh" == *'echo-server executed'* ]] \
  || fail "a fresh token for the same subject should work: $fresh"
pass "a fresh token for the same subject still works"

# The consequence worth stating plainly: with detectReplay on, a client cannot
# reuse a token across calls. It needs a new one per request. That is the point
# of the feature and also the reason it is not on by default.
echo "  note: detectReplay makes tokens single-use, so callers must mint one per request"

echo
echo "what replay detection does not catch:"

# ReplayDetector.Check returns nil on an empty jti. A token with no jti is
# never checked, and nothing warns about it -- so an IdP that does not mint
# jti claims silently disables this whole feature.
first_nojti="$(call alice-no-jti.txt session-C 6)"
[[ "$first_nojti" == *'echo-server executed'* ]] || fail "a token with no jti should be accepted once: $first_nojti"
second_nojti="$(call alice-no-jti.txt session-C 7)"
if [[ "$second_nojti" == *'"code":-32001'* ]]; then
  fail "a jti-less token is now replay-checked -- update this demo, the gap has closed"
fi
echo "  gap: a token with no jti claim is never replay-checked, and nothing warns"

echo
echo "an unusual rate is caught even when every call is permitted:"

# Every one of these is a granted tool, a fresh token, and its own session, so
# nothing else in the chain has a reason to refuse it. The velocity tracker
# keys on the subject, which is why they all share one.
burst=""
sent=0
for i in $(seq 1 12); do
  burst="$(call "burst-$i.txt" "burst-session-$i" "$((20 + i))")"
  sent=$i
  [[ "$burst" == *'"code":-32004'* ]] && break
done
[[ "$burst" == *'"code":-32004'* ]] \
  || fail "12 calls from one subject should have exceeded the threshold of 8: $burst"
pass "a subject over the velocity threshold is refused with -32004"

# Nine, not six or twelve: the threshold is 8 and the tracker alerts on the
# call that exceeds it. Pinning the number means a silently changed threshold
# fails here rather than passing vaguely.
if (( sent != 9 )); then
  fail "expected the 9th call to trip a threshold of 8, got call $sent"
fi
pass "on the call after the threshold, not sooner or later"

echo
echo "the audit trail distinguishes the three:"

logs="$("${compose[@]}" logs nullfield 2>/dev/null || true)"
[[ "$logs" == *'"gate":"anomaly"'* ]] || fail "no anomaly gate events in the audit trail"
pass "velocity alerts are recorded against the anomaly gate"
[[ "$logs" == *'velocity_limit'* ]] || fail "the velocity reason class is missing"
pass "with a reason class of their own"
[[ "$logs" == *'integrity check failed'* ]] || fail "integrity failures are not logged"
pass "and integrity failures are logged separately"

echo
echo "anomaly demo green: three detections, and the blind spot in one of them"
