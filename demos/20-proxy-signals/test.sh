#!/usr/bin/env bash
# tier: 1
# requires: compose
# summary: a session that trips the proxy's breaker is signalled once, by signed webhook
#
# Signals from proxy mode. Each session gets two calls; the third trips that
# session's breaker. The proxy refuses it and posts one signed signal.
#
# Proves:
#
#   1. A session within its limit is allowed.
#   2. Past it, the session is refused at the circuit gate (-32002).
#   3. Another session is unaffected.
#   4. The trip is one circuit.tripped; later refusals are tool.denied.
#   5. It is posted once to the webhook, which verifies the signature.
#   6. The receiver rejects an unsigned post.
set -euo pipefail

cd "$(dirname "$0")/../.."
compose=(docker compose -f docker-compose.yaml -f demos/20-proxy-signals/compose.override.yaml)
proxy="http://127.0.0.1:9090/mcp"

pass() { echo "  ok:  $1"; }
fail() { echo "FAIL: $1" >&2; exit 1; }

# A fresh signing secret per run, in a temp dir. Readable by the containers'
# non-root users through the bind mount; the directory itself is private.
work="$(mktemp -d)"
openssl rand -hex 32 >"$work/secret"
chmod 0644 "$work/secret"
export SIGNAL_SECRET_FILE="$work/secret"

cleanup() { "${compose[@]}" down -v >/dev/null 2>&1 || true; rm -rf "$work"; }
trap cleanup EXIT

"${compose[@]}" up -d --wait >/dev/null 2>&1 || { "${compose[@]}" logs >&2; fail "the stack did not start"; }
"${compose[@]}" logs nullfield | grep -q '"signalling by webhook"' \
  || fail "the proxy is not signalling -- rebuild the image (docker compose build)"

call() {
  curl -sS -X POST "$proxy" -H 'Content-Type: application/json' -H "Mcp-Session-Id: $1" \
    -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo","arguments":{"message":"hi"}}}'
}

s1="s1-$(date +%s)"
s2="s2-$(date +%s)"

echo
echo "1. a session within its limit is allowed"
for i in 1 2; do
  out="$(call "$s1")"
  [[ "$out" == *'"result"'* ]] || fail "call $i refused: $out"
done
pass "two calls allowed"

echo
echo "2. past it, the session is refused at the circuit gate"
for i in 3 4 5; do
  out="$(call "$s1")"
  [[ "$out" == *'"code":-32002'* ]] || fail "call $i: want -32002, got: $out"
done
pass "calls 3-5 refused with -32002"

echo
echo "3. another session is unaffected"
out="$(call "$s2")"
[[ "$out" == *'"result"'* ]] || fail "$s2 refused: $out"
pass "$s2 allowed"

echo
echo "4. the trip is one circuit.tripped; later refusals are tool.denied"
sleep 2
logs="$("${compose[@]}" logs nullfield)"
trips="$(grep '"event_type":"circuit.tripped"' <<<"$logs" | grep -c "$s1" || true)"
later="$(grep '"event_type":"tool.denied"' <<<"$logs" | grep '"gate":"circuit"' | grep -c "$s1" || true)"
[[ "$trips" == 1 && "$later" == 2 ]] || fail "$trips circuit.tripped and $later later refusals for $s1, want 1 and 2"
pass "one circuit.tripped, two tool.denied at the circuit gate"

echo
echo "5. posted once to the webhook, signature verified"
verified="$("${compose[@]}" logs signal-receiver | grep '"verified"' | grep -c "$s1" || true)"
[[ "$verified" == 1 ]] || fail "$verified verified posts for $s1, want 1"
pass "receiver verified one circuit.tripped for $s1"

echo
echo "6. the receiver rejects an unsigned post"
code="$("${compose[@]}" exec -T signal-receiver python -c '
import urllib.request, urllib.error
req = urllib.request.Request("http://127.0.0.1:8080/hook", data=b"{\"type\":\"circuit.tripped\",\"session_id\":\"forged\"}")
try:
    print(urllib.request.urlopen(req).status)
except urllib.error.HTTPError as e:
    print(e.code)
')"
[[ "$code" == 401 ]] || fail "unsigned post: HTTP $code, want 401"
pass "unsigned post refused with 401"

echo
echo "proxy signals green: one trip per session, one signed post, nothing forgeable"
