#!/usr/bin/env bash
# tier: 1
# requires: compose
# summary: signed tokens are actually verified, and identity changes what is allowed
#
# Two halves. First that verification is real -- a forged, expired, wrong-issuer
# or wrong-audience token is refused, which is only meaningful because the
# forged one carries correct claims and the right kid and is signed by a key
# the JWKS has never published. Second that a verified identity changes the
# decision: the same tool call succeeds for a human and is refused for an agent.
#
# The demo was prose pointing at a JWKS on localhost:8888 that nothing started,
# and its generator needed a pip package. Both are fixed: a busybox httpd in
# compose serves the document, and the generator uses openssl and stdlib only.
#
# Nothing here is a real key. The keypair is regenerated on every run.
set -euo pipefail

cd "$(dirname "$0")/../.."
here="demos/02-jwt-identity-tracking"
compose=(docker compose -f docker-compose.yaml -f "$here/compose.override.yaml")
proxy="http://127.0.0.1:9090/mcp"

cleanup() { "${compose[@]}" down -v >/dev/null 2>&1 || true; }
trap cleanup EXIT

pass() { echo "  ok:  $1"; }
fail() { echo "FAIL: $1" >&2; exit 1; }

bash "$here/generate-test-jwt.sh" >/dev/null
tok() { cat "$here/.generated/$1"; }

"${compose[@]}" up -d --wait >/dev/null

# Bare, with no Authorization header at all.
anon() {
  curl -sS -X POST "$proxy" -H 'Content-Type: application/json' \
    -d "{\"jsonrpc\":\"2.0\",\"id\":$1,\"method\":\"tools/call\",\"params\":{\"name\":\"$2\",\"arguments\":{}}}"
}

as() {
  local token="$1" id="$2" tool="$3"
  curl -sS -X POST "$proxy" \
    -H 'Content-Type: application/json' \
    -H "Authorization: Bearer $token" \
    -d "{\"jsonrpc\":\"2.0\",\"id\":$id,\"method\":\"tools/call\",\"params\":{\"name\":\"$tool\",\"arguments\":{}}}"
}

probe="$(as "$(tok human-token.txt)" 0 cost.check_usage)"
[[ "$probe" != *'"code":-32003'* ]] \
  || fail "this demo's registry is not mounted -- check the -f compose.override.yaml flag"

echo
echo "a valid token is verified, not merely present:"

ok="$(as "$(tok human-token.txt)" 1 cost.check_usage)"
[[ "$ok" == *'echo-server executed'* ]] || fail "a valid human token was refused: $ok"
pass "a token signed by the published key is accepted"

# The regression assertion. NULLFIELD_JWKS_URL used to select a verifier that
# took the raw token string as the subject without parsing it. If that ever
# comes back, the audit trail says `identity` is a 700-character JWT instead of
# alice@example.com.
logs="$("${compose[@]}" logs nullfield 2>/dev/null || true)"
[[ "$logs" == *'"identity":"alice@example.com"'* ]] \
  || fail "the subject should come from the sub claim; the audit trail says otherwise"
pass "the subject comes from the sub claim, not the raw token"

echo
echo "every way a token can be wrong is refused:"

# Correct claims, correct kid, signed by a key the JWKS never published. This
# is the one that proves a signature is actually being checked -- the others
# could all pass by reading claims and never verifying anything.
forged="$(as "$(tok forged-token.txt)" 2 cost.check_usage)"
[[ "$forged" == *'"code":-32001'* ]] || fail "a token signed by an unpublished key was accepted: $forged"
pass "a forged signature is refused, though its claims are perfect"

expired="$(as "$(tok expired-token.txt)" 3 cost.check_usage)"
[[ "$expired" == *'"code":-32001'* ]] || fail "an expired token was accepted: $expired"
pass "an expired token is refused"

wrong_iss="$(as "$(tok wrong-issuer-token.txt)" 4 cost.check_usage)"
[[ "$wrong_iss" == *'"code":-32001'* ]] || fail "a token from another issuer was accepted: $wrong_iss"
pass "a token from another issuer is refused"

wrong_aud="$(as "$(tok wrong-audience-token.txt)" 5 cost.check_usage)"
[[ "$wrong_aud" == *'"code":-32001'* ]] || fail "a token for another audience was accepted: $wrong_aud"
pass "a token minted for another audience is refused"

garbage="$(as 'not.a.jwt' 6 cost.check_usage)"
[[ "$garbage" == *'"code":-32001'* ]] || fail "a garbage token was accepted: $garbage"
pass "something that is not a token at all is refused"

missing="$(anon 7 cost.check_usage)"
[[ "$missing" == *'"code":-32001'* ]] || fail "a call with no token was accepted: $missing"
pass "a call with no token is refused"

echo
echo "identity decides what the call is allowed to do:"

# Same tool, same registry, same upstream. Only the token differs.
human_destructive="$(as "$(tok human-token.txt)" 10 tenant.delete_tenant)"
[[ "$human_destructive" == *'echo-server executed'* ]] \
  || fail "a human in mcp-writers should reach the destructive tool: $human_destructive"
pass "a human in mcp-writers may call the destructive tool"

agent_destructive="$(as "$(tok agent-token.txt)" 11 tenant.delete_tenant)"
[[ "$agent_destructive" == *'"code":-32000'* ]] \
  || fail "an agent should not reach the destructive tool: $agent_destructive"
pass "an agent calling the same tool is refused by policy"

agent_read="$(as "$(tok agent-token.txt)" 12 cost.check_usage)"
[[ "$agent_read" == *'echo-server executed'* ]] \
  || fail "an agent should still reach read-only tools: $agent_read"
pass "the agent keeps the read-only tools it is granted"

auto="$(as "$(tok autonomous-token.txt)" 13 cost.check_usage)"
[[ "$auto" == *'"code":-32000'* ]] \
  || fail "an autonomous caller should be denied everything: $auto"
pass "an autonomous caller is denied even the read-only tools"

echo
echo "the audit trail attributes the call:"

logs="$("${compose[@]}" logs nullfield 2>/dev/null || true)"
[[ "$logs" == *'"identity":"ops-agent-svc"'* ]] || fail "the agent's calls are not attributed to it"
pass "each decision names the verified principal"
[[ "$logs" == *'agent-read-only'* ]] || fail "the audit trail does not name the identity-conditional rule"
pass "and the identity-conditional rule that matched"

echo
echo "identity demo green: verified, attributed, and it changes the answer"
