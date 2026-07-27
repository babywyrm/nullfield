#!/usr/bin/env bash
# tier: 1
# requires: compose
# summary: sensitive content in a tool response is redacted or blocked, per rule
#
# The gates in demo 01 all decide before the call goes upstream. This one
# decides after: the tool ran, it returned something it should not have, and
# nullfield is the last thing between that and the model's context window.
#
# The echo server reflects its arguments, so sending a fake credential as an
# argument is enough to get one back in a response without a purpose-built
# upstream. Nothing here is a real secret.
#
# It was prose with no script before, describing patterns and severities that
# nothing checked.
set -euo pipefail

cd "$(dirname "$0")/../.."
compose=(docker compose -f docker-compose.yaml -f demos/12-response-inspection/compose.override.yaml)
proxy="http://127.0.0.1:9090/mcp"

cleanup() { "${compose[@]}" down -v >/dev/null 2>&1 || true; }
trap cleanup EXIT

pass() { echo "  ok:  $1"; }
fail() { echo "FAIL: $1" >&2; exit 1; }

"${compose[@]}" up -d --wait >/dev/null

# $3 becomes an argument value, which the echo server reflects back into the
# response text. That reflected text is what the inspector sees.
call() {
  local id="$1" tool="$2" leak="$3"
  curl -sS -X POST "$proxy" -H 'Content-Type: application/json' \
    -d "{\"jsonrpc\":\"2.0\",\"id\":$id,\"method\":\"tools/call\",\"params\":{\"name\":\"$tool\",\"arguments\":{\"body\":\"$leak\"}}}"
}

probe="$(call 0 report.fetch harmless)"
[[ "$probe" != *'"code":-32003'* ]] \
  || fail "this demo's registry is not mounted -- check the -f compose.override.yaml flag"

echo
echo "sensitive content is caught on the way back:"

# password:<8+ chars> is the credential_assignment rule. Fake, obviously.
cred="$(call 1 report.fetch 'password:hunter2xyz123')"
[[ "$cred" != *'hunter2xyz123'* ]] || fail "the credential came back verbatim: $cred"
[[ "$cred" == *'REDACTED'* ]] || fail "expected a redaction marker, got: $cred"
pass "a credential in the response is redacted"

# Redaction is surgical, not a blanket refusal: the caller still gets a usable
# answer, minus the part that should not have been there.
[[ "$cred" == *'echo-server executed'* ]] \
  || fail "redaction destroyed the rest of the response: $cred"
pass "the rest of the response survives"

ssn="$(call 2 report.fetch '123-45-6789')"
[[ "$ssn" != *'123-45-6789'* ]] || fail "the SSN came back verbatim: $ssn"
pass "a different category, PII, is caught by the same rule"

path="$(call 3 report.fetch '/var/run/secrets/kubernetes/token')"
[[ "$path" != *'/var/run/secrets/kubernetes'* ]] || fail "the service account path came back verbatim: $path"
pass "and so is an internal path"

echo
echo "the rule decides what happens next:"

# Same finding, different rule, different outcome. DENY discards the whole
# response rather than trying to clean it, which is the right call when a
# partial redaction cannot be trusted.
blocked="$(call 4 export.dump 'password:hunter2xyz123')"
[[ "$blocked" == *'"code":-32007'* ]] || fail "expected the response to be blocked, got: $blocked"
pass "onFinding: DENY blocks the whole response with -32007"

[[ "$blocked" != *'hunter2xyz123'* ]] || fail "the blocked response still leaked its contents: $blocked"
pass "and the caller gets none of it"

echo
echo "inspection is opt-in per rule:"

# The control. Identical content through a rule with no inspection block comes
# back untouched, which is what makes the assertions above mean something.
control="$(call 5 debug.echo 'password:hunter2xyz123')"
[[ "$control" == *'hunter2xyz123'* ]] \
  || fail "a rule without an inspection block should not redact: $control"
pass "a rule with no inspection block passes the same content through"

echo
echo "findings are on the record:"

logs="$("${compose[@]}" logs nullfield 2>/dev/null || true)"
[[ "$logs" == *'"gate":"inspection"'* ]] || fail "no inspection events in the audit trail"
pass "the audit trail records the inspection gate"

# The finding is summarised as a category and a count of asterisks, never the
# matched text, so the audit trail does not become the leak it just prevented.
findings="$(printf '%s\n' "$logs" | grep 'inspection.finding' || true)"
[[ -n "$findings" ]] || fail "no inspection.finding events in the audit trail"
[[ "$findings" == *'credential'* ]] || fail "the finding does not name what was found"
pass "and names the category that matched"

[[ "$findings" != *'hunter2xyz123'* ]] \
  || fail "the finding event copied the secret into the log, which makes the log the leak"
pass "without copying the secret into the finding"

# Worth being straight about: the secret does appear elsewhere in this log, in
# the tool.allowed event's args. That is NULLFIELD_AUDIT_LOG_LEVEL=FULL doing
# what it says, and it is visible here only because this demo smuggles the
# secret in as a request argument to get one into a response. A real leak comes
# from the upstream and never touches the request. It is still a fair warning
# about running FULL against tools whose arguments carry secrets.
[[ "$logs" == *'"event_type":"tool.allowed"'* ]] || fail "expected tool.allowed events at FULL audit level"
echo "  note: at AUDIT_LOG_LEVEL=FULL the request arguments are logged too, secrets included"

echo
echo "what is not configurable yet:"

# spec.rules[].inspection carries enabled and onFinding, and cmd/nullfield
# builds the inspector with inspection.DefaultConfig() -- all four categories,
# always. There is no way to enable credential detection and leave email
# addresses alone, which matters because the email rule fires on any address.
if ! grep -q 'inspection.DefaultConfig()' cmd/nullfield/main.go; then
  fail "the inspector is no longer built from DefaultConfig -- categories may be selectable now, so update this demo"
fi
echo "  gap: all four detection categories are always on; a rule cannot select between them"

echo
echo "inspection demo green: caught on the way back, and the rule decides what happens"
