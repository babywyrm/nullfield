#!/usr/bin/env bash
# tier: 1
# requires: compose
# summary: arguments are stripped and injected outbound, responses redacted inbound
#
# The echo server reflects the arguments it actually received, which is what
# makes request-side SCOPE observable at all: the assertions below read what
# reached the upstream, not what the caller sent.
#
# The walkthrough used to pass -v to `docker compose up`, which Compose v2
# reads as --verbose rather than a volume mount, so this ran against the
# default policy and no SCOPE rule was ever in play.
set -euo pipefail

cd "$(dirname "$0")/../.."

compose=(docker compose -f docker-compose.yaml -f demos/08-scope-action/compose.override.yaml)
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

if ! "${compose[@]}" config | grep -q '08-scope-action/policy.yaml'; then
  fail "this demo's policy is not mounted; the stack would run the default"
fi

"${compose[@]}" up -d --wait >/dev/null

# call ID TOOL ARGS_JSON
call() {
  curl -sS -X POST "$proxy" -H 'Content-Type: application/json' \
    -d "{\"jsonrpc\":\"2.0\",\"id\":$1,\"method\":\"tools/call\",\"params\":{\"name\":\"$2\",\"arguments\":$3}}"
}

echo
echo "scope decisions:"

scoped="$(call 1 pagerduty_resolve '{"incident_id":"INC-1","secret_key":"hunter2"}')"
# Assert the call succeeded before asserting what is absent from it. Without
# this, a 502 with an empty body satisfies every refutation below.
expect "the scoped call reaches the upstream at all"      "$scoped" 'echo-server executed'
refute "the stripped argument never reaches the upstream" "$scoped" 'hunter2'
refute "and neither does its name"                        "$scoped" 'secret_key'
expect "the injected argument does"                       "$scoped" 'read_only:true'
expect "the untouched argument survives"                  "$scoped" 'INC-1'

redacted="$(call 2 jira_get_issue '{"note":"the password is swordfish"}')"
expect "a matching response pattern is redacted" "$redacted" '[REDACTED]'

# The control. A SCOPE implementation that mangled every request would pass
# everything above and still be broken.
untouched="$(call 3 github_create_pr '{"repo":"acme/widgets","secret_key":"hunter2"}')"
expect "a pass-through tool keeps its arguments" "$untouched" 'acme/widgets'
expect "including ones another rule would strip" "$untouched" 'hunter2'

echo
echo "scope demo green: modification is scoped to the rules that ask for it"
