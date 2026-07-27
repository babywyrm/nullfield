#!/usr/bin/env bash
# tier: 3
# requires: mesh
# summary: waypoint ext_authz with attested spiffe identity, observe then enforce
#
# nullfield as a mesh-native arbiter.
#
# Proves four things that only show up against real mesh traffic, and that no
# unit test can establish:
#
#   1. The caller is identified cryptographically, not by a claim it asserts.
#   2. MCP is recognised by parsing the body, not by matching a URL.
#   3. Observe mode records what enforcement would have done without doing it.
#   4. A body too large to read is refused rather than authorized on the part
#      that fit.
#
# Namespace-scoped resources are applied automatically. Registering the
# extension provider edits mesh-wide config and restarts istiod, so it is opt-in
# via APPLY_MESH_CONFIG=true rather than something a test script does to a
# cluster on your behalf.
set -euo pipefail

ns="${1:-nullfield-mesh-demo}"
apply_mesh="${APPLY_MESH_CONFIG:-false}"
here="$(cd "$(dirname "$0")" && pwd)"

fail() { echo "FAIL: $*" >&2; exit 1; }
ok()   { echo "  ok: $*"; }

# ---------------------------------------------------------------- prerequisites

command -v kubectl >/dev/null || fail "kubectl not found"
kubectl -n istio-system get deploy istiod >/dev/null 2>&1 || fail "istiod not found; this demo needs Istio ambient"

if [[ "$apply_mesh" == "true" ]]; then
  bash "$here/register-provider.sh" "$ns"
elif ! kubectl -n istio-system get cm istio -o jsonpath='{.data.mesh}' | grep -q "name: nullfield-demo-ext-authz"; then
  cat >&2 <<EOF
FAIL: extension provider nullfield-demo-ext-authz is not registered.

  Re-run with APPLY_MESH_CONFIG=true to register it (backs up the istio
  ConfigMap and restarts istiod), or add it by hand under data.mesh:

    extensionProviders:
    - name: nullfield-demo-ext-authz
      envoyExtAuthzGrpc:
        service: nullfield-extauthz.${ns}.svc.cluster.local
        port: 9191
        includeRequestBodyInCheck:
          maxRequestBytes: 8192
          allowPartialMessage: true
EOF
  exit 1
fi

# ---------------------------------------------------------------------- deploy

kubectl apply -f "$here/mesh.yaml" >/dev/null
kubectl apply -f "$here/arbiter.yaml" >/dev/null

kubectl -n "$ns" rollout status deploy/mcp-echo --timeout=120s >/dev/null
kubectl -n "$ns" rollout status deploy/nullfield-extauthz --timeout=120s >/dev/null
kubectl -n "$ns" wait --for=condition=Ready pod/mesh-demo-client --timeout=120s >/dev/null
kubectl -n "$ns" wait --for=condition=Programmed gateway/mesh-demo-waypoint --timeout=180s >/dev/null
echo "deployed to $ns"

# Envoy needs a moment to pick up the new filter chain after the waypoint is
# programmed; without this the first calls race the config push.
sleep 10

# ------------------------------------------------------------------- utilities

call() {
  # call <tool> [padding-bytes] -> prints the HTTP status
  local tool="$1" pad_bytes="${2:-0}" pad=""
  if [[ "$pad_bytes" -gt 0 ]]; then
    pad="$(head -c "$pad_bytes" /dev/zero | tr '\0' 'x')"
  fi
  kubectl -n "$ns" exec mesh-demo-client -- curl -s -o /dev/null -w '%{http_code}' \
    -X POST http://mcp-echo/mcp -H 'Content-Type: application/json' \
    -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"${tool}\",\"arguments\":{\"pad\":\"${pad}\"}}}"
}

# The newest arbiter decision, as JSON. The audit event is the product here: a
# demo that only checked status codes would pass just as happily with the
# decision service switched off.
#
# An absent decision is the most likely failure and the least self-explanatory,
# so it gets a real message. Piping straight into a JSON parser reports it as a
# decoder traceback, which says nothing about the actual problem.
latest_decision() {
  local line
  line="$(kubectl -n "$ns" logs deploy/nullfield-extauthz --tail=60 2>/dev/null | grep arbiter.decision | tail -1)"
  if [[ -z "$line" ]]; then
    echo "FAIL: the decision service recorded no decision for that request." >&2
    echo "      It is running, so the check is not reaching it. Usually one of:" >&2
    echo "        - the waypoint has not picked up the AuthorizationPolicy yet" >&2
    echo "        - the extension provider name does not match the policy's provider" >&2
    echo "        - istiod cannot parse extensionProviders; check its log for" >&2
    echo "          'available providers are []', which turns every CUSTOM policy" >&2
    echo "          into a deny without saying so" >&2
    exit 1
  fi
  python3 -c "import sys,json;print(json.loads(json.loads(sys.stdin.read())['payload']))" <<<"$line"
}

decision_field() {
  kubectl -n "$ns" logs deploy/nullfield-extauthz --tail=60 2>/dev/null \
    | grep arbiter.decision | tail -1 \
    | python3 -c "import sys,json;print(json.loads(json.loads(sys.stdin.read())['payload']).get('$1',''))"
}

expect_field() {
  local field="$1" want="$2" got
  got="$(decision_field "$field")"
  [[ "$got" == "$want" ]] || fail "$field = '${got}', want '${want}'"
  ok "$field = $want"
}

# ------------------------------------------------------------ 1. identity + MCP

echo
echo "1. the caller is identified, and MCP is recognised by parse"
status="$(call dangerous_tool)"
sleep 2
latest_decision >/dev/null

principal="$(decision_field workload_principal)"
[[ "$principal" == spiffe://*/ns/${ns}/sa/mesh-demo-client ]] \
  || fail "workload_principal = '${principal}', want the client's SPIFFE id"
ok "workload_principal = $principal"
expect_field attester  "mesh-header"
expect_field assurance "ATTESTED"
expect_field transport "A"
expect_field tool_name "dangerous_tool"

# ------------------------------------------------------- 2. observe does not block

echo
echo "2. observe mode records the counterfactual without acting on it"
expect_field counterfactual "DENY"
[[ "$status" == "200" ]] \
  || fail "a denied call returned HTTP ${status} in observe mode; observe must not affect traffic"
ok "the call policy would have denied still returned HTTP 200"

# ------------------------------------------------------------- 3. truncated body

echo
echo "3. a body too large to read is refused, and still attributed"
status="$(call dangerous_tool 20000)"
sleep 2
expect_field reason_class "body_truncated"
expect_field attester     "mesh-header"
expect_field counterfactual "DENY"
[[ "$status" == "200" ]] \
  || fail "truncated request returned HTTP ${status} in observe mode"
ok "refused to decide, recorded the caller, and left the response alone"

# ------------------------------------------------------------------- 4. enforce

echo
echo "4. the same deployment enforces when told to"
kubectl -n "$ns" set env deploy/nullfield-extauthz NULLFIELD_EXTAUTHZ_MODE=enforce >/dev/null
kubectl -n "$ns" rollout status deploy/nullfield-extauthz --timeout=120s >/dev/null
sleep 5

status="$(call dangerous_tool)"
[[ "$status" == "403" ]] || fail "denied tool returned HTTP ${status} under enforce, want 403"
ok "the denied tool is now blocked (HTTP 403)"

status="$(call echo)"
[[ "$status" == "200" ]] || fail "allowed tool returned HTTP ${status} under enforce, want 200"
ok "the allowed tool still passes (HTTP 200)"

echo
echo "mesh arbiter green: attested identity, MCP by parse, observe-safe, enforce-capable"
