#!/usr/bin/env bash
# tier: 3
# requires: mesh
# summary: rules name API operations from a per-target map, and ambiguous paths are refused
#
# Operation maps on the mesh. A YAML map names each METHOD /path on a target;
# the waypoint asks nullfield; policy matches the name and its parameters.
#
# Proves, against real Envoy traffic:
#
#   1. A named read on an allowed owner is allowed, and the name audited.
#   2. Another named operation is allowed by the same rule.
#   3. A DENY on a name refuses that operation.
#   4. A parameter narrows: another owner falls to default deny.
#   5. A trailing slash cannot dodge the DENY: the path is refused as ambiguous.
#   6. A path the map does not list has no name and is default denied.
#   7. A Host naming the mapped target, sent to another Service, is refused.
#
# Shares demo 16's namespace and extension provider; run demo 16 once first
# (APPLY_MESH_CONFIG=true registers the provider).
set -euo pipefail

ns="nullfield-mesh-demo"
here="$(cd "$(dirname "$0")" && pwd)"
mesh="$here/../16-mesh-arbiter"

fail() { echo "FAIL: $*" >&2; exit 1; }
ok()   { echo "  ok: $*"; }

# ---------------------------------------------------------------- prerequisites

for c in kubectl python3; do command -v "$c" >/dev/null || fail "$c not found"; done
kubectl -n istio-system get cm istio -o jsonpath='{.data.mesh}' | grep -q "name: nullfield-demo-ext-authz" \
  || fail "extension provider not registered; run APPLY_MESH_CONFIG=true demos/16-mesh-arbiter/test.sh first"

if [[ "${BUILD_IMAGES:-false}" == "true" ]]; then
  echo "building images..."
  ( cd "$here/../.." \
    && docker build -q -f Dockerfile.extauthz -t ghcr.io/babywyrm/nullfield-extauthz:latest . >/dev/null \
    && docker build -q -f tests/echo-server/Dockerfile -t ghcr.io/babywyrm/nullfield-echo:latest . >/dev/null )
  if command -v k3s >/dev/null 2>&1; then
    for img in nullfield-extauthz nullfield-echo; do
      docker save "ghcr.io/babywyrm/$img:latest" | k3s ctr images import - >/dev/null
    done
  fi
fi

# ---------------------------------------------------------------------- deploy

kubectl apply -f "$mesh/mesh.yaml" >/dev/null
kubectl apply -f "$mesh/arbiter.yaml" >/dev/null
kubectl apply -f "$here/arbiter-policy.yaml" >/dev/null

# Strategic merge keys containers and volumes by name, so a re-run is a no-op.
kubectl -n "$ns" patch deploy/nullfield-extauthz --type strategic -p '
spec:
  template:
    spec:
      containers:
        - name: extauthz
          env:
            - {name: NULLFIELD_OPERATIONS_DIR, value: /etc/nullfield-operations}
            - {name: NULLFIELD_EXTAUTHZ_MODE, value: enforce}
          volumeMounts:
            - {name: operations, mountPath: /etc/nullfield-operations, readOnly: true}
      volumes:
        - name: operations
          configMap: {name: nullfield-extauthz-operations}
' >/dev/null
# Demo 16 checks POST only, which is all MCP uses. A REST API is every method.
kubectl -n "$ns" patch authorizationpolicy/nullfield-ext-authz --type merge -p '{"spec":{"rules":[{}]}}' >/dev/null

for app in nullfield-extauthz mcp-echo; do
  kubectl -n "$ns" rollout restart "deploy/$app" >/dev/null
  kubectl -n "$ns" rollout status "deploy/$app" --timeout=120s >/dev/null
  for i in $(seq 1 60); do
    [[ "$(kubectl -n "$ns" get pods -l "app=$app" --no-headers | wc -l)" -eq 1 ]] && break
    [[ "$i" == 60 ]] && fail "an old $app pod did not terminate in 60s"
    sleep 1
  done
done
kubectl -n "$ns" wait --for=condition=Ready pod/mesh-demo-client --timeout=120s >/dev/null

kubectl -n "$ns" logs deploy/nullfield-extauthz --tail=40 | grep -q '"loaded operation maps"' \
  || fail "the arbiter did not load the operation maps; rebuild with BUILD_IMAGES=true or check its log"
echo "deployed to $ns (enforce, operation map for mcp-echo)"

# ------------------------------------------------------------------- utilities

# call <method> <path> -> HTTP status. --path-as-is sends the path unaltered.
call() {
  kubectl -n "$ns" exec mesh-demo-client -- curl -s --path-as-is -o /dev/null -w '%{http_code}' \
    -X "$1" "http://mcp-echo$2" -H 'Content-Type: application/json' \
    -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}'
}

decision_field() {
  kubectl -n "$ns" logs deploy/nullfield-extauthz --tail=60 2>/dev/null \
    | grep arbiter.decision | tail -1 \
    | python3 -c "import sys,json;print(json.loads(json.loads(sys.stdin.read())['payload']).get('$1',''))"
}

expect_field() {
  local got
  got="$(decision_field "$1")"
  [[ "$got" == "$2" ]] || fail "$1 = '${got}', want '$2'"
  ok "$1 = ${2:-(absent)}"
}

expect_status() {
  [[ "$1" == "$2" ]] || fail "HTTP $1, want $2"
  ok "HTTP $2"
}

# ------------------------------------------------------------------- readiness

printf 'waiting for the waypoint to route through the arbiter'
for i in $(seq 1 30); do
  call GET /repos/acme/widgets >/dev/null 2>&1 || true
  [[ "$(decision_field action 2>/dev/null)" == "repos.get" ]] && break
  [[ "$i" == 30 ]] && { echo; fail "the arbiter saw no traffic in 60s"; }
  printf '.'; sleep 2
done
echo

# ------------------------------------------------------------------------ 1-6

echo
echo "1. a named read on acme is allowed, and the name audited"
expect_status "$(call GET /repos/acme/widgets)" 200
sleep 1
expect_field action repos.get
expect_field reason_class allowed

echo
echo "2. another named operation is allowed by the same rule"
expect_status "$(call POST /repos/acme/widgets/issues)" 200
sleep 1
expect_field action issues.create

echo
echo "3. a DENY on the name refuses the delete"
expect_status "$(call DELETE /repos/acme/widgets)" 403
expect_field action repos.delete
expect_field reason_class policy_denied

echo
echo "4. the owner parameter narrows: another owner is default denied"
expect_status "$(call GET /repos/evil/widgets)" 403
expect_field action repos.get
expect_field reason_class default_deny

echo
echo "5. a trailing slash cannot dodge the DENY"
expect_status "$(call DELETE /repos/acme/widgets/)" 403
expect_field gate operation
expect_field reason_class operation_ambiguous

echo
echo "6. a path the map does not list has no name"
expect_status "$(call GET /healthz)" 403
expect_field action ""
expect_field reason_class default_deny

echo
echo "7. a Host naming mcp-echo cannot carry its allow to another service"
# The waypoint routes on the address and ignores Host, so this reaches
# run-controller under mcp-echo's rules unless the arbiter checks.
expect_status "$(kubectl -n "$ns" exec mesh-demo-client -- curl -s -o /dev/null -w '%{http_code}' \
  -H 'Host: mcp-echo' http://run-controller/repos/acme/widgets)" 403
expect_field gate target
expect_field reason_class target_mismatch

echo
echo "operation maps green: rules on names, parameters narrowing, no spelling around a DENY"
