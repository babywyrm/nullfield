#!/usr/bin/env bash
# tier: 2
# requires: kubernetes
# summary: editing a nullfieldpolicy crd changes a running sidecar's mind
#
# The payoff is step 4: grant a tool in the CRD, re-apply, and watch a sidecar
# that was denying it start allowing it, with no restart and nobody touching a
# ConfigMap by hand. Nothing in the repository proved that chain end to end
# before this.
#
# It needs the active-target bridge, which is off by default. Without
# NULLFIELD_ACTIVE_TARGET_CM and NULLFIELD_ACTIVE_TARGET_LABEL the controller
# renders a per-policy ConfigMap that nothing mounts, so applying a CRD looks
# like it worked and changes nothing. controller.yaml switches it on.
set -euo pipefail

ns="${1:-nullfield-crd-demo}"
build_images="${BUILD_IMAGES:-false}"

cd "$(dirname "$0")/../.."
here="demos/10-crd-policy"

pass() { echo "  ok:  $1"; }
fail() { echo "FAIL: $1" >&2; exit 1; }

if [[ "$build_images" == "true" ]]; then
  echo "Building local images..."
  docker build -q -t ghcr.io/babywyrm/nullfield:latest . >/dev/null
  docker build -q -f Dockerfile.controller -t ghcr.io/babywyrm/nullfield-controller:latest . >/dev/null
  docker build -q -f tests/echo-server/Dockerfile -t ghcr.io/babywyrm/nullfield-echo:latest . >/dev/null
  if command -v k3s >/dev/null 2>&1; then
    for img in nullfield nullfield-controller nullfield-echo; do
      docker save "ghcr.io/babywyrm/$img:latest" | k3s ctr images import - >/dev/null
    done
  fi
fi

echo "Using namespace: $ns"

# Teardown does not block, so a re-run can arrive while the previous namespace
# is still Terminating. Creating into one of those fails with a Forbidden that
# reads like an RBAC problem and is not.
phase="$(kubectl get namespace "$ns" -o jsonpath='{.status.phase}' 2>/dev/null || true)"
if [[ "$phase" == "Terminating" ]]; then
  echo "  waiting for the previous run's namespace to finish terminating..."
  for _ in $(seq 1 60); do
    kubectl get namespace "$ns" >/dev/null 2>&1 || break
    sleep 2
  done
fi
kubectl get namespace "$ns" >/dev/null 2>&1 || kubectl create namespace "$ns"

work="$(mktemp -d)"
pf_pid=""
cleanup() {
  [[ -n "$pf_pid" ]] && kill "$pf_pid" >/dev/null 2>&1 || true
  rm -rf "$work"
  if [[ "${KEEP:-false}" != "true" ]]; then
    kubectl delete namespace "$ns" --wait=false >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

kubectl apply -f deploy/crds/nullfieldpolicy-crd.yaml >/dev/null
kubectl -n "$ns" apply -f "$here/tools.yaml" >/dev/null
kubectl -n "$ns" apply -f "$here/controller.yaml" >/dev/null
kubectl -n "$ns" rollout status deployment/crd-demo-controller --timeout=120s >/dev/null

echo
echo "the crd reaches a sidecar:"

kubectl -n "$ns" apply -f "$here/policy.yaml" >/dev/null

# The controller polls every 10s, so this is the CRD-to-ConfigMap leg only.
for _ in $(seq 1 24); do
  kubectl -n "$ns" get configmap crd-demo-active-policy >/dev/null 2>&1 && break
  sleep 5
done
kubectl -n "$ns" get configmap crd-demo-active-policy >/dev/null 2>&1 \
  || fail "the controller never bridged the CRD to crd-demo-active-policy -- check NULLFIELD_ACTIVE_TARGET_CM and the nullfield.io/active-for label"
pass "the controller renders the labelled CRD into the sidecar's ConfigMap"

source_label="$(kubectl -n "$ns" get configmap crd-demo-active-policy -o jsonpath='{.metadata.labels.nullfield\.io/active-source}')"
[[ "$source_label" == "crd-demo" ]] \
  || fail "expected active-source=crd-demo on the ConfigMap, got '${source_label:-<empty>}'"
pass "the ConfigMap records which CRD it came from"

# The workload mounts that ConfigMap, so it can only start once it exists.
kubectl -n "$ns" apply -f "$here/workload.yaml" >/dev/null
kubectl -n "$ns" rollout status deployment/crd-demo-runtime --timeout=180s >/dev/null

kubectl -n "$ns" port-forward service/crd-demo-runtime 19090:9090 19091:9091 >"$work/pf.log" 2>&1 &
pf_pid=$!
for _ in $(seq 1 30); do
  curl -fsS http://127.0.0.1:19091/healthz >/dev/null 2>&1 && break
  sleep 1
done
curl -fsS http://127.0.0.1:19091/healthz >/dev/null 2>&1 \
  || fail "sidecar never became reachable; port-forward log: $(cat "$work/pf.log")"

call() {
  curl -sS -X POST http://127.0.0.1:19090/mcp -H 'Content-Type: application/json' \
    -d "{\"jsonrpc\":\"2.0\",\"id\":$1,\"method\":\"tools/call\",\"params\":{\"name\":\"$2\",\"arguments\":{}}}"
}

echo
echo "the policy in the crd is the policy being enforced:"

granted="$(call 1 cost.check_usage)"
[[ "$granted" == *'echo-server executed'* ]] \
  || fail "the CRD's ALLOW rule did not take effect: $granted"
pass "a tool the CRD grants is allowed"

# Registered in tools.yaml on purpose, so this refusal comes from policy
# (-32000) rather than the registry (-32003). Without a registered-but-ungranted
# tool the demo could not tell the two gates apart.
refused="$(call 2 secrets.read_config)"
[[ "$refused" == *'"code":-32000'* ]] \
  || fail "expected a policy denial for secrets.read_config, got: $refused"
pass "a registered tool the CRD does not grant is refused by policy"

before="$(call 3 audit.list_actions)"
[[ "$before" == *'"code":-32000'* ]] \
  || fail "audit.list_actions should start out denied, got: $before"
pass "audit.list_actions starts out denied"

echo
echo "editing the crd changes the running sidecar's mind:"

# The only change is granting one more tool. Note this also grows the document,
# but the bridge hashes the whole policy now, so an edit that happened to
# preserve the length would be caught too.
sed 's/toolNames: \["cost.check_usage"\]/toolNames: ["cost.check_usage", "audit.list_actions"]/' \
  "$here/policy.yaml" >"$work/policy-v2.yaml"
grep -q 'audit.list_actions' "$work/policy-v2.yaml" \
  || fail "failed to build the edited policy -- the sed target has drifted"

kubectl -n "$ns" apply -f "$work/policy-v2.yaml" >/dev/null

# Three legs, and only the first is tunable: the controller's 10s poll, then
# kubelet refreshing the projected volume (up to its sync period, a minute by
# default), then the sidecar's own 10s poll. Budget generously.
started="$(date +%s)"
after=""
for _ in $(seq 1 40); do
  after="$(call 4 audit.list_actions)"
  [[ "$after" == *'echo-server executed'* ]] && break
  sleep 5
done
[[ "$after" == *'echo-server executed'* ]] \
  || fail "the sidecar never picked up the edited CRD within 200s; last response: $after"
pass "kubectl apply on the CRD flipped a live deny into an allow, with no restart"
echo "       (took $(( $(date +%s) - started ))s to propagate)"

restarts="$(kubectl -n "$ns" get pods -l app=crd-demo-runtime \
  -o jsonpath='{.items[*].status.containerStatuses[*].restartCount}')"
[[ "$restarts" != *[1-9]* ]] \
  || fail "a container restarted, so this proves nothing about hot-reload (restarts: $restarts)"
pass "no container restarted while that happened"

still_denied="$(call 5 secrets.read_config)"
[[ "$still_denied" == *'"code":-32000'* ]] \
  || fail "the edit widened more than it should have: $still_denied"
pass "the rest of the policy is unchanged"

echo
echo "crd demo green: kubectl apply is the control plane for a running sidecar"
