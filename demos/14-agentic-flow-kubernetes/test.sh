#!/usr/bin/env bash
# tier: 2
# requires: kubernetes
# summary: the controller compiles an agenticflow crd and a sidecar enforces it
set -euo pipefail

ns="${1:-nullfield-demo}"
build_images="${BUILD_IMAGES:-false}"

cd "$(dirname "$0")/../.."

echo "Using namespace: $ns"

if [[ "$build_images" == "true" ]]; then
  echo "Building local images for single-node clusters..."
  docker build -t ghcr.io/babywyrm/nullfield:latest .
  docker build -f Dockerfile.controller -t ghcr.io/babywyrm/nullfield-controller:latest .
  docker build -f tests/echo-server/Dockerfile -t ghcr.io/babywyrm/nullfield-echo:latest .
  if command -v k3s >/dev/null 2>&1; then
    for img in nullfield nullfield-controller nullfield-echo; do
      docker save "ghcr.io/babywyrm/$img:latest" | k3s ctr images import -
    done
  fi
fi

kubectl get namespace "$ns" >/dev/null 2>&1 || kubectl create namespace "$ns"
kubectl apply -f deploy/crds/agenticflow-crd.yaml

# The controller is what compiles a flow into a ConfigMap. The demo used to
# apply the CRD and then wait for a ConfigMap with nothing running that could
# write one, so it could only ever have passed against a cluster that happened
# to have a controller left over from something else.
kubectl -n "$ns" apply -f demos/14-agentic-flow-kubernetes/controller.yaml
kubectl -n "$ns" rollout status deploy/flow-demo-controller --timeout=120s

kubectl -n "$ns" apply -f demos/14-agentic-flow-kubernetes/agentic-flow.yaml

echo "Applied AgenticFlow. Waiting for nullfield-flow-echo-known-path ConfigMap..."
for _ in $(seq 1 24); do
  if kubectl -n "$ns" get configmap nullfield-flow-echo-known-path >/dev/null 2>&1; then
    break
  fi
  sleep 5
done

# A bare `kubectl get` here fails with NotFound and nothing else, which says
# the ConfigMap is missing but not why. The controller's own logs and the
# flow's status conditions are where the answer is, so print them before
# giving up.
if ! kubectl -n "$ns" get configmap nullfield-flow-echo-known-path >/dev/null 2>&1; then
  echo "FAIL: the controller never compiled the AgenticFlow into a ConfigMap" >&2
  echo "--- controller logs ---" >&2
  kubectl -n "$ns" logs deploy/flow-demo-controller --tail=40 >&2 2>/dev/null || true
  echo "--- flow status ---" >&2
  kubectl -n "$ns" get agenticflow echo-known-path -o yaml 2>/dev/null | sed -n '/status:/,$p' >&2 || true
  exit 1
fi

compiled="$(mktemp)"
policy="$(mktemp)"
tools="$(mktemp)"
trap 'rm -f "$compiled" "$policy" "$tools"' EXIT

kubectl -n "$ns" get configmap nullfield-flow-echo-known-path -o jsonpath='{.data.compiled\.yaml}' >"$compiled"
kubectl -n "$ns" get configmap nullfield-flow-echo-known-path -o jsonpath='{.data.policy\.yaml}' >"$policy"
kubectl -n "$ns" get configmap nullfield-flow-echo-known-path -o jsonpath='{.data.tools\.yaml}' >"$tools"

grep -q "kind: NullfieldPolicy" "$policy"
grep -q "kind: ToolRegistry" "$tools"
grep -q "id: echo-allow" "$policy"
grep -q "id: github-create-pr-deny" "$policy"
grep -q "id: dangerous-tool-deny" "$policy"
grep -q "id: default-deny" "$policy"

echo "ok: AgenticFlow reconciled to ConfigMap"
echo "ok: policy.yaml and tools.yaml generated"
echo
kubectl -n "$ns" get agenticflow echo-known-path
kubectl -n "$ns" get configmap nullfield-flow-echo-known-path
compiled_status="$(kubectl -n "$ns" get agenticflow echo-known-path -o jsonpath='{.status.conditions[?(@.type=="Compiled")].status}')"
if [[ "$compiled_status" != "True" ]]; then
  echo "FAIL: expected AgenticFlow Compiled=True, got ${compiled_status:-<empty>}" >&2
  exit 1
fi
echo "ok: AgenticFlow status reports Compiled=True"

echo
echo "Deploying runtime workload..."
kubectl -n "$ns" apply -f demos/14-agentic-flow-kubernetes/workload.yaml
kubectl -n "$ns" rollout status deployment/agentic-flow-runtime --timeout=120s

pf_log="$(mktemp)"
trap 'rm -f "$compiled" "$policy" "$tools" "$pf_log"; if [[ -n "${pf_pid:-}" ]]; then kill "$pf_pid" >/dev/null 2>&1 || true; fi' EXIT
kubectl -n "$ns" port-forward service/agentic-flow-runtime 19090:9090 19091:9091 >"$pf_log" 2>&1 &
pf_pid=$!
for _ in $(seq 1 20); do
  if curl -fsS http://127.0.0.1:19091/healthz >/dev/null 2>&1; then
    break
  fi
  sleep 1
done

call_tool() {
  local id="$1"
  local tool="$2"
  curl -fsS -X POST http://127.0.0.1:19090/mcp \
    -H "Content-Type: application/json" \
    -d "{\"jsonrpc\":\"2.0\",\"id\":$id,\"method\":\"tools/call\",\"params\":{\"name\":\"$tool\",\"arguments\":{}}}"
}

allowed="$(call_tool 1 echo)"
denied="$(call_tool 2 dangerous_tool)"
unknown="$(call_tool 3 unknown_tool)"

echo "$allowed" | grep -q '"result"'
echo "$allowed" | grep -q 'echo-server executed'
echo "$denied" | grep -q '"code":-32000'
echo "$unknown" | grep -q '"code":-32003'

echo "ok: runtime ALLOW path executed through nullfield"
echo "ok: runtime DENY path blocked by policy"
echo "ok: unknown tool blocked by registry/default path"
