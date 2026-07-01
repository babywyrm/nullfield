#!/usr/bin/env bash
set -euo pipefail

ns="${1:-nullfield-demo}"
build_images="${BUILD_IMAGES:-false}"

cd "$(dirname "$0")/../.."

echo "Using namespace: $ns"

if [[ "$build_images" == "true" ]]; then
  echo "Building local images for single-node clusters..."
  docker build -t ghcr.io/babywyrm/nullfield:latest .
  docker build -f tests/echo-server/Dockerfile -t ghcr.io/babywyrm/nullfield-echo:latest .
  if command -v k3s >/dev/null 2>&1; then
    docker save ghcr.io/babywyrm/nullfield:latest | k3s ctr images import -
    docker save ghcr.io/babywyrm/nullfield-echo:latest | k3s ctr images import -
  fi
fi

kubectl get namespace "$ns" >/dev/null 2>&1 || kubectl create namespace "$ns"
kubectl apply -f deploy/crds/agenticflow-crd.yaml
kubectl -n "$ns" apply -f demos/14-agentic-flow-kubernetes/agentic-flow.yaml

echo "Applied AgenticFlow. Waiting for nullfield-flow-echo-known-path ConfigMap..."
for _ in $(seq 1 24); do
  if kubectl -n "$ns" get configmap nullfield-flow-echo-known-path >/dev/null 2>&1; then
    break
  fi
  sleep 5
done

kubectl -n "$ns" get configmap nullfield-flow-echo-known-path >/dev/null

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
