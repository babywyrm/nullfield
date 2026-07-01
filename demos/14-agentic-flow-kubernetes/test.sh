#!/usr/bin/env bash
set -euo pipefail

ns="${1:-nullfield-demo}"

cd "$(dirname "$0")/../.."

echo "Using namespace: $ns"

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
grep -q "id: github-create-pr-hold" "$policy"
grep -q "id: dangerous-tool-deny" "$policy"
grep -q "id: default-deny" "$policy"

echo "ok: AgenticFlow reconciled to ConfigMap"
echo "ok: policy.yaml and tools.yaml generated"
echo
kubectl -n "$ns" get agenticflow echo-known-path
kubectl -n "$ns" get configmap nullfield-flow-echo-known-path
