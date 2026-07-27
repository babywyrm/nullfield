#!/usr/bin/env bash
#
# Proxy-mode regression baseline.
#
# Runs the original data path in a namespace with no mesh at all, so a failure
# here means the decision core is broken and a failure only in the mesh demos
# means the mesh integration is. Without that split, every mesh problem starts
# with an unbounded search.
#
# Deliberately does not enrol the namespace in ambient. If it did, a waypoint
# would sit in front of this traffic and the baseline would no longer be one.
set -euo pipefail

ns="${1:-nullfield-baseline}"
build_images="${BUILD_IMAGES:-false}"

cd "$(dirname "$0")/../.."

echo "namespace: $ns"

if [[ "$build_images" == "true" ]]; then
  echo "building images..."
  docker build -q -t ghcr.io/babywyrm/nullfield:latest . >/dev/null
  docker build -q -f tests/echo-server/Dockerfile -t ghcr.io/babywyrm/nullfield-echo:latest . >/dev/null
  if command -v k3s >/dev/null 2>&1; then
    docker save ghcr.io/babywyrm/nullfield:latest | k3s ctr images import - >/dev/null
    docker save ghcr.io/babywyrm/nullfield-echo:latest | k3s ctr images import - >/dev/null
  fi
fi

kubectl get namespace "$ns" >/dev/null 2>&1 || kubectl create namespace "$ns"

# Fail loudly rather than silently measuring the wrong thing. A meshed namespace
# would still pass every assertion below while proving something else entirely.
dataplane="$(kubectl get namespace "$ns" -o jsonpath='{.metadata.labels.istio\.io/dataplane-mode}' 2>/dev/null || true)"
if [[ -n "$dataplane" ]]; then
  echo "FAIL: namespace $ns is enrolled in the mesh (dataplane-mode=$dataplane)." >&2
  echo "      This demo is the no-mesh baseline; use demo 16 for the mesh path." >&2
  exit 1
fi

kubectl -n "$ns" apply -f demos/15-proxy-baseline/workload.yaml
kubectl -n "$ns" rollout status deployment/nullfield-baseline --timeout=120s

pf_log="$(mktemp)"
cleanup() {
  if [[ -n "${pf_pid:-}" ]]; then kill "$pf_pid" >/dev/null 2>&1 || true; fi
  rm -f "$pf_log"
}
trap cleanup EXIT

kubectl -n "$ns" port-forward service/nullfield-baseline 19090:9090 19091:9091 >"$pf_log" 2>&1 &
pf_pid=$!

ready=false
for _ in $(seq 1 30); do
  if curl -fsS http://127.0.0.1:19091/healthz >/dev/null 2>&1; then ready=true; break; fi
  sleep 1
done
if [[ "$ready" != "true" ]]; then
  echo "FAIL: admin endpoint never came up" >&2
  cat "$pf_log" >&2
  exit 1
fi

call_tool() {
  curl -fsS -X POST http://127.0.0.1:19090/mcp \
    -H "Content-Type: application/json" \
    -d "{\"jsonrpc\":\"2.0\",\"id\":$1,\"method\":\"tools/call\",\"params\":{\"name\":\"$2\",\"arguments\":{}}}"
}

expect() {
  local label="$1" body="$2" want="$3"
  if grep -q -- "$want" <<<"$body"; then
    echo "  ok: $label"
  else
    echo "FAIL: $label -- expected to find '$want' in: $body" >&2
    exit 1
  fi
}

echo
echo "proxy-mode decisions:"
expect "ALLOW reaches the upstream"     "$(call_tool 1 echo)"           'echo-server executed'
expect "DENY is refused by policy"      "$(call_tool 2 dangerous_tool)" '"code":-32000'
expect "unknown tool is refused"        "$(call_tool 3 not_registered)" '"code":-32003'

echo
echo "baseline green: proxy mode decides correctly with no mesh present"
