#!/usr/bin/env bash
# tier: 3
# requires: mesh
# summary: a run that trips its breaker is signalled once, as a Kubernetes Event and a signed webhook
#
# Signals on the mesh. Each run gets two calls; the third trips that run's
# breaker. nullfield refuses the call and tells whoever owns the run, so the
# controller can end its pod.
#
# Proves, against real Envoy traffic:
#
#   1. A run within its limit is allowed.
#   2. Past it, the run is refused at the circuit gate.
#   3. Another run on the same pod is unaffected.
#   4. The trip is one circuit.tripped event, however many calls follow.
#   5. It is recorded once as a Kubernetes Event on the pod's ServiceAccount,
#      annotated with the run.
#   6. It is posted once to the webhook, which verifies the signature.
#   7. The receiver rejects an unsigned post.
#
# Shares demo 16's namespace and extension provider, and demo 17's stand-in
# controller; run demo 16 once first (APPLY_MESH_CONFIG=true).
set -euo pipefail

ns="nullfield-mesh-demo"
demo="$(cd "$(dirname "$0")" && pwd)"
here="$demo/../17-run-tokens"
mesh="$demo/../16-mesh-arbiter"

fail() { echo "FAIL: $*" >&2; exit 1; }
ok()   { echo "  ok: $*"; }

# ---------------------------------------------------------------- prerequisites

for c in kubectl python3 openssl; do command -v "$c" >/dev/null || fail "$c not found"; done
kubectl -n istio-system get cm istio -o jsonpath='{.data.mesh}' | grep -q "name: nullfield-demo-ext-authz" \
  || fail "extension provider not registered; run APPLY_MESH_CONFIG=true demos/16-mesh-arbiter/test.sh first"

if [[ "${BUILD_IMAGES:-false}" == "true" ]]; then
  echo "building images..."
  ( cd "$demo/../.." \
    && docker build -q -f Dockerfile.extauthz -t ghcr.io/babywyrm/nullfield-extauthz:latest . >/dev/null \
    && docker build -q -f tests/echo-server/Dockerfile -t ghcr.io/babywyrm/nullfield-echo:latest . >/dev/null )
  if command -v k3s >/dev/null 2>&1; then
    for img in nullfield-extauthz nullfield-echo; do
      docker save "ghcr.io/babywyrm/$img:latest" | k3s ctr images import - >/dev/null
    done
  fi
fi

. "$here/run-controller.sh"

# ---------------------------------------------------------------------- deploy

kubectl apply -f "$mesh/mesh.yaml" >/dev/null
kubectl apply -f "$mesh/arbiter.yaml" >/dev/null
kubectl apply -f "$demo/manifests.yaml" >/dev/null
deploy_controller

# A fresh signing secret per run, from a file so it never sits in argv.
openssl rand -hex 32 >"$work/secret"
kubectl -n "$ns" create secret generic signal-webhook --from-file=secret="$work/secret" \
  --dry-run=client -o yaml | kubectl apply -f - >/dev/null

kubectl -n "$ns" patch deploy/nullfield-extauthz --type strategic -p '
spec:
  template:
    spec:
      containers:
        - name: extauthz
          env:
            - {name: NULLFIELD_EXTAUTHZ_MODE, value: enforce}
            - {name: NULLFIELD_SIGNAL_KUBE_EVENTS, value: "true"}
            - {name: NULLFIELD_SIGNAL_WEBHOOK_URL, value: "http://signal-receiver/hook"}
            - {name: NULLFIELD_SIGNAL_WEBHOOK_SECRET_FILE, value: /etc/nullfield-signal/secret}
          volumeMounts:
            - {name: signal-secret, mountPath: /etc/nullfield-signal, readOnly: true}
      volumes:
        - name: signal-secret
          secret: {secretName: signal-webhook}
' >/dev/null

for app in nullfield-extauthz mcp-echo signal-receiver; do
  kubectl -n "$ns" rollout restart "deploy/$app" >/dev/null
  kubectl -n "$ns" rollout status "deploy/$app" --timeout=180s >/dev/null
  for i in $(seq 1 60); do
    [[ "$(kubectl -n "$ns" get pods -l "app=$app" --no-headers | wc -l)" -eq 1 ]] && break
    [[ "$i" == 60 ]] && fail "an old $app pod did not terminate in 60s"
    sleep 1
  done
done
kubectl -n "$ns" wait --for=condition=Ready pod/mesh-demo-client --timeout=120s >/dev/null

log="$(kubectl -n "$ns" logs deploy/nullfield-extauthz --tail=60)"
grep -q '"signalling as Kubernetes Events"' <<<"$log" && grep -q '"signalling by webhook"' <<<"$log" \
  || fail "the arbiter is not signalling; rebuild with BUILD_IMAGES=true or check its log"
echo "deployed to $ns (enforce, two calls per run, signals on)"

# ------------------------------------------------------------------- utilities

call() {
  kubectl -n "$ns" exec mesh-demo-client -- curl -s -o /dev/null -w '%{http_code}' \
    -X POST http://mcp-echo/mcp -H 'Content-Type: application/json' -H "Txn-Token: $1" \
    -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo","arguments":{}}}'
}

decision_field() {
  kubectl -n "$ns" logs deploy/nullfield-extauthz --tail=60 2>/dev/null \
    | grep arbiter.decision | tail -1 \
    | python3 -c "import sys,json;print(json.loads(json.loads(sys.stdin.read())['payload']).get('$1',''))"
}

expect_status() {
  [[ "$1" == "$2" ]] || fail "HTTP $1, want $2"
  ok "HTTP $2"
}

# ------------------------------------------------------------------- readiness

printf 'waiting for the waypoint to route through the arbiter'
for i in $(seq 1 30); do
  call none >/dev/null 2>&1 || true
  [[ "$(decision_field reason_class 2>/dev/null)" == "run_token_invalid" ]] && break
  [[ "$i" == 30 ]] && { echo; fail "the arbiter saw no traffic in 60s"; }
  printf '.'; sleep 2
done
echo

principal="$(decision_field workload_principal)"
[[ "$principal" == spiffe://*/ns/${ns}/sa/mesh-demo-client ]] \
  || fail "workload_principal = '${principal}', want the client's SPIFFE id"

# Run IDs unique to this invocation, so Events from earlier runs cannot count.
stamp="$(date +%s)"
run_a="run-a-$stamp"
run_b="run-b-$stamp"
token_a="$(mint txntoken+jwt "$run_a" "$principal" acme/widgets)"
token_b="$(mint txntoken+jwt "$run_b" "$principal" acme/widgets)"

# ------------------------------------------------------------------------ 1-7

echo
echo "1. a run within its limit is allowed"
expect_status "$(call "$token_a")" 200
expect_status "$(call "$token_a")" 200

echo
echo "2. past it, the run is refused at the circuit gate"
expect_status "$(call "$token_a")" 403
[[ "$(decision_field gate)" == circuit && "$(decision_field run_id)" == "$run_a" ]] \
  || fail "refused at '$(decision_field gate)' for '$(decision_field run_id)', want circuit for $run_a"
ok "gate = circuit, run_id = $run_a"
expect_status "$(call "$token_a")" 403

echo
echo "3. another run on the same pod is unaffected"
expect_status "$(call "$token_b")" 200

echo
echo "4. the trip is one circuit.tripped event"
sleep 3
trips="$(kubectl -n "$ns" logs deploy/nullfield-extauthz --tail=200 | grep '"event_type":"circuit.tripped"' | grep -c "$run_a" || true)"
[[ "$trips" == 1 ]] || fail "$trips circuit.tripped events for $run_a, want 1"
ok "one circuit.tripped for $run_a after two refusals"

echo
echo "5. recorded once as a Kubernetes Event on the pod's ServiceAccount"
events="$(kubectl -n "$ns" get events.events.k8s.io --field-selector reason=CircuitTripped -o json \
  | python3 -c "
import sys, json
items = [e for e in json.load(sys.stdin)['items']
         if e['metadata'].get('annotations', {}).get('nullfield.io/run-id') == '$run_a']
for e in items:
    r = e['regarding']
    print(r['kind'], r['name'])
")"
[[ "$events" == "ServiceAccount mesh-demo-client" ]] \
  || fail "Events for $run_a: '${events}', want one on ServiceAccount mesh-demo-client"
ok "one CircuitTripped Event regarding ServiceAccount/mesh-demo-client, run $run_a"

echo
echo "6. posted once to the webhook, signature verified"
verified="$(kubectl -n "$ns" logs deploy/signal-receiver --tail=50 | grep '"verified"' | grep -c "$run_a" || true)"
[[ "$verified" == 1 ]] || fail "$verified verified posts for $run_a, want 1"
ok "receiver verified one circuit.tripped for $run_a"

echo
echo "7. the receiver rejects an unsigned post"
code="$(kubectl -n "$ns" exec mesh-demo-client -- curl -s -o /dev/null -w '%{http_code}' \
  -X POST http://signal-receiver/hook -H 'Content-Type: application/json' \
  -d "{\"type\":\"circuit.tripped\",\"run_id\":\"forged-$stamp\"}")"
expect_status "$code" 401

echo
echo "signals green: one trip, one Event, one signed post, nothing forgeable"
