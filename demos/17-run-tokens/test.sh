#!/usr/bin/env bash
# tier: 3
# requires: mesh
# summary: a run token bound to its pod narrows one run to one repo, through a real waypoint
#
# Run tokens on the mesh. A stand-in controller signs a Transaction Token per
# run; the waypoint asks nullfield; nullfield verifies the token, binds it to
# the attested caller, and lets the token narrow what policy allows.
#
# Proves, against real Envoy traffic:
#
#   1. A call with no run token is refused, and still attributed.
#   2. A token issued to this pod is accepted, and the run is recorded.
#   3. The token narrows: a repo outside its tctx is refused.
#   4. A token issued to another pod is refused here.
#   5. An access token cannot stand in for a run token.
#   6. The token never reaches the upstream.
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

for c in kubectl python3 openssl; do command -v "$c" >/dev/null || fail "$c not found"; done
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

# ------------------------------------------------------------ the controller key

# A fresh key per run, never written outside a temp dir. The kid changes with
# it, so the arbiter fetches the new JWKS instead of serving a cached key.
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
openssl genrsa -out "$work/key.pem" 2048 2>/dev/null
kid="demo17-$(date +%s)"

python3 - "$work/key.pem" "$kid" >"$work/jwks.json" <<'EOF'
import base64, json, subprocess, sys
key, kid = sys.argv[1:3]
mod = subprocess.run(["openssl", "rsa", "-in", key, "-noout", "-modulus"],
                     capture_output=True, check=True, text=True).stdout.strip().split("=", 1)[1]
b64 = lambda b: base64.urlsafe_b64encode(b).rstrip(b"=").decode()
print(json.dumps({"keys": [{"kty": "RSA", "kid": kid, "alg": "RS256", "use": "sig",
                            "n": b64(bytes.fromhex(mod)), "e": "AQAB"}]}))
EOF

# mint <typ> <run> <req_wl> <repos,comma,separated>
mint() {
  python3 - "$work/key.pem" "$kid" "$@" <<'EOF'
import base64, json, subprocess, sys, time
key, kid, typ, run, workload, repos = sys.argv[1:7]
b64 = lambda b: base64.urlsafe_b64encode(b).rstrip(b"=").decode()
header = {"alg": "RS256", "kid": kid}
if typ:
    header["typ"] = typ
now = int(time.time())
claims = {"aud": "cluster.local", "iat": now, "exp": now + 600, "txn": run,
          "sub": "team-sre", "scope": "incident.triage", "req_wl": workload,
          "tctx": {"repos": repos.split(",")}}
signing = b64(json.dumps(header).encode()) + "." + b64(json.dumps(claims).encode())
sig = subprocess.run(["openssl", "dgst", "-sha256", "-sign", key],
                     input=signing.encode(), capture_output=True, check=True).stdout
print(signing + "." + b64(sig))
EOF
}

# ---------------------------------------------------------------------- deploy

kubectl apply -f "$mesh/mesh.yaml" >/dev/null
kubectl apply -f "$mesh/arbiter.yaml" >/dev/null
kubectl apply -f "$here/arbiter-policy.yaml" >/dev/null

kubectl -n "$ns" create configmap run-controller-jwks --from-file=jwks.json="$work/jwks.json" \
  --dry-run=client -o yaml | kubectl apply -f - >/dev/null
kubectl apply -f "$here/controller.yaml" >/dev/null
# A ConfigMap volume refreshes on the kubelet's schedule, not ours; a restart
# serves this run's key now.
kubectl -n "$ns" rollout restart deploy/run-controller >/dev/null
kubectl -n "$ns" rollout status deploy/run-controller --timeout=120s >/dev/null

# Restart both: ext_authz reads its policy once at start, and a rebuilt
# :latest image is not picked up by a pod already running the old one.
# `logs deploy/x` reads an arbitrary pod while an old one is terminating, so
# wait for the old one to go before trusting a log line.
kubectl -n "$ns" set env deploy/nullfield-extauthz NULLFIELD_EXTAUTHZ_MODE=enforce >/dev/null
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

kubectl -n "$ns" logs deploy/nullfield-extauthz --tail=40 | grep -q '"run tokens verified"' \
  || fail "the arbiter did not load the runToken block; check its log for a policy error"
echo "deployed to $ns (enforce, run tokens required)"

# ------------------------------------------------------------------- utilities

# call <repo> [token] -> HTTP status
call() {
  local repo="$1" token="${2:-}" hdr=()
  [[ -n "$token" ]] && hdr=(-H "Txn-Token: $token")
  kubectl -n "$ns" exec mesh-demo-client -- curl -s -o /dev/null -w '%{http_code}' \
    -X POST http://mcp-echo/mcp -H 'Content-Type: application/json' "${hdr[@]}" \
    -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"echo\",\"arguments\":{\"repo\":\"${repo}\"}}}"
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
  ok "$1 = $2"
}

expect_status() {
  [[ "$1" == "$2" ]] || fail "HTTP $1, want $2"
  ok "HTTP $2"
}

# ------------------------------------------------------------------- readiness

printf 'waiting for the waypoint to route through the arbiter'
for i in $(seq 1 30); do
  call acme/widgets >/dev/null 2>&1 || true
  [[ "$(decision_field reason_class 2>/dev/null)" == "run_token_missing" ]] && break
  [[ "$i" == 30 ]] && { echo; fail "the arbiter saw no traffic in 60s"; }
  printf '.'; sleep 2
done
echo

principal="$(decision_field workload_principal)"
[[ "$principal" == spiffe://*/ns/${ns}/sa/mesh-demo-client ]] \
  || fail "workload_principal = '${principal}', want the client's SPIFFE id"
other="${principal%/sa/*}/sa/someone-else"

# ------------------------------------------------------------------------ 1-6

echo
echo "1. no run token: refused, and still attributed"
expect_status "$(call acme/widgets)" 403
expect_field gate run_token
expect_field reason_class run_token_missing
ok "workload_principal = $principal"

echo
echo "2. a token issued to this pod is accepted, and the run recorded"
run_a="$(mint txntoken+jwt run-a "$principal" acme/widgets)"
expect_status "$(call acme/widgets "$run_a")" 200
sleep 1
expect_field run_id run-a
expect_field identity team-sre
expect_field assurance MEDIUM

echo
echo "3. the token narrows: a repo outside its tctx is refused"
expect_status "$(call acme/payroll "$run_a")" 403
expect_field run_id run-a
expect_field reason_class policy_denied

echo
echo "4. a token issued to another pod is refused here"
expect_status "$(call acme/widgets "$(mint txntoken+jwt run-b "$other" acme/widgets)")" 403
expect_field reason_class run_token_unbound

echo
echo "5. an access token cannot stand in for a run token"
expect_status "$(call acme/widgets "$(mint at+jwt run-c "$principal" acme/widgets)")" 403
expect_field reason_class run_token_invalid

echo
echo "6. the token never reached the upstream"
expect_status "$(call acme/widgets "$run_a")" 200
sleep 1
seen="$(kubectl -n "$ns" logs deploy/mcp-echo --tail=20 | grep '"msg":"received"' | tail -1 \
  | python3 -c "import sys,json;print(json.loads(sys.stdin.read()).get('txn_token','absent'))")"
[[ "$seen" != "absent" ]] || fail "the echo server does not report txn_token; rebuild with BUILD_IMAGES=true"
[[ "$seen" == "False" ]] || fail "the upstream received the Txn-Token header"
ok "mcp-echo received no Txn-Token"

echo
echo "run tokens green: bound to the pod, narrowing one run, never forwarded"
