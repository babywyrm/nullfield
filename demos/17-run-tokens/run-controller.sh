# Sourced by demos 17 and 19: a stand-in run controller. Expects $ns and $here
# (the directory of demo 17) and defines mint and deploy_controller.
#
# A fresh key per run, never written outside a temp dir. The kid changes with
# it, so the arbiter fetches the new JWKS instead of serving a cached key.
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
openssl genrsa -out "$work/key.pem" 2048 2>/dev/null
kid="run-controller-$(date +%s)"

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

# Publishes this run's JWKS. A ConfigMap volume refreshes on the kubelet's
# schedule, not ours; a restart serves the new key now.
deploy_controller() {
  kubectl -n "$ns" create configmap run-controller-jwks --from-file=jwks.json="$work/jwks.json" \
    --dry-run=client -o yaml | kubectl apply -f - >/dev/null
  kubectl apply -f "$here/controller.yaml" >/dev/null
  kubectl -n "$ns" rollout restart deploy/run-controller >/dev/null
  kubectl -n "$ns" rollout status deploy/run-controller --timeout=120s >/dev/null
}
