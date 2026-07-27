#!/usr/bin/env bash
#
# Register the demo's decision service as an Istio extension provider.
#
# Split out of test.sh because it is the one step that edits mesh-wide
# configuration and restarts istiod. Everything else the demo does is scoped to
# its own namespace and goes away when that namespace does; this does not. It
# backs up the ConfigMap first and is idempotent.
set -euo pipefail

ns="${1:-nullfield-mesh-demo}"
provider="nullfield-demo-ext-authz"
service="nullfield-extauthz.${ns}.svc.cluster.local"
backup_dir="${BACKUP_DIR:-/tmp}"

stamp="$(date +%Y%m%d-%H%M%S)"
backup="${backup_dir}/istio-cm-${stamp}.yaml"
mkdir -p "$backup_dir"
kubectl -n istio-system get cm istio -o yaml >"$backup"

kubectl -n istio-system get cm istio -o jsonpath='{.data.mesh}' >/tmp/mesh-current.yaml

# Parse and re-emit rather than splicing text in.
#
# An earlier version inserted the provider as a formatted string, which produced
# a list whose first item was indented two spaces and whose remaining items were
# not. That is not valid as a single sequence, so istiod parsed extensionProviders
# as empty and reported "available providers are []" - at which point every
# CUSTOM AuthorizationPolicy in the mesh silently converts to a deny, including
# ones that have nothing to do with this demo. Editing shared cluster config by
# string manipulation is not worth the convenience.
# Exit 2 means "already correct", distinct from any other failure. Treating a
# non-zero exit as "nothing to do" would report success for a crash, which is
# how the corruption above survived a run that looked like it had passed.
set +e
python3 - "$provider" "$service" <<'PY'
import sys
import yaml

provider, service = sys.argv[1], sys.argv[2]

try:
    with open("/tmp/mesh-current.yaml") as fh:
        mesh = yaml.safe_load(fh) or {}
except yaml.YAMLError as exc:
    print(f"the live mesh config is not parseable YAML: {exc}", file=sys.stderr)
    sys.exit(1)

providers = mesh.setdefault("extensionProviders", [])
entry = {
    "name": provider,
    "envoyExtAuthzGrpc": {
        "service": service,
        "port": 9191,
        "includeRequestBodyInCheck": {
            "maxRequestBytes": 8192,
            # True because the demo starts in observe mode. With false, Envoy
            # answers an oversized body with 413 before the check runs, so a
            # deployment meant to be read-only breaks traffic while observing
            # nothing. test.sh asserts on that boundary.
            "allowPartialMessage": True,
        },
    },
}

for i, existing in enumerate(providers):
    if existing.get("name") == provider:
        if existing == entry:
            sys.exit(2)
        providers[i] = entry
        break
else:
    providers.append(entry)

with open("/tmp/mesh-next.yaml", "w") as fh:
    yaml.safe_dump(mesh, fh, sort_keys=False)
PY
rc=$?
set -e

case "$rc" in
  0) ;;
  2)
    echo "provider ${provider} already registered and current"
    rm -f "$backup"
    exit 0
    ;;
  *)
    echo "FAIL: could not rewrite the mesh config (exit ${rc}); nothing was changed." >&2
    echo "      A copy of the current config is at ${backup}" >&2
    exit 1
    ;;
esac

echo "backed up istio ConfigMap to ${backup}"

python3 - <<'PY'
import json
with open("/tmp/mesh-next.yaml") as fh:
    mesh = fh.read()
with open("/tmp/mesh-patch.json", "w") as fh:
    json.dump({"data": {"mesh": mesh}}, fh)
PY

kubectl -n istio-system patch cm istio --type merge --patch-file=/tmp/mesh-patch.json >/dev/null
echo "registered ${provider} -> ${service}"

kubectl -n istio-system rollout restart deploy/istiod >/dev/null
kubectl -n istio-system rollout status deploy/istiod --timeout=180s >/dev/null

# Verify rather than assume. A malformed edit does not fail the patch; it fails
# later, quietly, as an empty provider list.
sleep 5
if kubectl -n istio-system logs deploy/istiod --tail=100 2>/dev/null | grep -q "available providers are \[\]"; then
  echo "FAIL: istiod cannot parse extensionProviders after this edit." >&2
  echo "      Restore with: kubectl -n istio-system apply -f ${backup}" >&2
  exit 1
fi
echo "istiod restarted, providers parse cleanly"
