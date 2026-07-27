#!/usr/bin/env bash
#
# Tests demos/run.sh against a synthetic demo tree. Never touches real demos:
# a harness test that depends on the demos it runs cannot tell you the harness
# is broken.
set -euo pipefail

repo_root="$(cd "$(dirname "$0")/.." && pwd)"
run_sh="$repo_root/demos/run.sh"

fixture=""
cleanup() { [[ -n "$fixture" ]] && rm -rf "$fixture"; }
trap cleanup EXIT

pass=0
fail=0

check() {
  local label="$1" got="$2" want="$3"
  if [[ "$got" == *"$want"* ]]; then
    echo "  ok: $label"
    pass=$((pass + 1))
  else
    echo "  FAIL: $label" >&2
    echo "        want substring: $want" >&2
    echo "        got: $got" >&2
    fail=$((fail + 1))
  fi
}

check_status() {
  local label="$1" got="$2" want="$3"
  if [[ "$got" == "$want" ]]; then
    echo "  ok: $label"
    pass=$((pass + 1))
  else
    echo "  FAIL: $label -- want exit $want, got exit $got" >&2
    fail=$((fail + 1))
  fi
}

make_fixture() {
  # HARNESS_TMPDIR exists so the fixture can be placed somewhere writable when
  # the default temp directory is not, such as under a sandbox.
  if [[ -n "${HARNESS_TMPDIR:-}" ]]; then
    mkdir -p "$HARNESS_TMPDIR"
    fixture="$(mktemp -d "$HARNESS_TMPDIR/harness.XXXXXX")"
  else
    fixture="$(mktemp -d)"
  fi

  mkdir -p "$fixture/01-alpha"
  cat >"$fixture/01-alpha/test.sh" <<'EOF'
#!/usr/bin/env bash
# tier: 1
# requires: compose
# summary: alpha passes
echo "alpha ran"
EOF

  mkdir -p "$fixture/02-beta"
  cat >"$fixture/02-beta/test.sh" <<'EOF'
#!/usr/bin/env bash
# tier: 1
# requires: none
# summary: beta fails on purpose
# ci: no
echo "beta ran"
exit 1
EOF

  mkdir -p "$fixture/03-gamma"
  cat >"$fixture/03-gamma/test.sh" <<'EOF'
#!/usr/bin/env bash
# tier: 1
# requires: compose
# summary: gamma compose tier one
echo "gamma ran"
EOF
  cat >"$fixture/03-gamma/test-k8s.sh" <<'EOF'
#!/usr/bin/env bash
# tier: 2
# requires: kubernetes
# summary: gamma on a cluster
echo "gamma k8s ran"
EOF

  chmod +x "$fixture"/*/test*.sh
}

make_fixture
export NULLFIELD_DEMOS_DIR="$fixture"

echo "discovery:"
out="$("$run_sh" --list)"
check "lists alpha"          "$out" "01-alpha"
check "lists beta"           "$out" "02-beta"
check "lists both gamma scripts" "$out" "test-k8s.sh"
check "shows tier"           "$out" "1"
check "shows requires"       "$out" "compose"
check "shows summary"        "$out" "alpha passes"
check "marks ci opt-out"     "$out" "no"

echo
echo "results: $pass passed, $fail failed"
[[ "$fail" -eq 0 ]]
