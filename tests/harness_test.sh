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
  fixture="$(mktemp -d)"

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
echo "audit:"
status=0
"$run_sh" --audit >/dev/null 2>&1 || status=$?
check_status "clean tree audits clean" "$status" "0"

mkdir -p "$fixture/04-empty"
status=0
out="$("$run_sh" --audit 2>&1)" || status=$?
check_status "directory with no script fails audit" "$status" "1"
check "names the empty directory" "$out" "04-empty"
rmdir "$fixture/04-empty"

mkdir -p "$fixture/05-headerless"
cat >"$fixture/05-headerless/test.sh" <<'EOF'
#!/usr/bin/env bash
echo "no header"
EOF
chmod +x "$fixture/05-headerless/test.sh"
status=0
out="$("$run_sh" --audit 2>&1)" || status=$?
check_status "missing header fails audit" "$status" "1"
check "names the missing field" "$out" "missing header field: tier"
rm -rf "$fixture/05-headerless"

mkdir -p "$fixture/06-badtier"
cat >"$fixture/06-badtier/test.sh" <<'EOF'
#!/usr/bin/env bash
# tier: 9
# requires: compose
# summary: tier nine does not exist
EOF
chmod +x "$fixture/06-badtier/test.sh"
status=0
out="$("$run_sh" --audit 2>&1)" || status=$?
check_status "invalid tier fails audit" "$status" "1"
check "names the bad tier" "$out" "tier: 9"
rm -rf "$fixture/06-badtier"

mkdir -p "$fixture/07-notexec"
cat >"$fixture/07-notexec/test.sh" <<'EOF'
#!/usr/bin/env bash
# tier: 1
# requires: none
# summary: this one is not executable
EOF
chmod -x "$fixture/07-notexec/test.sh"
status=0
out="$("$run_sh" --audit 2>&1)" || status=$?
check_status "non-executable script fails audit" "$status" "1"
check "says it is not executable" "$out" "not executable"
rm -rf "$fixture/07-notexec"

echo
echo "results: $pass passed, $fail failed"
[[ "$fail" -eq 0 ]]
