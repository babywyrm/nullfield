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
echo "execution:"
status=0
out="$("$run_sh" 01-alpha 2>&1)" || status=$?
check_status "named passing demo exits 0" "$status" "0"
check "named demo actually ran" "$out" "alpha ran"

status=0
out="$("$run_sh" 02-beta 2>&1)" || status=$?
check_status "named failing demo exits 1" "$status" "1"

status=0
out="$("$run_sh" 99-nope 2>&1)" || status=$?
check_status "unknown demo name exits 2" "$status" "2"

status=0
out="$("$run_sh" --tier 1 2>&1)" || status=$?
check_status "tier 1 fails when a tier-1 demo fails" "$status" "1"
check "tier 1 ran alpha" "$out" "alpha ran"
check "tier 1 ran beta"  "$out" "beta ran"
check "tier 1 ran gamma" "$out" "gamma ran"
check "tier 1 left the k8s script alone" "$out" "tier 1: 2 passed, 1 failed"

status=0
out="$("$run_sh" --ci 2>&1)" || status=$?
check_status "--ci skips the ci:no demo and passes" "$status" "0"
check "--ci says it skipped beta" "$out" "02-beta"

status=0
out="$("$run_sh" --tier 2 2>&1)" || status=$?
check_status "tier 2 runs only the k8s script" "$status" "0"
check "tier 2 ran gamma k8s" "$out" "gamma k8s ran"

status=0
out="$("$run_sh" --tier 3 2>&1)" || status=$?
check_status "empty tier exits 0" "$status" "0"
check "empty tier says so" "$out" "no demos"

echo
echo "record:"
cat >"$fixture/VERIFIED.md" <<'EOF'
# Verified Runs

| Date | Demo | Tier | Result | Substrate |
|---|---|---|---|---|
EOF

NULLFIELD_SUBSTRATE="k3s-test" "$run_sh" --tier 2 --record >/dev/null 2>&1
out="$(cat "$fixture/VERIFIED.md")"
check "records the demo name" "$out" "03-gamma"
check "records the tier"      "$out" "| 2 |"
check "records the result"    "$out" "PASS"
check "records the substrate" "$out" "k3s-test"
check "records today's date"  "$out" "$(date +%Y-%m-%d)"

# A failing tier-2 demo must be recorded as FAIL, not omitted. A log that only
# ever says PASS is not evidence of anything.
mkdir -p "$fixture/08-badk8s"
cat >"$fixture/08-badk8s/test-k8s.sh" <<'EOF'
#!/usr/bin/env bash
# tier: 2
# requires: kubernetes
# summary: fails on a cluster
exit 1
EOF
chmod +x "$fixture/08-badk8s/test-k8s.sh"
NULLFIELD_SUBSTRATE="k3s-test" "$run_sh" --tier 2 --record >/dev/null 2>&1 || true
out="$(cat "$fixture/VERIFIED.md")"
check "records a failure too" "$out" "| 08-badk8s | 2 | FAIL |"
rm -rf "$fixture/08-badk8s"

echo
echo "index:"
"$run_sh" --index >/dev/null 2>&1 || true
out="$(cat "$fixture/README.md" 2>/dev/null || echo '<no index written>')"
check "index has the header"      "$out" "# Demonstration Flows"
check "index lists alpha"         "$out" "01-alpha"
check "index carries the summary" "$out" "alpha passes"
check "index shows the tier"      "$out" "| 03 | [gamma](03-gamma/) | 1 |"
check "index flags the ci opt-out" "$out" "not in CI"
check "index says it is generated" "$out" "generated by"

# A directory with no script still exists on disk. Omitting it would make the
# index under-report the tree, which is the failure class this whole thing is
# meant to remove.
mkdir -p "$fixture/09-noscript"
"$run_sh" --index >/dev/null 2>&1 || true
out="$(cat "$fixture/README.md" 2>/dev/null || echo '<no index written>')"
check "index lists a script-less demo" "$out" "09-noscript"
check "index marks it as unasserted"   "$out" "no assertion script yet"
rm -rf "$fixture/09-noscript"

echo
echo "results: $pass passed, $fail failed"
[[ "$fail" -eq 0 ]]
