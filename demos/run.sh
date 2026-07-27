#!/usr/bin/env bash
#
# Demo runner.
#
# Demos declare their own tier and infrastructure in a header comment. This
# script discovers them by globbing rather than reading a list, because a
# hand-maintained list is a second source of truth and demos/README.md is the
# standing evidence of what that costs.
set -euo pipefail

demos_dir="${NULLFIELD_DEMOS_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)}"
repo_root="$(cd "$demos_dir/.." && pwd)"

usage() {
  cat <<'EOF'
usage: demos/run.sh [options] [demo-name]

  --list           show every demo, its tier, and what it needs
  --tier N         run every demo at tier N (1, 2, or 3)
  --ci             run tier 1 only, skipping demos marked "ci: no"
  --audit          verify every demo directory has a script with a valid header
  --record         append results to demos/VERIFIED.md (use with --tier 2 or 3)
                   set NULLFIELD_SUBSTRATE to name where it ran, e.g.
                   NULLFIELD_SUBSTRATE="k3s 1.34 / Istio 1.30.1 ambient"
  --index          regenerate demos/README.md from the script headers
  -h, --help       this

  demo-name        run one demo by directory name, e.g. 16-mesh-arbiter

examples:
  demos/run.sh --list
  demos/run.sh --ci
  demos/run.sh --tier 3 --record
  demos/run.sh 16-mesh-arbiter
EOF
}

# Reads one header field. Only the first 15 lines are scanned, so a stray
# comment further down a long script cannot masquerade as metadata.
meta() {
  local file="$1" field="$2"
  sed -n '1,15p' "$file" | sed -n "s/^# *${field}: *//p" | head -1
}

# Emits every discovered script path, one per line, sorted.
discover() {
  local f
  for f in "$demos_dir"/*/test*.sh; do
    [[ -e "$f" ]] || continue
    printf '%s\n' "$f"
  done | LC_ALL=C sort
}

demo_name_of() {
  basename "$(dirname "$1")"
}

cmd_list() {
  printf '%-26s %-14s %-5s %-11s %-3s %s\n' \
    DEMO SCRIPT TIER REQUIRES CI SUMMARY
  local f ci
  while IFS= read -r f; do
    [[ -n "$f" ]] || continue
    ci="$(meta "$f" ci)"
    [[ -n "$ci" ]] || ci="yes"
    printf '%-26s %-14s %-5s %-11s %-3s %s\n' \
      "$(demo_name_of "$f")" \
      "$(basename "$f")" \
      "$(meta "$f" tier)" \
      "$(meta "$f" requires)" \
      "$ci" \
      "$(meta "$f" summary)"
  done <<<"$(discover)"
}

cmd_audit() {
  local problems=0 d f name field tier requires summary ci

  # Every demo directory must ship at least one assertion script. A demo that
  # cannot assert anything is a document, and documents belong in docs/.
  for d in "$demos_dir"/*/; do
    [[ -d "$d" ]] || continue
    name="$(basename "$d")"
    if ! compgen -G "$d/test*.sh" >/dev/null; then
      echo "audit: $name has no test script" >&2
      problems=$((problems + 1))
    fi
  done

  while IFS= read -r f; do
    [[ -n "$f" ]] || continue
    name="$(demo_name_of "$f")/$(basename "$f")"

    if [[ ! -x "$f" ]]; then
      echo "audit: $name is not executable" >&2
      problems=$((problems + 1))
    fi

    tier="$(meta "$f" tier)"
    requires="$(meta "$f" requires)"
    summary="$(meta "$f" summary)"
    ci="$(meta "$f" ci)"

    for field in tier requires summary; do
      if [[ -z "$(meta "$f" "$field")" ]]; then
        echo "audit: $name is missing header field: $field" >&2
        problems=$((problems + 1))
      fi
    done

    case "$tier" in
      1|2|3|"") ;;
      *) echo "audit: $name has an invalid tier: $tier" >&2
         problems=$((problems + 1)) ;;
    esac

    case "$requires" in
      none|compose|kubernetes|mesh|"") ;;
      *) echo "audit: $name has an invalid requires: $requires" >&2
         problems=$((problems + 1)) ;;
    esac

    if [[ -n "$ci" && "$ci" != "no" ]]; then
      echo "audit: $name has ci: $ci (only 'no' is meaningful; omit otherwise)" >&2
      problems=$((problems + 1))
    fi

    if [[ "$ci" == "no" && "$tier" != "1" ]]; then
      echo "audit: $name is tier $tier and does not need ci: no" >&2
      problems=$((problems + 1))
    fi
  done <<<"$(discover)"

  if [[ "$problems" -gt 0 ]]; then
    echo "audit: $problems problem(s)" >&2
    return 1
  fi
  echo "audit: clean"
}

# Runs one script from the repository root so relative paths inside a demo
# behave the same whether it was invoked by the runner or by hand.
run_one() {
  local f="$1" name
  name="$(demo_name_of "$f")/$(basename "$f")"
  echo "── $name"
  if (cd "$repo_root" && bash "$f"); then
    echo "── $name: PASS"
    return 0
  fi
  echo "── $name: FAIL" >&2
  return 1
}

# scripts_at TIER SKIP_CI_OPTOUT -> newline-separated paths
scripts_at() {
  local want_tier="$1" skip_optout="$2" f
  while IFS= read -r f; do
    [[ -n "$f" ]] || continue
    [[ "$(meta "$f" tier)" == "$want_tier" ]] || continue
    if [[ "$skip_optout" == "true" && "$(meta "$f" ci)" == "no" ]]; then
      echo "skipping $(demo_name_of "$f") (ci: no)" >&2
      continue
    fi
    printf '%s\n' "$f"
  done <<<"$(discover)"
}

# cmd_run TIER SKIP_CI_OPTOUT RECORD
cmd_run() {
  local want_tier="$1" skip_optout="$2" record="$3"
  local scripts passed=0 failed=0 f
  scripts="$(scripts_at "$want_tier" "$skip_optout")"

  if [[ -z "$scripts" ]]; then
    echo "no demos at tier $want_tier"
    return 0
  fi

  while IFS= read -r f; do
    [[ -n "$f" ]] || continue
    if run_one "$f"; then
      passed=$((passed + 1))
      [[ "$record" == "true" ]] && record_result "$f" PASS
    else
      failed=$((failed + 1))
      [[ "$record" == "true" ]] && record_result "$f" FAIL
    fi
    echo
  done <<<"$scripts"

  echo "tier $want_tier: $passed passed, $failed failed"
  [[ "$failed" -eq 0 ]]
}

cmd_run_named() {
  local want="$1" f found=""
  while IFS= read -r f; do
    [[ -n "$f" ]] || continue
    [[ "$(demo_name_of "$f")" == "$want" ]] || continue
    found="yes"
    run_one "$f" || return 1
  done <<<"$(discover)"

  if [[ -z "$found" ]]; then
    echo "no such demo: $want" >&2
    echo "try: demos/run.sh --list" >&2
    return 2
  fi
}

# Appends a dated line to VERIFIED.md. The substrate is the operator's claim
# about where this ran; a result with no substrate is not worth much, so it
# defaults to something obviously unhelpful rather than to nothing.
record_result() {
  local f="$1" result="$2"
  local verified="$demos_dir/VERIFIED.md"
  local substrate="${NULLFIELD_SUBSTRATE:-unspecified}"

  [[ -f "$verified" ]] || return 0

  printf '| %s | %s | %s | %s | %s |\n' \
    "$(date +%Y-%m-%d)" \
    "$(demo_name_of "$f")" \
    "$(meta "$f" tier)" \
    "$result" \
    "$substrate" >>"$verified"
}

# Regenerates demos/README.md from the script headers. The index is derived
# rather than maintained, which is what stops the count, the summaries, and the
# tiers from drifting apart again.
cmd_index() {
  local out="$demos_dir/README.md" f name num tier summary ci

  {
    cat <<'HEADER'
# Demonstration Flows

<!-- generated by demos/run.sh --index — do not edit by hand -->

Each demo has a `README.md` walkthrough and at least one assertion script that
exits non-zero when the demo is wrong.

Tier describes infrastructure and nothing else:

- **Tier 1** — Docker Compose, or just the built binary. Hermetic, and gated in CI.
- **Tier 2** — needs a Kubernetes cluster.
- **Tier 3** — needs an Istio ambient mesh.

Tiers 2 and 3 are never gated in CI. See [VERIFIED.md](VERIFIED.md) for when
they last ran and on what.

## Running them

```bash
./demos/run.sh --list          # everything, with tier and requirements
./demos/run.sh --ci            # what CI runs
./demos/run.sh --tier 2        # cluster demos
./demos/run.sh 16-mesh-arbiter # one by name
```

## Demos

| # | Demo | Tier | What it covers |
|---|---|---|---|
HEADER

    # Walk directories rather than scripts, so a demo that ships nothing to run
    # still appears. Omitting it would let the index under-report the tree,
    # which is the failure this generator exists to prevent.
    local d scripts
    for d in "$demos_dir"/*/; do
      [[ -d "$d" ]] || continue
      name="$(basename "$d")"
      num="${name%%-*}"

      scripts="$(discover | grep "/$name/" || true)"
      if [[ -z "$scripts" ]]; then
        printf '| %s | [%s](%s/) | — | *no assertion script yet* |\n' \
          "$num" "${name#*-}" "$name"
        continue
      fi

      while IFS= read -r f; do
        [[ -n "$f" ]] || continue
        tier="$(meta "$f" tier)"
        summary="$(meta "$f" summary)"
        ci="$(meta "$f" ci)"
        [[ "$ci" == "no" ]] && tier="$tier (not in CI)"
        printf '| %s | [%s](%s/) | %s | %s |\n' \
          "$num" "${name#*-}" "$name" "$tier" "$summary"
      done <<<"$scripts"
    done

    printf '\n'
  } >"$out"

  echo "wrote $out"
}

main() {
  local tier="" named="" record="false" skip_optout="false" action=""

  [[ $# -gt 0 ]] || { usage; exit 2; }

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --list)   action="list" ;;
      --audit)  action="audit" ;;
      --index)  action="index" ;;
      --record) record="true" ;;
      --ci)     action="run"; tier="1"; skip_optout="true" ;;
      --tier)
        shift
        [[ $# -gt 0 ]] || { echo "--tier needs a number" >&2; exit 2; }
        action="run"; tier="$1" ;;
      -h|--help) usage; exit 0 ;;
      -*) echo "unknown option: $1" >&2; usage >&2; exit 2 ;;
      *)  action="named"; named="$1" ;;
    esac
    shift
  done

  case "$action" in
    list)  cmd_list ;;
    audit) cmd_audit ;;
    index) cmd_index ;;
    run)   cmd_run "$tier" "$skip_optout" "$record" ;;
    named) cmd_run_named "$named" ;;
    *)     usage >&2; exit 2 ;;
  esac
}

main "$@"
