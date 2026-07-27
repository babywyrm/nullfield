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

main() {
  [[ $# -gt 0 ]] || { usage; exit 2; }
  case "$1" in
    --list) cmd_list ;;
    --audit) cmd_audit ;;
    -h|--help) usage ;;
    *) echo "unknown option: $1" >&2; usage >&2; exit 2 ;;
  esac
}

main "$@"
