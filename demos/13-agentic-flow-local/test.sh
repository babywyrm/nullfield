#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/../.."

out="$(mktemp)"
trap 'rm -f "$out"' EXIT

go run ./cmd/nullfield-compile demos/13-agentic-flow-local/agentic-flow.yaml >"$out"

require() {
  local pattern="$1"
  local label="$2"
  if ! grep -q "$pattern" "$out"; then
    echo "FAIL: missing $label ($pattern)" >&2
    exit 1
  fi
  echo "ok: $label"
}

require "kind: NullfieldPolicy" "compiled policy"
require "kind: ToolRegistry" "compiled registry"
require "id: echo-allow" "allow rule id"
require "id: github-create-pr-scope" "credentialed scope rule id"
require "secretRef: GITHUB_READ_TOKEN" "credential injection"
require "oauth_audience: https://api.github.com" "OAuth audit context"
require "id: pagerduty-resolve-hold" "hold rule id"
require "id: dangerous-tool-deny" "deny rule id"
require "id: default-deny" "default deny"

echo
echo "AgenticFlow local demo compiled successfully."
echo "Compiled artifact: $out"
