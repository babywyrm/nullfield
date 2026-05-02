#!/usr/bin/env bash
# Diff the live camazotz tools/list against integrations/camazotz/tools.yaml.
#
# Portable — takes any MCP endpoint URL, no NUC / cluster-specific assumptions.
# Use against:
#   - local Compose:        http://localhost:8080/mcp
#   - K3s NodePort:         http://<node>:30080/mcp
#   - generic K8s ingress:  https://camazotz.example.com/mcp
#   - kubectl port-forward: http://localhost:8080/mcp
#
# Prints two lists:
#   added  — tools the live deployment exposes but tools.yaml does not register
#            (these get default-denied today; triage into tier 1 / 2 / 3)
#   removed — tools registered in tools.yaml but no longer live
#             (likely a renamed module — remove or alias)
#
# This script intentionally does not auto-edit tools.yaml. Tier placement is
# a human judgment that depends on a tool's actual destructive potential, and
# silently appending unknown tools to ALLOW would defeat the bundle's purpose.
#
# Usage:
#   bash integrations/camazotz/sync-tools.sh http://localhost:8080/mcp
#
# Requires: curl, jq, awk.

set -euo pipefail

URL="${1:-}"
if [[ -z "$URL" ]]; then
    echo "usage: $0 <camazotz-mcp-url>" >&2
    echo "example: $0 http://localhost:8080/mcp" >&2
    exit 2
fi

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
REGISTRY="$REPO_ROOT/integrations/camazotz/tools.yaml"
if [[ ! -f "$REGISTRY" ]]; then
    echo "registry not found: $REGISTRY" >&2
    exit 2
fi

for bin in curl jq awk; do
    command -v "$bin" >/dev/null || { echo "missing dependency: $bin" >&2; exit 2; }
done

LIVE_TMP="$(mktemp)"
REG_TMP="$(mktemp)"
trap 'rm -f "$LIVE_TMP" "$REG_TMP"' EXIT

curl -s --max-time 10 "$URL" \
    -X POST -H "Content-Type: application/json" \
    -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}' \
    | jq -r '.result.tools[].name' \
    | sort -u > "$LIVE_TMP"

LIVE_COUNT="$(wc -l < "$LIVE_TMP" | tr -d ' ')"
if [[ "$LIVE_COUNT" -eq 0 ]]; then
    echo "no tools returned from $URL — check URL, auth, or that the server speaks MCP" >&2
    exit 1
fi

awk '/^[[:space:]]*-[[:space:]]*name:/ { sub(/^[[:space:]]*-[[:space:]]*name:[[:space:]]*/, ""); print }' \
    "$REGISTRY" | sort -u > "$REG_TMP"

REG_COUNT="$(wc -l < "$REG_TMP" | tr -d ' ')"

echo "live  ($URL): $LIVE_COUNT tools"
echo "local ($REGISTRY): $REG_COUNT tools"
echo

ADDED="$(comm -23 "$LIVE_TMP" "$REG_TMP")"
REMOVED="$(comm -13 "$LIVE_TMP" "$REG_TMP")"

if [[ -z "$ADDED" && -z "$REMOVED" ]]; then
    echo "in sync — every live tool is registered, no stale entries"
    exit 0
fi

if [[ -n "$ADDED" ]]; then
    echo "added (live but unregistered — currently default-denied):"
    while IFS= read -r t; do echo "  - $t"; done <<< "$ADDED"
    echo
fi

if [[ -n "$REMOVED" ]]; then
    echo "removed (registered but no longer live — likely renamed):"
    while IFS= read -r t; do echo "  - $t"; done <<< "$REMOVED"
    echo
fi

echo "review additions and add them to the right tier in tools.yaml + policy.yaml"
exit 1
