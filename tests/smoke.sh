#!/usr/bin/env bash
# Smoke test for nullfield proxy + echo server.
# Usage: docker compose up -d && bash tests/smoke.sh

BASE="http://localhost:9090"
ADMIN="http://localhost:9091"
PASS=0
FAIL=0

check() {
  local desc="$1" expected="$2" actual="$3"
  if echo "$actual" | grep -q "$expected"; then
    echo "  PASS: $desc"
    PASS=$((PASS + 1))
  else
    echo "  FAIL: $desc"
    echo "        expected to contain: $expected"
    echo "        got: $actual"
    FAIL=$((FAIL + 1))
  fi
}

echo "=== nullfield smoke tests ==="
echo ""

echo "[admin endpoints]"
resp=$(curl -sf "$ADMIN/healthz" 2>&1 || true)
check "/healthz returns ok" "ok" "$resp"

resp=$(curl -sf "$ADMIN/readyz" 2>&1 || true)
check "/readyz returns ok" "ok" "$resp"

echo ""
echo "[MCP passthrough — non-tools/call methods forwarded to upstream]"

resp=$(curl -sf -X POST "$BASE" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}' 2>&1 || true)
check "initialize returns protocolVersion" "protocolVersion" "$resp"

resp=$(curl -sf -X POST "$BASE" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}' 2>&1 || true)
check "tools/list returns tool definitions" "echo" "$resp"

resp=$(curl -sf -X POST "$BASE" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":3,"method":"ping"}' 2>&1 || true)
check "ping returns result" "result" "$resp"

echo ""
echo "[registry enforcement — unregistered tools rejected]"

resp=$(curl -s -X POST "$BASE" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":10,"method":"tools/call","params":{"name":"dangerous_tool","arguments":{}}}' 2>&1 || true)
check "dangerous_tool blocked: -32003 not registered" "not registered" "$resp"

resp=$(curl -s -X POST "$BASE" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":11,"method":"tools/call","params":{"name":"totally_fake_tool","arguments":{}}}' 2>&1 || true)
check "totally_fake_tool blocked: -32003 not registered" "not registered" "$resp"

echo ""
echo "[policy enforcement — registered tools hit default-deny rule]"

resp=$(curl -s -X POST "$BASE" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":20,"method":"tools/call","params":{"name":"github_create_pr","arguments":{"repo":"test","title":"test"}}}' 2>&1 || true)
check "github_create_pr denied by policy: -32000" "denied by policy" "$resp"

resp=$(curl -s -X POST "$BASE" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":21,"method":"tools/call","params":{"name":"pagerduty_resolve","arguments":{"incident_id":"P123"}}}' 2>&1 || true)
check "pagerduty_resolve denied by policy: -32000" "denied by policy" "$resp"

echo ""
echo "[non-JSON traffic — passed through as-is]"

resp=$(curl -sf "$BASE" 2>&1 || true)
check "GET / passed through (non-JSON-RPC)" "" "$resp"

echo ""
echo "=== Results: $PASS passed, $FAIL failed ==="
[ "$FAIL" -eq 0 ] || exit 1
