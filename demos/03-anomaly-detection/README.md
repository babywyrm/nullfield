# Demo 03: Anomaly Detection

Detect and respond to suspicious patterns in MCP tool call traffic: session binding violations, token replay, and tool call velocity spikes.

## Patterns covered

### 1. Session binding violation

When `integrity.bindToSession: true`, nullfield tracks which identity is associated with each MCP session. If the identity changes mid-session, the request is rejected.

**How to trigger:**

```bash
# Start a session with one identity
curl -s -X POST http://localhost:9090/mcp \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $(cat demos/02-jwt-identity-tracking/human-token.txt)" \
  -H "Mcp-Session-Id: session-123" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"cost.check_usage","arguments":{}}}'

# Then try to use the same session with a different identity
curl -s -X POST http://localhost:9090/mcp \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $(cat demos/02-jwt-identity-tracking/agent-token.txt)" \
  -H "Mcp-Session-Id: session-123" \
  -d '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"cost.check_usage","arguments":{}}}'
```

**Expected:** Second request rejected with `-32001` "integrity check failed: identity changed mid-session."

**What this catches:** An LLM or intermediate agent swapping out the caller context to escalate privileges.

### 2. Token replay

When `integrity.detectReplay: true`, nullfield tracks the JTI (JWT ID) of each token. If the same JTI appears twice, the second request is rejected.

**How to trigger:**

```bash
TOKEN=$(cat demos/02-jwt-identity-tracking/human-token.txt)

# First use — allowed
curl -s -X POST http://localhost:9090/mcp \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"cost.check_usage","arguments":{}}}'

# Same token again — rejected (same JTI)
curl -s -X POST http://localhost:9090/mcp \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"cost.check_usage","arguments":{}}}'
```

**Expected:** Second request rejected with `-32001` "integrity check failed: token replay detected."

**What this catches:** Captured tokens being reused by an attacker or a compromised agent.

### 3. Velocity spike (requires anomaly.enabled — see below)

When anomaly detection is enabled, nullfield tracks the rate of tool calls per identity. If the rate exceeds the threshold, an alert is emitted.

**Policy config:**

```yaml
anomaly:
  enabled: true
  velocity:
    threshold: 5       # calls per minute per identity
    alertAction: LOG   # LOG = alert but allow, DENY = block
```

**How to trigger:**

```bash
TOKEN=$(cat demos/02-jwt-identity-tracking/human-token.txt)
for i in $(seq 1 10); do
  curl -s -X POST http://localhost:9090/mcp \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer $TOKEN" \
    -d "{\"jsonrpc\":\"2.0\",\"id\":$i,\"method\":\"tools/call\",\"params\":{\"name\":\"cost.check_usage\",\"arguments\":{}}}" &
done
wait
```

**Expected:** After the 5th call in a minute, audit log shows `anomaly.velocity` events.

**What this catches:** Runaway agent loops, automated abuse, compromised credentials being used at scale.

## Audit log patterns

Check the nullfield logs for these event types:

```bash
# Session binding violations
kubectl -n camazotz logs -l app=brain-gateway -c nullfield | grep "identity.failed"

# Velocity alerts
kubectl -n camazotz logs -l app=brain-gateway -c nullfield | grep "anomaly.velocity"

# All denials
kubectl -n camazotz logs -l app=brain-gateway -c nullfield | grep "tool.denied"
```

## Prerequisites

- Complete Demo 02 first (generates the test keys and tokens)
- nullfield running with the JWT demo policy (`demos/02-jwt-identity-tracking/policy.yaml`)

## Key files

- `demos/02-jwt-identity-tracking/policy.yaml` — identity + integrity config
- `docs/identity-policy.md` — full configuration guide
- `docs/observability.md` — metrics and monitoring
