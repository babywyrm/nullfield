# Demo 01: Basic Tool Filtering

The foundation — tool registry enforcement, tiered allow/deny policy, circuit breaker, and structured audit trail.

## Setup

Start camazotz (or any MCP server) on port 8080, then start nullfield:

```bash
cd /path/to/nullfield

NULLFIELD_UPSTREAM_ADDR=localhost:8080 \
NULLFIELD_POLICY_PATH=integrations/camazotz/policy.yaml \
NULLFIELD_REGISTRY_PATH=integrations/camazotz/tools.yaml \
./bin/nullfield
```

## What to observe

### 1. Allowed tool (tier 1 — read-only, 60/min)

```bash
curl -s -X POST http://localhost:9090/mcp \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"cost.check_usage","arguments":{}}}' | python3 -m json.tool
```

Expected: real response from camazotz with usage data.

### 2. Blocked tool (tier 3 — high-risk)

```bash
curl -s -X POST http://localhost:9090/mcp \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"secrets.leak_config","arguments":{}}}' | python3 -m json.tool
```

Expected: `{"error":{"code":-32000,"message":"denied by policy: ..."}}`

### 3. Unregistered tool (not in registry at all)

```bash
curl -s -X POST http://localhost:9090/mcp \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"admin.drop_tables","arguments":{}}}' | python3 -m json.tool
```

Expected: `{"error":{"code":-32003,"message":"tool not registered: ..."}}`

### 4. Check the audit trail

In a second terminal:

```bash
# If running as binary:
# (audit logs go to stdout)

# If running on K3s:
kubectl -n camazotz logs -l app=brain-gateway -c nullfield --tail=10
```

Every request shows: event type (`tool.allowed` / `tool.denied`), tool name, identity, reason.

### 5. Run the full demo script

```bash
bash integrations/camazotz/demo.sh
```

17-point automated test covering all tiers.

## How the policy works

```
Request arrives
    │
    ├── Tool in registry?  NO → -32003 (rejected)
    ├── Circuit breaker?   OPEN → -32002 (rejected)
    └── Policy rules (first match wins):
        ├── Tier 1: 25 read-only tools → ALLOW (60/min)
        ├── Tier 2: 25 write tools → ALLOW (20/min)
        ├── Tier 3: 7 high-risk tools → DENY
        └── Default: DENY everything else
```

## Key files

- `integrations/camazotz/tools.yaml` — 57 registered tools
- `integrations/camazotz/policy.yaml` — three-tier policy
- `integrations/camazotz/demo.sh` — 17-point automated test
