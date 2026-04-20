# Sidecar Mode — Docker Compose

Deploy nullfield as a sidecar proxy in front of any MCP server using Docker Compose. This is the fastest way to see policy enforcement in action.

## What you'll learn

- **Registry filtering** — requests for unregistered tools are rejected before reaching your MCP server
- **Policy enforcement** — tiered allow/deny rules control which tools can be called
- **Audit logging** — every decision is logged with tool name, action, and reason

## Prerequisites

- Docker Engine 20.10+
- Docker Compose v2 (`docker compose` — not the legacy `docker-compose`)

## Step 1: Start the stack

From the nullfield repo root:

```bash
docker compose up -d
```

This starts two containers:
- `echo-server` — a minimal MCP server that responds to any tool call (port 8080, internal only)
- `nullfield` — the sidecar proxy (port 9090 exposed for MCP traffic, port 9091 for admin/metrics)

## Step 2: Verify health

```bash
curl -s http://localhost:9091/healthz
```

Expected output:

```json
{"status":"ok"}
```

## Step 3: Test MCP passthrough

### 3a. Initialize

```bash
curl -s -X POST http://localhost:9090/mcp \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}' | python3 -m json.tool
```

Expected output:

```json
{
    "jsonrpc": "2.0",
    "id": 1,
    "result": {
        "protocolVersion": "2025-03-26",
        "serverInfo": {
            "name": "echo-mcp-server",
            "version": "0.1.0"
        },
        "capabilities": {
            "tools": {}
        }
    }
}
```

### 3b. List tools

```bash
curl -s -X POST http://localhost:9090/mcp \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}' | python3 -m json.tool
```

Expected output:

```json
{
    "jsonrpc": "2.0",
    "id": 2,
    "result": {
        "tools": [
            {
                "name": "echo",
                "description": "Echoes back the input",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "message": {"type": "string"}
                    }
                }
            },
            {
                "name": "github_create_pr",
                "description": "Simulated: create a GitHub PR",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "repo": {"type": "string"},
                        "title": {"type": "string"}
                    }
                }
            },
            {
                "name": "pagerduty_resolve",
                "description": "Simulated: resolve a PagerDuty incident",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "incident_id": {"type": "string"}
                    }
                }
            },
            {
                "name": "dangerous_tool",
                "description": "This tool should be blocked by nullfield policy",
                "inputSchema": {
                    "type": "object",
                    "properties": {}
                }
            }
        ]
    }
}
```

### 3c. Ping

```bash
curl -s -X POST http://localhost:9090/mcp \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":3,"method":"ping","params":{}}' | python3 -m json.tool
```

Expected output:

```json
{
    "jsonrpc": "2.0",
    "id": 3,
    "result": {}
}
```

## Step 4: Test registry enforcement

Call a tool that isn't in the registry (`tools.yaml`). Nullfield rejects it immediately — the request never reaches the echo server.

```bash
curl -s -X POST http://localhost:9090/mcp \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"admin.drop_tables","arguments":{}}}' | python3 -m json.tool
```

Expected output:

```json
{
    "jsonrpc": "2.0",
    "id": 4,
    "error": {
        "code": -32003,
        "message": "tool not registered: admin.drop_tables"
    }
}
```

## Step 5: Test policy enforcement

### 5a. Call an allowed tool

The `echo` tool is registered AND allowed by policy:

```bash
curl -s -X POST http://localhost:9090/mcp \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"echo","arguments":{"message":"hello nullfield"}}}' | python3 -m json.tool
```

Expected output:

```json
{
    "jsonrpc": "2.0",
    "id": 5,
    "result": {
        "content": [
            {
                "type": "text",
                "text": "echo-server executed tool=\"echo\" args=map[message:hello nullfield] at 2026-04-19T..."
            }
        ]
    }
}
```

### 5b. Call a denied tool

The `dangerous_tool` is registered in the echo server's response, but the policy's wildcard deny rule (`toolNames: ["*"]`) blocks everything not explicitly allowed:

```bash
curl -s -X POST http://localhost:9090/mcp \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"dangerous_tool","arguments":{}}}' | python3 -m json.tool
```

Expected output:

```json
{
    "jsonrpc": "2.0",
    "id": 6,
    "error": {
        "code": -32000,
        "message": "denied by policy: tool dangerous_tool matched deny rule"
    }
}
```

## Step 6: Check metrics

```bash
curl -s http://localhost:9091/metrics | grep nullfield_
```

Expected output (subset):

```
nullfield_requests_total{method="initialize",action="allow"} 1
nullfield_requests_total{method="tools/call",action="allow",tool="echo"} 1
nullfield_requests_total{method="tools/call",action="deny",tool="dangerous_tool"} 1
nullfield_requests_total{method="tools/call",action="reject_unregistered",tool="admin.drop_tables"} 1
nullfield_policy_evaluations_total{result="allow"} 1
nullfield_policy_evaluations_total{result="deny"} 1
nullfield_registry_rejections_total 1
nullfield_upstream_latency_seconds_bucket{le="0.01"} ...
```

## Step 7: Check audit logs

```bash
docker compose logs nullfield | grep audit
```

Expected output (one line per decision):

```
nullfield-1  | {"level":"info","msg":"audit","event":"tool.allowed","tool":"echo","method":"tools/call","reason":"matched allow rule"}
nullfield-1  | {"level":"info","msg":"audit","event":"tool.denied","tool":"dangerous_tool","method":"tools/call","reason":"matched deny rule: wildcard"}
nullfield-1  | {"level":"info","msg":"audit","event":"tool.rejected","tool":"admin.drop_tables","method":"tools/call","reason":"tool not registered"}
```

## Step 8: Customize

To use your own policy and tool registry, edit the volume mounts in `docker-compose.yaml`:

```yaml
volumes:
  - ./my-config/policy.yaml:/etc/nullfield/policy.yaml:ro
  - ./my-config/tools.yaml:/etc/nullfield/tools.yaml:ro
```

Or override with environment variables for quick testing:

```bash
NULLFIELD_POLICY_PATH=/etc/nullfield/policy.yaml \
NULLFIELD_REGISTRY_PATH=/etc/nullfield/tools.yaml \
docker compose up -d
```

Policy format reference — see `examples/policy.yaml` in the repo.

## Cleanup

```bash
docker compose down
```

## Next steps

- [Demo 05 — Sidecar on Kubernetes](../05-sidecar-kubernetes/) — deploy to any K8s cluster with ConfigMap-based policy
- Demo 06 — HOLD mode (human-in-the-loop approval) — coming soon
- Demo 07 — Budget enforcement (token/cost limits per session) — coming soon
