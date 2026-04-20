# Controller Mode — Centralized Holds, Budgets, and Admin

Deploy the nullfield controller alongside a sidecar to get centralized hold management, shared budget enforcement, and a unified admin API.

## What you'll learn

- Deploying the controller alongside sidecars using Docker Compose
- Centralized hold management — approve/deny holds from the controller admin API
- Shared budget enforcement — a single budget counter regardless of how many sidecars are running
- Unified admin API — one place to see all events, holds, budgets, and connected sidecars

## Architecture

```text
┌─────────────┐     ┌──────────────┐     ┌───────────────────────┐
│ echo-server │◄────│  nullfield   │────►│ nullfield-controller  │
│   :8080     │     │  (sidecar)   │gRPC │                       │
└─────────────┘     │  :9090 :9091 │     │ gRPC  :9092           │
                    └──────────────┘     │ Admin :9093           │
                                         │ Health:9091           │
                                         └───────────────────────┘
```

The sidecar handles all local decisions (registry, identity, circuit breaker, policy evaluation). When a rule triggers HOLD or BUDGET, the sidecar delegates to the controller via gRPC.

## Prerequisites

- Docker and Docker Compose
- nullfield repository cloned

## Step 1: Start the stack

```bash
docker compose -f demos/09-controller-mode/docker-compose.yaml up -d --build
```

Wait for all three containers to become healthy:

```bash
docker compose -f demos/09-controller-mode/docker-compose.yaml ps
```

Expected output:

```
NAME                      SERVICE                STATUS
...-echo-server-1         echo-server            running
...-nullfield-1           nullfield              running (healthy)
...-nullfield-controller  nullfield-controller   running (healthy)
```

## Step 2: Verify the controller is up

```bash
curl -s http://localhost:9093/healthz
```

Expected:

```
ok
```

## Step 3: Check sidecar registration

When the sidecar starts with `NULLFIELD_CONTROLLER_ADDR` set, it registers itself with the controller. Verify:

```bash
curl -s http://localhost:9093/admin/targets | python3 -m json.tool
```

Expected (one registered sidecar):

```json
[
    {
        "id": "...",
        "addr": "...",
        "registered_at": "...",
        "last_heartbeat": "..."
    }
]
```

## Step 4: Test a HOLD

The policy puts `delegation.invoke_agent` and `config.update_settings` under a HOLD rule — the request is parked until a human approves or the 5-minute timeout expires.

### 4a. Send a held tool call

In one terminal, send a request that will be held. This call blocks until the hold is resolved:

```bash
curl -s -X POST http://localhost:9090/mcp \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"delegation.invoke_agent","arguments":{"target":"agent-7"}}}' &
HOLD_PID=$!
echo "Request is waiting (PID $HOLD_PID)..."
```

### 4b. List holds on the controller

In a second terminal, list the pending holds:

```bash
curl -s http://localhost:9093/admin/holds | python3 -m json.tool
```

Expected:

```json
[
    {
        "id": "<hold-id>",
        "tool": "delegation.invoke_agent",
        "status": "pending",
        "created_at": "...",
        "timeout": "5m0s"
    }
]
```

Copy the `id` value from the response.

### 4c. Approve the hold via the controller

```bash
curl -s -X POST http://localhost:9093/admin/holds/<hold-id>/approve \
  -H "X-Approver: demo-admin" | python3 -m json.tool
```

Expected:

```json
{
    "status": "approved",
    "hold": "<hold-id>"
}
```

The curl from step 4a should now return the echo-server response. The hold was managed entirely through the controller's admin API.

### 4d. Verify the hold resolved

```bash
curl -s http://localhost:9093/admin/holds | python3 -m json.tool
```

Expected: empty list `[]` (or the hold now shows `status: approved`).

## Step 5: Test BUDGET

The policy limits `llm.generate_summary` to 5 calls per session per hour. This budget is tracked centrally by the controller — adding more sidecars doesn't multiply the quota.

### 5a. Use up the budget

```bash
for i in $(seq 1 6); do
  echo "--- Call $i ---"
  curl -s -X POST http://localhost:9090/mcp \
    -H "Content-Type: application/json" \
    -d "{\"jsonrpc\":\"2.0\",\"id\":$i,\"method\":\"tools/call\",\"params\":{\"name\":\"llm.generate_summary\",\"arguments\":{\"text\":\"hello\"}}}" | python3 -m json.tool
  echo
done
```

Expected: calls 1–5 succeed. Call 6 is rejected:

```json
{
    "jsonrpc": "2.0",
    "id": 6,
    "error": {
        "code": -32004,
        "message": "budget exceeded: maxCallsPerHour (session)"
    }
}
```

### 5b. Check budget usage on the controller

```bash
curl -s http://localhost:9093/admin/budgets | python3 -m json.tool
```

Expected: shows the budget counter at 5/5.

## Step 6: Check the unified event stream

Every decision — allow, deny, hold, budget — is reported to the controller:

```bash
curl -s http://localhost:9093/admin/events | python3 -m json.tool
```

Expected: a list of events from all the calls above, including `tool.allowed`, `tool.denied`, `tool.held`, and `budget.exceeded` events.

Filter by type:

```bash
curl -s "http://localhost:9093/admin/events?type=tool.held" | python3 -m json.tool
```

## Step 7: What's different from sidecar-only mode

| Capability | Sidecar-only | With controller |
|---|---|---|
| HOLD management | Local — approve via sidecar's own admin port (`:9091`) | Centralized — approve via controller admin (`:9093`) |
| BUDGET tracking | Per-sidecar — each sidecar has its own counters | Shared — one counter across all sidecars |
| Event stream | Per-sidecar logs | Unified — controller aggregates all events |
| Admin dashboard | One per sidecar | One for the entire cluster |
| Connected sidecars | N/A | `/admin/targets` shows all registered sidecars |
| Failure mode | Fully independent | Sidecar falls back to local enforcement if controller is unreachable |

The controller is always opt-in. Omit `NULLFIELD_CONTROLLER_ADDR` and the sidecar works exactly as before.

## Cleanup

```bash
docker compose -f demos/09-controller-mode/docker-compose.yaml down -v
```

## Next steps

- [Kubernetes Deployment with Helm](../../deploy/helm/nullfield/) — deploy the controller and sidecars on a real cluster
- [Architecture](../../docs/architecture.md) — how the sidecar ↔ controller gRPC protocol works
- [Implementation Guide](../../docs/implementation-guide.md) — production adoption guide
