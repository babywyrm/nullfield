# Controller Mode — Central Inventory and Events

Deploy the nullfield controller alongside a sidecar to get a fleet-wide view of
what is deployed and what it decided.

> **Read this first.** Controller mode delivers less than its name suggests.
> The sidecar registers its inventory and streams every decision to the
> controller, and both work. **Centralized holds and shared budgets do not.**
> `pkg/hold/remote.go` and `pkg/budget/remote.go` exist and wrap the controller
> client correctly, but nothing in `cmd/` ever constructs them, and
> `HandlerOpts.Holds` is a concrete `*hold.Manager` rather than an interface,
> so the remote implementation could not be substituted even if something
> tried. In controller mode the local hold manager is deliberately left nil, so
> a HOLD rule falls through to an outright deny.
>
> `test.sh` asserts both gaps and is written to **fail** when either is
> implemented, so this page cannot quietly go back to overstating things.

## What you'll learn

- Deploying the controller alongside sidecars using Docker Compose
- Sidecar registration — every sidecar reports its tool and rule inventory
- A unified event stream — one place to see what every sidecar decided
- Where the mode currently stops, and why

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

The sidecar makes every decision locally: registry, identity, circuit breaker,
policy evaluation, holds, and budgets. What travels over gRPC is registration
and the audit event stream, in that one direction.

Delegating HOLD and BUDGET to the controller is the intent of the design and
is not yet wired. Until it is, a second sidecar gets its own budget counters
and its own holds, so the quota is per-replica rather than shared.

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

## Step 4: See where HOLD stops

The policy puts `delegation.invoke_agent` and `config.update_settings` under a
HOLD rule. In sidecar-only mode that parks the request until a human resolves
it. In controller mode it does not.

### 4a. Send a call the policy wants to hold

```bash
curl -s -X POST http://localhost:9090/mcp \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"delegation.invoke_agent","arguments":{"target":"agent-7"}}}' \
  | python3 -m json.tool
```

It returns immediately rather than blocking:

```json
{
    "jsonrpc": "2.0",
    "id": 1,
    "error": {
        "code": -32000,
        "message": "denied by policy: requires human approval"
    }
}
```

### 4b. Confirm nothing was parked

```bash
curl -s http://localhost:9093/admin/holds | python3 -m json.tool
```

Expected: `[]`.

The sidecar's own `/admin/holds` is not there either — in controller mode the
hold admin API is never registered, on the assumption the controller owns it:

```bash
curl -s http://localhost:9091/admin/holds
# 404 page not found
```

### 4c. Why

`cmd/nullfield/main.go` only builds a `hold.Manager` when there is no
controller client, so `h.holds` is nil and the handler's HOLD branch is
skipped entirely. The request falls through to a deny, which the audit trail
records honestly with `reason_class: policy_held`:

```bash
docker compose -f demos/09-controller-mode/docker-compose.yaml logs nullfield \
  | grep policy_held | tail -1
```

`pkg/hold/remote.go` is the missing half. It wraps the controller client and
does the right thing, and nothing constructs it. Substituting it also needs
`HandlerOpts.Holds` to become an interface rather than a concrete
`*hold.Manager`, and needs the resolution to travel back to the sidecar so the
original request can be released.

If you implement this, `test.sh` will start failing on purpose. That is the
signal to update this page.

## Step 5: Test BUDGET

The policy limits `llm.generate_summary` to 5 calls per session per hour. That
limit is enforced, but by the sidecar's own tracker: `GET /admin/budgets` on
the controller stays empty however many calls you make, and a second sidecar
would get a second quota. Tracking it centrally is the intent and is not yet
wired.

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

Expected: `[]`.

The limit was enforced, but by the sidecar's own `budget.Tracker`. The
controller never sees the counter, so a second sidecar would get a second
quota rather than sharing this one. `pkg/budget/remote.go` is the missing half
here, in the same way `pkg/hold/remote.go` is for holds.

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

| Capability | Sidecar-only | With controller | Status |
|---|---|---|---|
| Event stream | Per-sidecar logs | Unified — the controller aggregates every decision | Works |
| Inventory | None | Every sidecar reports its tool and rule counts to `/admin/targets` | Works |
| HOLD management | Local — approve via the sidecar's own admin port (`:9091`) | Intended: approve via controller admin (`:9093`) | **Not wired.** The hold manager is nil in controller mode, so HOLD denies outright |
| BUDGET tracking | Per-sidecar counters | Intended: one counter across all sidecars | **Not wired.** Counters stay local and `/admin/budgets` stays empty |

Sidecar-only mode is the better choice today if you need HOLD, because there
the hold manager exists and `/admin/holds` on the sidecar works. Demo 06 shows
that path end to end.
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
