# nullfield — Architecture

How nullfield works internally: the request lifecycle, the decision chain, and what each package is responsible for.

---

## Request Lifecycle

Every HTTP request to nullfield follows this path:

```text
HTTP Request arrives (:9090)
  │
  ├─ Not JSON-RPC? ──► Forward to upstream as-is (passthrough)
  │
  ├─ JSON-RPC but not tools/call? ──► Audit log ──► Forward to upstream
  │   (initialize, tools/list, ping, etc.)
  │
  └─ JSON-RPC tools/call ──► Decision Chain
       │
       ├─ 1. IDENTITY ──► Extract + verify Bearer token
       │   fail? ──► Return -32001 (identity failed)
       │
       ├─ 2. REGISTRY ──► Is the tool name in the registry?
       │   no? ──► Audit "tool.denied" ──► Return -32003 (not registered)
       │
       ├─ 3. INTEGRITY (opt-in) ──► Session binding + replay detection
       │   fail? ──► Audit "identity.failed" ──► Return -32001
       │
       ├─ 4. CIRCUIT BREAKER ──► Session within limits?
       │   no? ──► Audit "circuit.tripped" ──► Return -32002 (circuit open)
       │
       ├─ 5. POLICY ENGINE ──► Evaluate rules top-to-bottom, first match:
       │   DENY → -32000 | HOLD → park | SCOPE → modify | ALLOW → continue
       │
       ├─ 6. BUDGET CHECK ──► If budget: block on matched rule
       │   exhausted? ──► Return -32004
       │
       ├─ 7. VELOCITY CHECK ──► Anomaly detection (opt-in)
       │   spike? ──► Log alert or Return -32004
       │
       ├─ 8. AUDIT ──► Emit "tool.allowed" event
       │
       └─ 9. FORWARD ──► Proxy to upstream (SCOPE response on return)
```

---

## Decision Chain

The gates are evaluated in order. Each gate is independent — a request must pass all of them to reach the upstream.

```text
           ┌──────────┐  ┌──────────┐  ┌───────────┐  ┌───────────┐  ┌────────┐  ┌────────┐  ┌──────────┐
Request ──►│ IDENTITY │─►│ REGISTRY │─►│ INTEGRITY │─►│ CIRCUIT   │─►│ POLICY │─►│ BUDGET │─►│ VELOCITY │─► Audit ─► Forward
           └────┬─────┘  └────┬─────┘  └─────┬─────┘  └─────┬─────┘  └───┬────┘  └───┬────┘  └────┬─────┘
                │ FAIL         │ NO           │ FAIL          │ NO          │ DENY      │ EXHAUSTED  │ SPIKE
                ▼              ▼              ▼               ▼             ▼           ▼            ▼
            -32001         -32003         -32001          -32002        -32000      -32004       -32004
```

Why this order:
1. **Identity first** — must know who is calling before any other check.
2. **Registry second** — cheapest check. HashMap lookup. Rejects unregistered tool names immediately.
3. **Integrity third** (opt-in) — session binding and replay detection. Only runs if configured.
4. **Circuit breaker fourth** — protects the policy engine and upstream from runaway agents.
5. **Policy fifth** — most expensive check. Rule iteration with when-condition evaluation. Produces ALLOW/DENY/HOLD/SCOPE/BUDGET.
6. **Budget sixth** — if the matched rule has a budget: block, enforce quotas.
7. **Velocity seventh** (opt-in) — anomaly detection. Alerts or denies on rate spikes.

---

## Package Responsibilities

| Package | Responsibility |
|---------|---------------|
| `cmd/nullfield` | Entrypoint. Loads config, wires dependencies, starts HTTP servers. |
| `pkg/proxy` | MCP JSON-RPC parsing (`mcp.go`). Reverse proxy handler with decision chain (`handler.go`). |
| `pkg/identity` | Extract Bearer token from request header. Verify identity (noop in dev, JWKS in prod). Context propagation. |
| `pkg/registry` | File-backed tool allowlist. Thread-safe for hot-reload. IsRegistered() is the gate. |
| `pkg/circuit` | Per-session call count + duration tracking. Allow/Record/Sweep lifecycle. |
| `pkg/policy` | Rule engine interface (`engine.go`). First-match ALLOW/DENY evaluator (`rules.go`). YAML policy loader (`loader.go`). |
| `pkg/audit` | Structured JSON event emitter. Event types: mcp.request, tool.allowed, tool.denied, identity.failed, circuit.tripped. |
| `pkg/credentials` | Secret provider interface for credential injection (env, static, Vault). |
| `pkg/anomaly` | Velocity tracker — per-identity tool call rate detection with sliding window. |
| `api/v1alpha1` | Go type definitions for NullfieldPolicy, ToolRegistry, and related CRD structures. |
| `internal/config` | Environment variable loading with defaults and validation. |

---

## Controller vs Sidecar

nullfield splits responsibilities between two components:

**Sidecar** — stateless enforcement, runs per-pod. Handles identity verification, registry checks, integrity, circuit breaker, policy evaluation, and audit logging. All decisions that can be made locally stay local. If the controller is unreachable, the sidecar continues to enforce policy independently.

**Controller** — stateful coordination, runs once per cluster. Handles holds, shared budgets, webhook alerting, event aggregation, and the unified admin dashboard. Sidecars delegate to the controller via gRPC when `NULLFIELD_CONTROLLER_ADDR` is set.

```text
┌──────────┐   ┌──────────┐   ┌──────────┐
│ Sidecar  │   │ Sidecar  │   │ Sidecar  │
│ (pod A)  │   │ (pod B)  │   │ (pod C)  │
└────┬─────┘   └────┬─────┘   └────┬─────┘
     │              │              │
     │    gRPC      │    gRPC      │    gRPC
     └──────────────┼──────────────┘
                    ▼
          ┌─────────────────┐
          │   Controller    │
          │                 │
          │  holds, budgets │
          │  events, alerts │
          │  admin API      │
          └─────────────────┘
```

### gRPC communication

The sidecar connects to the controller via the `NullfieldController` gRPC service (defined in `api/v1alpha1/proto/controller.proto`). RPCs:

| RPC | Purpose |
|-----|---------|
| `RegisterSidecar` | Sidecar announces itself on startup (target name, pod identity) |
| `CreateHold` | Sidecar delegates a HOLD decision to the controller |
| `CheckBudget` | Sidecar checks/increments a shared budget counter |
| `ReportEvent` | Sidecar forwards audit events for aggregation and alerting |

### Failure modes

| Scenario | Behavior | Rationale |
|----------|----------|-----------|
| Controller unreachable, BUDGET check | Fail open — allow the call | Availability over precision; local circuit breaker still enforces per-session limits |
| Controller unreachable, HOLD check | Fail closed — deny the call | HOLD exists to gate dangerous actions; allowing without approval defeats the purpose |
| Controller unreachable, event reporting | Fail open — log locally, drop gRPC send | Audit events are still emitted to stdout; alerting degrades but enforcement doesn't |

---

## Layered Security Model

nullfield implements defense in depth through four layers:

```text
┌─────────────────────────────────────────────────────┐
│  L4: Agentic Flow Control                           │
│  Identity chaining, human-in-the-loop approval,     │
│  call chain tracing, delegation depth limits         │
├─────────────────────────────────────────────────────┤
│  L3: Tool Governance                                │
│  Registration workflow, approval gates,              │
│  tool lifecycle, rug-pull detection                  │
├─────────────────────────────────────────────────────┤
│  L2: Identity-Aware Policy (implemented)             │
│  Different rules for human vs agent vs autonomous,   │
│  tenant scoping, identity type in policy rules       │
├─────────────────────────────────────────────────────┤
│  L1: Traffic Enforcement (implemented)              │
│  Tool registry, policy engine, circuit breaker,      │
│  structured audit, rate limiting                     │
└─────────────────────────────────────────────────────┘
```
