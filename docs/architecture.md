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
       ├─ 3. CIRCUIT BREAKER ──► Session within limits?
       │   no? ──► Audit "circuit.tripped" ──► Return -32002 (circuit open)
       │
       ├─ 4. INTEGRITY (opt-in) ──► Session binding + replay detection
       │   fail? ──► Audit "identity.failed" ──► Return -32001
       │
       ├─ 5. POLICY ──► Evaluate rules top-to-bottom, first match wins
       │   Rules can have when: conditions (identity type, provider, claims)
       │   denied? ──► Audit "tool.denied" ──► Return -32000 (policy denied)
       │
       └─ 6. FORWARD ──► Audit "tool.allowed" ──► Proxy to upstream
```

---

## Decision Chain

The gates are evaluated in order. Each gate is independent — a request must pass all of them to reach the upstream.

```text
           ┌─────────────┐     ┌──────────────┐     ┌──────────────┐     ┌────────────┐
Request ──►│  REGISTRY    │────►│  CIRCUIT BRK │────►│  INTEGRITY   │────►│   POLICY   │──► Upstream
           │              │     │              │     │  (opt-in)    │     │            │
           │ Is tool name │     │ Session call │     │ Session bind │     │ First-match│
           │ registered?  │     │ count + time │     │ + replay chk │     │ ALLOW/DENY │
           │              │     │ within limit?│     │              │     │ + when:    │
           └──────┬───────┘     └──────┬───────┘     └──────┬───────┘     └─────┬──────┘
                  │ NO                 │ NO                  │ FAIL              │ NO MATCH
                  ▼                    ▼                     ▼                   ▼
              -32003               -32002                -32001              -32000
           "not registered"    "circuit open"       "integrity fail"   "denied by policy"
```

Why this order:
1. **Registry first** — cheapest check. HashMap lookup. Rejects obviously wrong tool names before doing anything else.
2. **Circuit breaker second** — protects the policy engine and upstream from runaway agents. If a session is already over limits, don't bother evaluating policy.
3. **Integrity third** (opt-in) — session binding and replay detection. Only runs if `integrity.enabled: true`.
4. **Policy last** — most expensive check. Rule iteration with when-condition evaluation. Only runs for registered tools within circuit and integrity limits.

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
| `pkg/credentials` | Secret provider interface for credential injection (env/static for now, Vault/ASM future). |
| `api/v1alpha1` | Go type definitions for NullfieldPolicy, ToolRegistry, and related CRD structures. |
| `internal/config` | Environment variable loading with defaults and validation. |

---

## Layered Security Model

nullfield implements defense in depth through four planned layers:

```text
┌─────────────────────────────────────────────────────┐
│  L4: Agentic Flow Control (future)                  │
│  Identity chaining, human-in-the-loop approval,     │
│  call chain tracing, delegation depth limits         │
├─────────────────────────────────────────────────────┤
│  L3: Tool Governance (future)                       │
│  Registration workflow, approval gates,              │
│  tool lifecycle, rug-pull detection                  │
├─────────────────────────────────────────────────────┤
│  L2: Identity-Aware Policy (future)                 │
│  Different rules for human vs agent vs autonomous,   │
│  tenant scoping, identity type in policy rules       │
├─────────────────────────────────────────────────────┤
│  L1: Traffic Enforcement (implemented)              │
│  Tool registry, policy engine, circuit breaker,      │
│  structured audit, rate limiting                     │
└─────────────────────────────────────────────────────┘
```
