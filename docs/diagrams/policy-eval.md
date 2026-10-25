# Policy Evaluation Chain

How nullfield decides whether to forward or reject a `tools/call` request.

Most of this describes proxy mode; see [Two Entries, Different Chains](#two-entries-different-chains)
for which gates the `ext_authz` decision service shares with it. Companions:
[traffic-flow.md](traffic-flow.md) and [mesh-arbiter.md](mesh-arbiter.md).

---

## The Nine Gates

```text
tools/call request
        │
        ▼
┌───────────────────────────────────┐
│  GATE 1: IDENTITY                 │
│                                   │
│  Valid identity token?            │
│                                   │
│  YES ──► continue                 │
│  NO  ──► -32001 identity failed   │
└───────────────┬───────────────────┘
                │
                ▼
┌───────────────────────────────────┐
│  GATE 2: REGISTRY                 │
│                                   │
│  Tool name in approved registry?  │
│                                   │
│  YES ──► continue                 │
│  NO  ──► -32003 not registered    │
└───────────────┬───────────────────┘
                │
                ▼
┌───────────────────────────────────┐
│  GATE 3: INTEGRITY (opt-in)       │
│                                   │
│  Session binding: same identity?  │
│  Replay detection: JTI reused?    │
│  Claims drift: scopes changed?    │
│                                   │
│  PASS ──► continue                │
│  FAIL ──► -32001 integrity fail   │
└───────────────┬───────────────────┘
                │
                ▼
┌───────────────────────────────────┐
│  GATE 4: CIRCUIT BREAKER          │
│                                   │
│  Session within call count        │
│  and duration limit?              │
│                                   │
│  YES ──► continue                 │
│  NO  ──► -32002 circuit open      │
└───────────────┬───────────────────┘
                │
                ▼
┌───────────────────────────────────┐
│  GATE 5: POLICY ENGINE            │
│                                   │
│  Walk rules top-to-bottom.        │
│  First matching rule wins.        │
│                                   │
│  ALLOW  ──► continue to gate 6    │
│  DENY   ──► -32000 policy denied  │
│  HOLD   ──► park for approval     │
│    ├─ approved ──► continue       │
│    ├─ denied   ──► -32000         │
│    └─ timeout  ──► -32005         │
│  SCOPE  ──► modify, continue      │
│  BUDGET ──► continue to gate 6    │
│  NO MATCH ──► -32000 default deny │
└───────────────┬───────────────────┘
                │
                ▼
┌───────────────────────────────────┐
│  GATE 6: BUDGET CHECK             │
│                                   │
│  If rule has budget: block,       │
│  is identity/session in quota?    │
│                                   │
│  WITHIN LIMITS ──► continue       │
│  EXHAUSTED ──► -32004 rate limit  │
└───────────────┬───────────────────┘
                │
                ▼
┌───────────────────────────────────┐
│  GATE 7: VELOCITY / ANOMALY      │
│  (opt-in)                         │
│                                   │
│  Per-identity call rate within    │
│  anomaly threshold?               │
│                                   │
│  NORMAL ──► continue              │
│  SPIKE + LOG  ──► alert, continue │
│  SPIKE + DENY ──► -32004          │
└───────────────┬───────────────────┘
                │
                ▼
┌───────────────────────────────────┐
│  GATE 8: AUDIT                    │
│                                   │
│  Emit structured event:           │
│  tool.allowed or scope.modified   │
└───────────────┬───────────────────┘
                │
                ▼
┌───────────────────────────────────┐
│  GATE 9: FORWARD                  │
│                                   │
│  Proxy request to upstream.       │
│  If SCOPE response config set,    │
│  redact patterns on the way back. │
└───────────────────────────────────┘
```

---

## The Five Actions

The policy engine (gate 5) produces one of five actions:

| Action | Behavior |
|--------|----------|
| ALLOW | Forward the request immediately |
| DENY | Reject with -32000 |
| HOLD | Park request, notify human, wait for approval/timeout |
| SCOPE | Modify request args (strip/inject), redact response patterns |
| BUDGET | Allow but enforce per-identity/session call + token quotas |

These compose. A single request may trigger multiple actions (e.g. SCOPE + BUDGET on the same rule).

---

## Rule Matching Logic

```text
For each rule in policy.rules:
    │
    ├─ Does rule.mcpMethod match the request method?
    │   NO  ──► skip this rule
    │
    ├─ Does rule.toolNames contain the tool name (or "*")?
    │   NO  ──► skip this rule
    │
    ├─ Does rule.when match the identity (type, provider, claims)?
    │   NO  ──► skip this rule
    │
    ├─ Does rule.celExpression evaluate to true?
    │   NO    ──► skip this rule
    │   ERROR ──► DENY (expression_error), never skip
    │
    ├─ Does rule.requireIdentity == true and identity is nil?
    │   YES ──► DENY (identity required but missing)
    │
    └─ MATCH FOUND
        ├─ rule.action == ALLOW  ──► forward (check budget if present)
        ├─ rule.action == DENY   ──► reject
        ├─ rule.action == HOLD   ──► park for approval
        ├─ rule.action == SCOPE  ──► modify and forward
        └─ rule.budget present   ──► check quota, then forward or reject

No rule matched? ──► DENY (default deny posture)
```

### `celExpression`

A [CEL](https://cel.dev) expression over one variable, `request`. It must
compile and return a bool, or the policy refuses to load.

| Field | Value |
|---|---|
| `request.method` | MCP method, e.g. `tools/call` |
| `request.tool` | tool name |
| `request.arguments` | the call's arguments, as a map |
| `request.transport` | `A` for MCP, `B` for wire API traffic |
| `request.target` | host acted on; set by ext_authz, empty on the proxy |
| `request.operation` | `METHOD /path`; set by ext_authz, empty on the proxy |
| `request.identity` | `subject`, `issuer`, `type`, `provider`, `scopes`, `groups`, `claims`; absent when unauthenticated |

```yaml
- action: ALLOW
  celExpression: >-
    request.target == "api.github.com" &&
    request.operation.startsWith("GET ") &&
    has(request.identity) && "sre" in request.identity.groups
```

An expression that errors refuses the call instead of skipping the rule, so
a missing key on a DENY rule cannot fall through to a looser ALLOW. Guard
optional fields with `has()`. Evaluation is cost-limited, since arguments
are caller-supplied.

---

## Audit Events

Every gate decision emits a structured audit event:

| Gate | Pass event | Fail event |
|------|-----------|------------|
| Identity | (implicit — continues) | `identity.failed` |
| Registry | (implicit — continues) | `tool.denied` (reason: "not registered") |
| Integrity | (implicit — continues) | `identity.failed` (reason: integrity violation) |
| Circuit Breaker | (implicit — continues) | `circuit.tripped` |
| Policy | `tool.allowed` | `tool.denied` (reason: "denied by policy") |
| Budget | (implicit — continues) | `tool.denied` (reason: "budget exhausted") |
| Velocity | `anomaly.velocity` (alert) | `tool.denied` (reason: "velocity limit") |
| HOLD | `hold.created` / `hold.approved` | `tool.denied` (reason: "hold denied/timeout") |
| SCOPE | `scope.modified` | `tool.denied` (reason: "scope violation") |

Non-`tools/call` methods emit `mcp.request` and are forwarded without gate evaluation.

---

## Two Entries, Different Chains

Everything above describes **proxy mode**. The `ext_authz` decision service runs
the same registry, policy, budget and velocity gates — one implementation,
`pkg/gates`, shared by both — but not the rest, and the difference is not
cosmetic: assuming all nine apply there would be a security error.

```text
  PROXY MODE (:9090)                    EXT_AUTHZ MODE (:9191)
  in the request path                   beside it

  HTTP request                          Envoy CheckRequest
       │                                     │
       │                                     ▼
       │                              ┌──────────────┐
       │                              │  TRANSLATE   │  extract attributes
       │                              │  ATTEST      │  workload identity
       │                              │  TRUNCATION  │  is the body whole?
       │                              └──────┬───────┘  no ──► refuse to decide
       ▼                                     │
  1. IDENTITY      (token)              ─────┤  not run
  2. REGISTRY  ◄──────────────────────────►  REGISTRY  (MCP calls only)
  3. INTEGRITY                          ─────┤  not run
  4. CIRCUIT                            ─────┤  not run
       │                                     │
  5. POLICY  ◄─── the same engine, ─────►  POLICY
       │          the same rules            │
  6. BUDGET    ◄──────────────────────────►  BUDGET    (per workload)
  7. VELOCITY  ◄──────────────────────────►  VELOCITY  (per workload)
       │                                     │
       ▼                                     ▼
  8. AUDIT  tool.allowed/denied         AUDIT  arbiter.decision
       │                                      + provenance
       ▼                                      + counterfactual
  9. FORWARD to upstream                      │
       │                                      ▼
       ▼                                 OK / Denied to Envoy
  SCOPE the response                     (Envoy forwards or blocks)
```

### Why the difference

| Gate | Absent from `ext_authz` because |
|------|--------------------------------|
| Identity | Superseded, not missing. The caller is attested from the mesh instead of presenting a token — a stronger claim, established earlier. |
| Integrity, Circuit | Both are keyed on the MCP session, which the mesh does not carry. |
| SCOPE / response | Structurally impossible: `ext_authz` sees requests only and cannot mutate them. Needs `ext_proc`. |

The gates that do run differ in two ways:

- **Registry** runs only when `NULLFIELD_REGISTRY_PATH` is set, and only on calls
  that name an MCP tool. A direct API call names none, so it reaches policy.
- **Budget and velocity** are charged to the attested workload principal. A rule
  whose budget is `perSession` refuses every call here, because there is no
  session to charge it to; so does a `perIdentity` budget when the caller could
  not be attested. A limit that cannot be charged refuses the call rather than
  being skipped.

### Gate values in the audit trail

`arbiter.decision` events carry a `gate` field with one of:

```text
translate   the request could not be read whole (body_truncated)
registry    the tool is not in the registry
policy      the rule engine decided
budget      the matched rule's budget is exhausted or cannot be charged
anomaly     call velocity exceeded a DENY threshold
```

A `velocity_limit` alert that only logs is a separate `anomaly.velocity` event.
A `gate` value the proxy can emit but this path cannot (`circuit`, `hold`,
`inspection`) is a sign the event came from the other front door.

See [mesh-arbiter.md](mesh-arbiter.md) for identity, modes, and the buffer
boundary.
