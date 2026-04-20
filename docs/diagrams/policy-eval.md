# Policy Evaluation Chain

How nullfield decides whether to forward or reject a `tools/call` request.

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
