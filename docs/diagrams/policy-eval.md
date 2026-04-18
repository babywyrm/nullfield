# Policy Evaluation Chain

How nullfield decides whether to forward or reject a `tools/call` request.

---

## The Three Gates

```text
tools/call request
    │
    ▼
┌─────────────────────────────────┐
│  GATE 1: IDENTITY               │
│                                  │
│  Is there a valid identity       │
│  token on this request?          │
│                                  │
│  YES ──► continue                │
│  NO  ──► -32001 identity failed  │
└─────────────┬───────────────────┘
              │
              ▼
┌─────────────────────────────────┐
│  GATE 2: REGISTRY               │
│                                  │
│  Is this tool name in the        │
│  approved tool registry?         │
│                                  │
│  YES ──► continue                │
│  NO  ──► -32003 not registered   │
└─────────────┬───────────────────┘
              │
              ▼
┌─────────────────────────────────┐
│  GATE 3: CIRCUIT BREAKER        │
│                                  │
│  Is this session within the      │
│  call count + duration limit?    │
│                                  │
│  YES ──► continue                │
│  NO  ──► -32002 circuit open     │
└─────────────┬───────────────────┘
              │
              ▼
┌─────────────────────────────────┐
│  GATE 4: POLICY ENGINE          │
│                                  │
│  Walk rules top-to-bottom.       │
│  First matching rule wins.       │
│                                  │
│  ALLOW ──► forward to upstream   │
│  DENY  ──► -32000 policy denied  │
│  NO MATCH ──► -32000 default deny│
└─────────────────────────────────┘
```

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
    ├─ Does rule.requireIdentity == true and identity is nil?
    │   YES ──► DENY (identity required but missing)
    │
    └─ MATCH FOUND
        ├─ rule.action == ALLOW ──► forward request
        └─ rule.action == DENY  ──► reject request

No rule matched? ──► DENY (default deny posture)
```

---

## Audit Events

Every gate decision emits a structured audit event:

| Gate | Pass event | Fail event |
|------|-----------|------------|
| Identity | (implicit — continues to next gate) | `identity.failed` |
| Registry | (implicit — continues to next gate) | `tool.denied` (reason: "not registered") |
| Circuit Breaker | (implicit — continues to next gate) | `circuit.tripped` |
| Policy | `tool.allowed` | `tool.denied` (reason: "denied by policy/rule") |

Non-`tools/call` methods emit `mcp.request` and are forwarded without gate evaluation.
