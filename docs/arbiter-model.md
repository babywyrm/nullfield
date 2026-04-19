# The Arbiter Model

nullfield is not a firewall. It is an arbiter — it decides not just whether a tool call is allowed, but *how* it is allowed, *under what conditions*, and *at what cost*.

---

## The Five Actions

Every tool call that reaches the policy engine results in one of five actions. These are the fundamental verbs of agentic traffic control.

```text
ALLOW    Forward the request immediately.
DENY     Reject the request immediately.
HOLD     Park the request. Notify a human. Wait for approval or timeout.
SCOPE    Allow but modify — strip parameters, inject credentials, redact response.
BUDGET   Allow but track — enforce token limits, call quotas, cost caps.
```

These compose. A single request may pass through multiple actions:

```text
BUDGET check (within quota?)
  → SCOPE (inject credentials, strip dangerous params)
    → HOLD (wait for human approval)
      → ALLOW (forward modified request to upstream)
```

### Comparison to HTTP methods

HTTP methods define what you can do with a resource. nullfield actions define what the arbiter can do with a tool call:

| HTTP | nullfield | Meaning |
|------|-----------|---------|
| GET | ALLOW | Read, forward as-is |
| DELETE | DENY | Reject, never reaches upstream |
| — | HOLD | No HTTP equivalent — async approval gate |
| PATCH | SCOPE | Modify in transit |
| — | BUDGET | No HTTP equivalent — resource accounting |

---

## Decision Chain

```text
Request arrives (:9090)
  │
  ├─ 1. IDENTITY ── verify JWT, extract type/provider/claims
  │    fail → -32001
  │
  ├─ 2. REGISTRY ── is tool name in the approved list?
  │    no → -32003
  │
  ├─ 3. INTEGRITY ── session binding, replay detection (opt-in)
  │    fail → -32001
  │
  ├─ 4. CIRCUIT BREAKER ── session within call/duration limits?
  │    no → -32002
  │
  ├─ 5. POLICY ENGINE ── evaluate rules top-to-bottom, first match:
  │    │
  │    ├─ DENY → -32000, reject with reason
  │    │
  │    ├─ ALLOW → continue to step 6
  │    │
  │    ├─ HOLD → park request
  │    │   ├─ notify (webhook, Slack, admin API)
  │    │   ├─ wait for approval (up to timeout)
  │    │   ├─ approved → continue to step 6
  │    │   ├─ denied → -32000
  │    │   └─ timeout → -32005 (or allow, configurable)
  │    │
  │    ├─ SCOPE → modify request params, continue to step 6
  │    │   (response is also modified on the way back)
  │    │
  │    └─ no match → -32000 (default deny)
  │
  ├─ 6. BUDGET CHECK ── if budget: block on matched rule
  │    ├─ within limits → record usage, continue
  │    └─ exhausted → -32004
  │
  ├─ 7. VELOCITY CHECK ── anomaly detection (opt-in)
  │    ├─ normal → continue
  │    └─ spike → log alert (or -32004 if DENY action)
  │
  ├─ 8. AUDIT ── emit tool.allowed event
  │
  └─ 9. FORWARD ── proxy to upstream (possibly modified by SCOPE)
       │
       └─ SCOPE response processing (redact on the way back)
```

---

## Error Codes

Standard JSON-RPC 2.0 application-defined error codes:

| Code | Constant | Meaning |
|------|----------|---------|
| -32000 | ErrCodePolicyDenied | Policy DENY rule matched, or HOLD was denied/rejected |
| -32001 | ErrCodeIdentityFailed | Identity verification or integrity check failed |
| -32002 | ErrCodeCircuitOpen | Circuit breaker tripped (session limits) |
| -32003 | ErrCodeToolUnknown | Tool not in registry |
| -32004 | ErrCodeRateLimited | Budget exhausted or velocity limit exceeded |
| -32005 | ErrCodeHoldTimeout | HOLD timed out without approval |
| -32006 | ErrCodeScopeViolation | SCOPE could not safely modify the request |

---

## YAML Specification

### ALLOW (unchanged from v0.1)

```yaml
- action: ALLOW
  mcpMethod: tools/call
  toolNames: [cost.check_usage]
  when:
    identity: human
  requireIdentity: true
```

### DENY (unchanged, gains reason: field in v0.2)

```yaml
- action: DENY
  mcpMethod: tools/call
  toolNames: [secrets.leak_config]
  reason: "secret exfiltration blocked"
```

### HOLD (v0.3)

```yaml
- action: HOLD
  mcpMethod: tools/call
  toolNames: [delegation.invoke_agent, cred_broker.configure_sidecar]
  when:
    identity: agent
  hold:
    timeout: 5m
    onTimeout: DENY          # DENY or ALLOW
    notify:
      webhook: "https://hooks.slack.com/..."
      # or: adminAPI: true   (poll via GET /admin/holds)
    approvers:
      groups: [security-team]
  reason: "agent delegation requires human approval"
```

### SCOPE (v0.4)

```yaml
- action: SCOPE
  mcpMethod: tools/call
  toolNames: [cred_broker.read_credential]
  when:
    identity: agent
  scope:
    request:
      stripArguments: [vault_password, master_key]
      injectArguments:
        read_only: "true"
    response:
      redactPatterns: ["password", "secret", "api_key"]
      redactReplacement: "[REDACTED]"
  reason: "agents get read-only access with secrets redacted"
```

### BUDGET (new — v0.3)

```yaml
- action: ALLOW
  mcpMethod: tools/call
  toolNames: [cost.invoke_llm, config.ask_agent]
  budget:
    perIdentity:
      maxCallsPerHour: 100
      maxTokensPerDay: 50000
    perSession:
      maxCalls: 20
      maxTokens: 10000
    onExhausted: DENY        # DENY or LOG
  reason: "LLM calls are budget-limited"
```

Budget is not a standalone action — it attaches to ALLOW rules as a constraint. The tool call is allowed *if* the budget has room.

---

## How Future Features Map to Actions

Every feature on the roadmap slots into one of the five actions:

| Feature | Action | How |
|---------|--------|-----|
| Tool-chain sequence detection | DENY or HOLD | Suspicious sequence triggers deny or approval gate |
| Claims drift detection | DENY | Scope changed mid-session → reject |
| Credential injection from Vault | SCOPE | Inject fetched secret into request params |
| Response PII detection | SCOPE | Redact PII patterns in tool response |
| Token/cost tracking | BUDGET | Count tokens from LLM responses |
| Delegation chain limits | HOLD | Agent-to-agent calls require approval beyond depth N |
| Time-of-day rules | DENY | Tool blocked outside allowed hours |
| Rug-pull detection | DENY | Tool definition changed since init → reject |
| Human-in-the-loop | HOLD | Dangerous operations parked for approval |

---

## Implementation Order

| Phase | Action | Status |
|-------|--------|--------|
| v0.1 | ALLOW | Implemented |
| v0.1 | DENY | Implemented |
| v0.3 | BUDGET | Implemented — per-identity/session call + token limits |
| v0.3 | HOLD | Implemented — admin API, webhook notify, timeout |
| v0.4 | SCOPE | Implemented — request/response modification, redaction |

BUDGET first because it's the simplest, most immediately useful, and structurally familiar. HOLD second because it's the flagship arbiter feature. SCOPE last because modifying request/response bodies changes the trust model.

---

## Principles

1. **Every action is opt-in.** If your policy only uses ALLOW and DENY, nullfield behaves exactly like v0.1.
2. **Actions compose.** BUDGET on an ALLOW rule. SCOPE then HOLD. Any combination.
3. **The YAML is human-readable.** A security reviewer can understand the policy in 30 seconds.
4. **The audit trail captures everything.** Every action, every modification, every approval, every budget decrement.
5. **Default is deny.** No rule matched = rejected.
