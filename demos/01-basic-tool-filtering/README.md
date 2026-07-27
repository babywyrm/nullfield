# Demo 01 — Basic Tool Filtering

The foundation. Three gates decide whether a tool call reaches its upstream,
they run in a fixed order, and the error code tells you which one answered.

```bash
demos/01-basic-tool-filtering/test.sh
```

Tier 1, no dependencies beyond Docker Compose, gated in CI.

## The gates, in order

```text
  tools/call
      │
      ▼
  ┌─────────────┐   not described in the registry     ──► -32003
  │  registry   │
  └──────┬──────┘
         ▼
  ┌─────────────┐   too many calls in this session    ──► -32002
  │  circuit    │
  └──────┬──────┘
         ▼
  ┌─────────────┐   known, and not granted            ──► -32000
  │  policy     │
  └──────┬──────┘
         ▼
    upstream
```

The order is not cosmetic. Because the registry runs first, **an unregistered
tool cannot be granted by writing an ALLOW rule for it** — the rule is never
reached. Registering a tool and granting a tool are two separate acts, and the
demo proves it by calling something that is both absent from the registry and
explicitly denied in policy. It comes back `-32003`, not `-32000`.

| Code | Gate | Means |
|---|---|---|
| `-32003` | registry | nothing describes this tool |
| `-32002` | circuit | this session has made too many calls |
| `-32000` | policy | the tool is known and not granted |

## Registry and policy do different jobs

`tools.yaml` describes what exists: names, scopes, per-minute ceilings. It is
the vocabulary.

`policy.yaml` decides who may do what: tiers of ALLOW, an explicit high-risk
DENY, and a trailing `*` default-deny so an unmatched tool is refused rather
than waved through.

`secrets.read_config` is in the registry *and* denied by policy, on purpose. A
demo where every refusal comes from the registry cannot show the two apart.

Denying it by name rather than leaving it to the default-deny is also
deliberate: the audit trail then names `tier-3-high-risk` as the rule that
decided, which is the difference between a policy you can review and one you
can only observe after the fact.

## Where the breaker's limits come from

Two sources, and the policy wins:

```yaml
# policy.yaml — takes precedence
circuitBreaker:
  maxToolCallsPerSession: 5

# compose.override.yaml — the fallback
environment:
  NULLFIELD_CIRCUIT_MAX_CALLS: "50"
```

The demo sets them to different values on purpose. Tripping on the 6th call is
what proves the policy won, and the test fails if it trips anywhere else.

A policy that omits `circuitBreaker` leaves the environment in place, so
existing deployments are unaffected. The fields are independent: declaring only
`maxToolCallsPerSession` leaves the duration to the environment. Non-positive
values are treated as unspecified rather than obeyed, because a negative limit
is a typo and not a request to disable the breaker.

This is read once at startup. Hot-reload swaps the rule engine, not the
breaker, so changing `circuitBreaker` in a mounted policy needs a restart.
`nullfield` logs which source won at startup:

```
circuit breaker configured maxCallsPerSession=5 maxSessionDuration=5m0s source=policy
```

**`onTrip` is still only a label.** Nothing in the codebase reads it, so `DENY`
and `KILL_POD` behave identically. The test greps for a reader and fails if one
appears, so the claim is checked rather than remembered.

## What the test asserts

```
the three gates, by the code they return:
  ok:  a granted tool reaches the upstream server
  ok:  a registered tool denied by policy returns -32000
  ok:  a tool the registry never described returns -32003

the registry runs before policy:
  ok:  an unregistered tool is refused by the registry, not by policy

the circuit breaker is per session:
  ok:  a session over its call limit returns -32002
  ok:  the limit came from the policy, not from the environment's looser value
  gap: onTrip is parsed and unread, so DENY and KILL_POD do the same thing
  ok:  a different session is unaffected

every decision is on the record:
  ok:  the audit trail names the gate that made each decision
  ok:  and names the rule, not just the outcome
```

The breaker is keyed on `Mcp-Session-Id`, so a runaway agent is contained
without taking down every other caller. The test checks a second session still
works, which is the half that matters in production.

## Related

- Demo 06, 07, and 08 cover the decisions policy can make beyond allow and
  deny: HOLD, BUDGET, and SCOPE.
- Demo 10 replaces the mounted `policy.yaml` with a Kubernetes custom resource.
