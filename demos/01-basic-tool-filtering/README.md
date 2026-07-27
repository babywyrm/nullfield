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

## One thing that does not work

The `circuitBreaker` block in the policy is **decorative**. It parses into the
spec and nothing reads it — `cmd/nullfield` builds the breaker from
`NULLFIELD_CIRCUIT_MAX_CALLS` and `NULLFIELD_CIRCUIT_MAX_DURATION` before the
policy is loaded, and never consults `spec.circuitBreaker`. That is true of
every policy in this repository, `onTrip: KILL_POD` included, which reads like
it would do something dramatic and does nothing at all.

So this demo sets the limit where it actually takes effect:

```yaml
# compose.override.yaml
environment:
  NULLFIELD_CIRCUIT_MAX_CALLS: "5"
```

and its policy asks for 50. The breaker trips on the 6th call, which is how the
test proves the environment won. That assertion fails if the policy ever starts
winning, which is the signal to come back and update this page.

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
  gap: the limit came from the environment; the policy's circuitBreaker block is ignored
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
