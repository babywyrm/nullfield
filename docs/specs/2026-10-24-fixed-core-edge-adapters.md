# Fixed Core, Edge Adapters — Design

**Date:** 2026-10-24
**Status:** Steps 1, 2 and 3a (run token) done; 3b next
**Related:**
- [`2026-07-26-mesh-native-arbiter.md`](2026-07-26-mesh-native-arbiter.md) — the three facts and authority grants this builds on

---

## Goal

One decision core that every scenario reaches through adapters. A new
scenario adds an adapter at the edge; it never adds a special case in the
middle.

```text
  normalize at the edge        decide in the middle        act at the edge
  ─────────────────────        ────────────────────        ───────────────
  MCP, HTTP API, CLI       ──►  gates + policy engine  ──►  allow, deny, hold,
  any issuer's token            same answer whichever        scope, audit,
  mesh attestation              door the call used           signal a controller
```

## Acceptance scenarios

The architecture is right when all three are configuration over the same core,
with no code specific to any one of them.

1. **Scheduled run.** A controller launches one pod per run, nobody in the loop.
   The pod reads credentials from Secrets that External Secrets Operator
   materializes, and calls MCP servers and SaaS APIs directly. Authority is the
   flow: run R of flow F at contract version V, owned by team T.
2. **Human on-behalf-of.** A person asks in chat; an agent acts for them through
   an RFC 8693 `act` chain from Okta.
3. **CI.** A GitHub Actions job presents its OIDC token and calls the same
   targets.

## Invariants

These hold in every deployment and are not configurable. Flexibility lives in
adapters; these are what keep a flexible product from being configurable into
one that mediates nothing.

- A rule that requires identity, presented with none, denies.
- A run token narrows what its contract allows. It never widens it.
- A token is bound to the workload it was issued for.
- Observe and enforce are always explicit.
- Half-configured security refuses to start.
- A dangerous mode is named for what it does.
- **A limit that cannot be charged refuses the call.** A per-identity budget
  with no subject to charge, or a per-session budget with no session, is not a
  budget.

## Gaps this closes, in order

### 1. One gate sequence for every front door

The proxy runs registry, circuit breaker, policy, budget, breaker accounting and
velocity, in that order. The gateway runs its own copy. ext_authz runs policy
only. So one policy means different things depending on how a call arrived, and
every new front door would add a third copy.

`pkg/gates` holds the sequence once. Each front door calls it and keeps only its
presentation: JSON-RPC error codes for the proxy and gateway, an Envoy response
for ext_authz.

- `Admit` runs before policy: the registry, when the call names a tool, then
  the circuit breaker.
- `Charge` runs after an allowing decision: budget, breaker accounting, then
  velocity.

On the mesh path the breaker and per-session budgets have no session to key on
until run identity lands in step 3. Per-identity budgets and velocity charge the
attested workload principal; an unattested caller has nothing to charge, and by
the invariant above a budgeted rule refuses it.

Found while doing this, recorded rather than fixed here:

- ext_authz deployments set `NULLFIELD_REGISTRY_PATH` and nothing read it.
  Fixed by this step.
- A SCOPE rule on the mesh path returns allowed and the call passes
  **unmodified**. ext_authz cannot rewrite a body, so stripping arguments or
  injecting credentials silently does not happen. Needs `ext_proc`, or a refusal
  in enforce mode until then.
- HOLD on the mesh path fails closed, which is correct, but cannot wait for a
  human: the provider timeout is 1s.
- Omitting `Mcp-Session-Id` skipped per-session budgets on the proxy. Fixed by
  the invariant above.

### 2. Rules over the whole normalized request

`Target` and `Operation` are populated for HTTP traffic and no rule reads them.
`celExpression` is accepted by the schema and evaluated nowhere. Wire CEL over
the normalized request, so target, operation and run-token narrowing are
expressible without a new Go field per scenario. Until then, reject policies
that set `celExpression`.

**2a (done):** auditing for the rejection found the problem was wider than
CEL. Every policy field is now either enforced or refused at load, including
by the CRD controller. Newly enforced: `maxCallsPerMinute` (rule and
registry), `requireExpiry`, `maxLifetime`. Refused: unknown keys and the
fields listed in the CHANGELOG. Still accepted but advisory: `selector`,
`audit.emitTo`, `audit.logLevel`, `inspection.detectPaths`.

**2b (done):** `celExpression` is a match predicate over `request`
(method, tool, arguments, transport, target, operation, identity). Compile
errors refuse the policy; runtime errors refuse the call. Target and
operation are populated by ext_authz only; the proxy sees MCP alone.

### 3. Identity composed from several sources

A request gets one `Identity` from one verifier. The three facts need several:
the mesh attests the workload, a run token supplies authority, an upstream
token may ride alongside. The run token is the first plugin: signed by the
launching controller, its subject bound to the attested workload, carrying the
run ID that budgets, the breaker and audit key on.

**3a design.** The run token is an IETF Transaction Token
([draft-ietf-oauth-transaction-tokens-11](https://datatracker.ietf.org/doc/draft-ietf-oauth-transaction-tokens/)),
so a controller can mint it with existing libraries and other services can
read it.

| Draft element | nullfield use |
|---|---|
| `Txn-Token` header, bare JWT | where the token is read |
| `typ: txntoken+jwt` | required; an ordinary access token cannot stand in |
| `aud` (trust domain) | required, must equal `runToken.audience` |
| `exp`, `iat` | required; `maxLifetime` bounds the difference |
| `txn` | the run ID: per-session budgets, audit `run_id`, `request.run.id` |
| `req_wl` | must equal the attested workload principal: the binding |
| `sub` | the principal; becomes `request.identity` |
| `tctx` | `request.run.context`; where a controller narrows one run |

Binding is on `req_wl`, not `sub`: in an on-behalf-of run `sub` is the human,
and the pod is the workload that holds the token.

Narrowing is a policy pattern, not a mechanism. Rules grant; a CEL condition
reading `request.run.context` can only make a rule match less, so a token can
narrow what policy allows and never widen it:
`request.arguments.repo in request.run.context.repos`.

Decisions:

- **ext_authz only.** The proxy and gateway see no attested workload, so they
  could not bind the token. They refuse a policy that sets `runToken` rather
  than accept it unbound.
- **Required by default.** With `runToken` set, a call without one is refused.
  `optional: true` admits tokenless calls, which rules can tell apart with
  `has(request.run)`.
- **Stripped on allow.** ext_authz tells Envoy to remove `Txn-Token` before
  forwarding, so it never reaches a SaaS API. Propagation through MCP servers
  you own is not supported yet.
- **Rates stay per workload; per-session budgets become per run.** The
  circuit breaker stays off on the mesh until a tokenless call cannot share
  one empty session key.

**3a (done).** As designed above. Bound calls report assurance `MEDIUM`.
Demo 17 verifies it on brainbox through a real waypoint, including the
binding, narrowing by `tctx`, and the strip.
Found on the way: the CRD schema does not preserve unknown fields at `spec`,
so a new top-level block is pruned silently unless the schema names it.

**3b (next):** the circuit breaker keyed on run ID; header propagation
through MCP servers you own; an upstream token riding alongside (the third
identity source).

### 4. Integration operation maps as data

Mapping `DELETE /repos/acme/widgets` on `api.github.com` to "delete repository
`acme/widgets`" is per integration. It ships as a data file per target, not
code, so integrations are added by writing YAML.

### 5. Outward events

`circuitBreaker.onTrip` is parsed and read nowhere. Decisions become events a
controller can subscribe to, so the controller that owns a run's pod can end it.

## Out of scope

Egress mediation for SaaS calls (roadmap v0.14), credential brokering, and
enforcement mode per flow and target. Each depends on the steps above.
