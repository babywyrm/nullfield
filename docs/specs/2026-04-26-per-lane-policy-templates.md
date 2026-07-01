# Per-Lane Policy Templates — Design

**Date:** 2026-04-26
**Status:** Design pending review, implementation pending
**Related:**
- [Identity Flow Framework](https://github.com/babywyrm/agentic-sec/blob/main/docs/identity-flows.md) (agentic-sec hub)
- Camazotz `/api/lanes` schema v1 ([babywyrm/camazotz PR shipping 2026-04-26](https://github.com/babywyrm/camazotz))
- Companion spec: `mcpnuke/docs/specs/2026-04-26-by-lane-reporting.md`

---

## Goal

Organize nullfield's policy surface around the **five agentic-identity lanes**
from the Identity Flow Framework so operators can pick the right starting
policy for each identity flow in their deployment without reverse-engineering
it from scratch.

Three concrete deliverables:

1. **Lane/transport labels** on every existing `NullfieldPolicy` under
   `examples/` so each file self-identifies where on the lane grid it
   belongs.
2. **A `policies/by-lane/` directory** with one starter template per lane.
   Each template is a minimum-viable, deploy-it-as-is NullfieldPolicy that
   implements the lane's expected default action (see the "Default Actions"
   table in identity-flows.md).
3. **Three new policy primitives** motivated by the gaps visible in the
   camazotz Lane 2 and Lane 4 labs:
   - `identity.requireActChain` — reject tokens missing the RFC 8693 `act`
     claim on delegated flows
   - `delegation.maxDepth: <n>` — reject if the `act` chain exceeds depth n
   - `identity.audienceMustNarrow` — RFC 8707 audience narrowing enforcement

## Non-Goals

- Auto-generating policies from camazotz `/api/lanes` output. That's
  mcpnuke's job (see the companion spec's `--coverage-report` flag).
- Changing the `NullfieldPolicy` CRD shape. All new primitives land as
  additive optional fields under the existing `rules[].*` schema — no
  version bump.
- Migrating existing deployments. These labels and templates are opt-in
  and additive; nothing in `examples/` changes semantics.
- Teaching what each lane *is*. That's what
  `agentic-sec/docs/identity-flows.md` exists for; this spec only binds
  nullfield vocabulary to that document's vocabulary.

## Constraints

- **Lane slugs must match camazotz.** The canonical list is defined in
  `camazotz/frontend/lane_taxonomy.py::LANES` and surfaced by
  `GET /api/lanes` (schema v1). Use these slugs verbatim:
  `human-direct`, `delegated`, `machine`, `chain`, `anonymous`.
- **Transport codes must match camazotz.** `A` = MCP JSON-RPC,
  `B` = Direct HTTP API, `C` = SDK/library.
- Templates must pass `kubectl apply --dry-run=server` against the
  published `nullfieldpolicy-crd.yaml`.
- No breaking changes to existing policy evaluation semantics — the three
  new primitives default to *not enforced* when omitted.

---

## Deliverable 1 — Label existing examples

Every YAML under `examples/` gets two new metadata labels:

```yaml
metadata:
  name: ...
  labels:
    nullfield.io/lane: "<slug>"          # one of the five lane slugs
    nullfield.io/transport: "<A|B|C>"    # optional, for multi-transport setups
```

### Mapping of existing examples

| File | `nullfield.io/lane` | `nullfield.io/transport` |
|------|---------------------|--------------------------|
| `examples/policy-minimal.yaml` | `anonymous` | `A` |
| `examples/policy.yaml` (demo-agents) | `delegated` | `A` |
| `examples/policy-identity.yaml` | `human-direct` | `A` |
| `examples/gateway/*.yaml` | per-file (see below) | per-file |
| `examples/crd/*.yaml` | per-file | per-file |

The per-file mapping under `gateway/` and `crd/` is a mechanical pass in
the implementation plan; this spec commits to labelling *all* existing
policies, not a subset.

### Why labels and not a new field

- Non-breaking: any consumer that ignores labels keeps working.
- Searchable via `kubectl get nullfieldpolicy -l nullfield.io/lane=chain`.
- Consistent with standard Kubernetes convention for optional taxonomy.

---

## Deliverable 2 — `policies/by-lane/` starter templates

New directory `policies/by-lane/` with one file per lane:

```
policies/by-lane/
  lane-1-human.yaml       # primary_lane: 1, action: ALLOW + audit
  lane-2-delegated.yaml   # primary_lane: 2, action: SCOPE + audit (uses audienceMustNarrow)
  lane-3-machine.yaml     # primary_lane: 3, action: SCOPE by workload id
  lane-4-chain.yaml       # primary_lane: 4, action: HOLD past depth=2 (uses requireActChain + maxDepth)
  lane-5-anonymous.yaml   # primary_lane: 5, action: DENY (allowlist only)
  README.md               # per-lane rationale, pointer to the framework doc
```

Each template must:
- Ship the default action specified for that lane in `identity-flows.md`.
- Include at least one rule that exercises a lane-specific primitive
  where the lane needs one (Lane 2 uses `audienceMustNarrow`, Lane 4 uses
  `requireActChain` + `maxDepth`).
- Pass `kubectl apply --dry-run=server` without warnings.
- Be minimally commented so an operator can read it top-to-bottom and
  understand what the lane *expects*.

### Example sketch — `lane-4-chain.yaml`

```yaml
apiVersion: nullfield.io/v1alpha1
kind: NullfieldPolicy
metadata:
  name: lane-4-chain-starter
  labels:
    nullfield.io/lane: "chain"
    nullfield.io/transport: "A"
spec:
  selector:
    matchLabels:
      nullfield.io/role: "agent-chain"
  rules:
    # Every call on this selector must carry an RFC 8693 act chain.
    - action: ALLOW
      mcpMethod: tools/call
      identity:
        requireActChain: true
      delegation:
        maxDepth: 2
      requireIdentity: true
    # Past depth 2, queue for human approval.
    - action: HOLD
      mcpMethod: tools/call
      delegation:
        maxDepth: 3          # evaluated as "reject if depth > 3"
    # Past depth 3, outright deny.
    - action: DENY
      mcpMethod: tools/call
```

This is illustrative only; exact wire syntax is locked in the implementation
plan once we confirm the CRD field placement.

---

## Deliverable 3 — Three new policy primitives

All three are additive fields under `spec.rules[].*`. Default behavior when
omitted is **not enforced** — i.e. current deployments are unaffected.

### `identity.requireActChain: bool`

Reject (or act per rule action) when the caller's JWT is missing an RFC 8693
`act` claim. The claim represents an actor-on-behalf chain; absence means
the agent is presenting the end-user token directly, which on Lane 2 and
Lane 4 flows is almost always wrong.

```yaml
rules:
  - action: DENY
    mcpMethod: tools/call
    identity:
      requireActChain: true
```

### `delegation.maxDepth: int`

Reject (or act per rule action) when the `act` chain length exceeds `n`.
Chain length counts the number of nested `act` claims; a top-level end
user calling directly has depth 0, one agent has depth 1, etc.

```yaml
rules:
  - action: HOLD
    mcpMethod: tools/call
    delegation:
      maxDepth: 2
```

### `identity.audienceMustNarrow: bool`

Reject (or act per rule action) when a downstream token's `aud` claim is
wider than its parent's `aud`. RFC 8707 narrowing. Catches the camazotz
`oauth_delegation_lab` audience-confusion pattern directly.

```yaml
rules:
  - action: DENY
    mcpMethod: tools/call
    identity:
      audienceMustNarrow: true
```

### Evaluation order

All three primitives are evaluated as *additional guards* on a rule — the
rule's `action` only applies when every declared guard passes. If any guard
fails, nullfield moves to the next rule in the policy (existing semantics).
No changes to the rules engine itself.

---

## Implementation Surface

### New files

- `policies/by-lane/lane-1-human.yaml`
- `policies/by-lane/lane-2-delegated.yaml`
- `policies/by-lane/lane-3-machine.yaml`
- `policies/by-lane/lane-4-chain.yaml`
- `policies/by-lane/lane-5-anonymous.yaml`
- `policies/by-lane/README.md`

### Modified files

- `deploy/crds/nullfieldpolicy-crd.yaml` — add OpenAPI schema for
  `identity.requireActChain`, `identity.audienceMustNarrow`,
  `delegation.maxDepth` on `spec.rules[].*`.
- `internal/policy/engine.go` (or equivalent) — add the three guard
  evaluators, called from the existing rule-match path.
- Every `examples/*.yaml` — add `nullfield.io/lane` (and `nullfield.io/transport`
  where obvious) labels.
- `docs/identity-policy.md` — new section "Per-Lane Policy Templates".
- `README.md` — link to `policies/by-lane/` from the top-level.

### Tests

- Unit: each new primitive's pass/fail truth table (JWT with/without `act`,
  depth ≤ n vs > n, aud narrower vs wider).
- Integration: each of the five `by-lane/*.yaml` templates applies cleanly
  and evaluates the expected action on representative requests.
- CRD: `kubectl apply --dry-run=server` passes for all five templates.

---

## Acceptance Criteria

1. `kubectl get nullfieldpolicy -A -l nullfield.io/lane=chain` returns the
   lane-4 starter template when installed.
2. Every file under `examples/` declares `nullfield.io/lane`.
3. `policies/by-lane/` contains exactly five lane templates plus a README.
4. The three new primitives are documented in `docs/identity-policy.md`
   with a pass/fail example each.
5. Engine unit tests cover each primitive's boundary cases.
6. Lane 4 starter template rejects a synthetic request with a 4-deep
   `act` chain and accepts a 2-deep one.
7. Lane 2 starter template rejects a request whose downstream token
   widens `aud` and accepts one that narrows it.

---

## Ecosystem Coupling

- The **lane slugs** and **transport codes** in this spec are *verbatim*
  copies of the vocabulary published by camazotz `GET /api/lanes`
  (schema v1). If that schema ever changes, this spec must move with it.
- **mcpnuke** will begin emitting `nullfield.io/lane` in its
  `--generate-policy` output once this spec lands (covered in the
  companion mcpnuke spec).
- **agentic-sec** docs already reference this spec by name in
  `docs/identity-flows.md` section "nullfield — Per-Lane Default Actions".

Three repos, one vocabulary, one feedback loop.

---

## Out of Scope (Future)

- Per-lane default audit sinks (e.g. Lane 4 audits to a different log
  stream than Lane 1).
- Auto-migration tool from legacy policies to labelled form.
- Per-lane rate-limit primitives (distinct from global `maxCallsPerMinute`).
