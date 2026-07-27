# Demo Harness and Walkthroughs

**Date:** 2026-07-27
**Status:** Approved, not yet implemented
**Related:** [`2026-07-26-mesh-native-arbiter.md`](2026-07-26-mesh-native-arbiter.md), [`ROADMAP.md`](../../ROADMAP.md)

---

## The problem

nullfield ships sixteen demos. Four of them assert anything.

Demos 13, 14, 15, and 16 have a `test.sh` that runs, checks, and exits
non-zero on failure. The other twelve are prose walkthroughs a reader is
expected to follow by hand, and several of them cannot work as written:

- **Demos 06, 07, and 08** — HOLD, BUDGET, and SCOPE, three of the five
  actions — each open with
  `docker compose up -d -v $(pwd)/demos/NN-.../policy.yaml:...`. On Compose v2,
  `-v` on `up` means *verbose*, not volume mount. The demo-specific policy is
  never mounted, so each of these demos runs against the default policy and
  cannot demonstrate the feature it exists to demonstrate.
- **`integrations/camazotz/demo.sh`** preflights on an expected 57 tools
  against a registry that now holds 139. It fails at the door.
- **Demos 10 and 11** state that policy reloads within 30 seconds. The poll
  interval is 10. Demo 11's curls also omit the `/mcp` path used everywhere
  else.
- **`policies/by-lane/lane-2-delegated.yaml`** warns that until
  `requireActChain` and `audienceMustNarrow` "are implemented in the engine,
  the rules that use them will validate as unknown fields but be ignored at
  runtime." `policies/by-lane/README.md`, in the same directory, states they
  have been enforced since 2026-05-01. The README is right.
- **`demos/README.md`** still sends readers to the quickstart for "a guided
  path through all demos". The quickstart was rewritten on 2026-07-26 to stop
  pointing at unverified demos, so that path no longer exists.

The common thread is not missing infrastructure. It is that every one of these
claims is hand-maintained and nothing checks it. A tool count, a poll interval,
an implementation-status comment, and a promise about another document drifted
independently, and each was correct when written.

Separately, the flows that would most differentiate nullfield have no runnable
coverage at all. There is no demo for OAuth, on-behalf-of delegation, Keycloak
or Zitadel, live Vault credential injection, `kubectl` mediation, or any real
SaaS integration. What exists is compile-time metadata:
`examples/agentic-flow.yaml` names an Atlassian OAuth audience and a Vault
credential, and demo 13 greps for them in compiled output. Nothing
authenticates against anything.

There is also no dedicated ALLOW or DENY demo, and nothing anywhere exercises
the circuit breaker.

## Non-goals

- Renumbering the demo directories. See the constraint below.
- Running tier 2 or tier 3 demos in GitHub Actions. A cluster and an Istio
  ambient mesh are not reasonable CI dependencies, and pretending otherwise
  produces a green badge that covers less than it appears to.
- Real SaaS integration against live GitHub, Slack, PagerDuty, or Atlassian.
  Demos must be runnable by a stranger with no accounts.
- Fixing every stale sentence in every document. This spec addresses the
  mechanism that lets prose drift, plus the specific instances above.

## Constraint: numbers are load-bearing

The published v0.12.0 release notes link to `demos/14-agentic-flow-kubernetes`,
`demos/15-proxy-baseline`, and `demos/16-mesh-arbiter`. `ROADMAP.md`,
`CHANGELOG.md`, `docs/quickstart.md`, `docs/mesh-integration.md`, and
`docs/agentic-flows.md` reference the same paths.

Therefore: **no demo is renumbered and no existing demo directory is merged
into another.** Retired numbers become gaps. New demos start at 17. This is
why demos 13 and 14 stay as two directories even though the multi-tier
convention below would otherwise combine them — the published link to 14 has
to keep resolving.

(References to `demos/15-extauthz-observe` and `demos/16-extauthz-observe`
exist only in `docs/plans/`, which is gitignored. They are a provisional name
from the working plan and are not a public problem.)

---

## The demo contract

Every demo directory contains a `README.md` walkthrough and at least one
executable assertion script. The script declares what it needs in a header
block:

```bash
#!/usr/bin/env bash
# tier: 1
# requires: compose
# summary: registry and policy gates refuse different things for different reasons
```

### Tiers

Tier describes infrastructure, and nothing else.

| Tier | `requires` | Meaning | CI |
|---|---|---|---|
| 1 | `compose` or `none` | Docker Compose, or just the built binary. Hermetic: no cluster, no external service, no credentials, no network beyond localhost | Runs on every push |
| 2 | `kubernetes` | Needs a cluster. Run on brainbox with one command | Not gated |
| 3 | `mesh` | Needs Istio ambient. Run on brainbox | Not gated |

A demo may opt out of CI with `# ci: no` while remaining tier 1. This exists
for the Zitadel variant of demo 17: it needs only Compose, so calling it tier 2
would be a lie about its infrastructure, but booting an identity provider on
every push is too slow to gate on. Tier stays an honest statement about
requirements; CI selection is a separate axis.

### The governing rule

**A demo that cannot assert anything is not a demo, it is a document.**

Demo 12 today is prose pointing at an external camazotz lab. Under this
contract it either becomes a tier-1 demo against the echo server or it moves
into `docs/` and stops appearing in a directory that implies it runs.

### Output is evidence

Scripts print what they asserted rather than passing silently, following the
pattern demo 15 already uses:

```text
proxy-mode decisions:
  ok: ALLOW reaches the upstream
  ok: DENY is refused by policy
  ok: unknown tool is refused
```

The terminal output is the artifact a reader trusts. A silent exit code is not.

### Recording what CI cannot vouch for

Tiers 2 and 3 are never gated, so their status has to be asserted by a human.
The runner supports `--record`, which appends a dated line to a committed
`demos/VERIFIED.md`:

```text
2026-07-27  16-mesh-arbiter  tier 3  PASS  k3s 1.34 / Istio 1.30.1 ambient
```

This makes "last verified" a deliberate claim someone made on a specific
substrate, rather than something a reader infers from a green badge that never
covered those demos.

---

## The harness

A single runner, `demos/run.sh`, discovers demos by globbing
`demos/*/test*.sh` and reading the header block. There is no registry file. A
hand-maintained list is a second source of truth, and `demos/README.md` shows
what that costs: its table is currently accurate, but its prerequisites still
name camazotz as the MCP server, its "demos 04+ deploy a sidecar" summary is
wrong for 13, and its closing line promises a quickstart tour that no longer
exists. Each was true when written.

```bash
./demos/run.sh --list                # what exists, what tier, what it needs
./demos/run.sh --tier 1              # everything CI gates
./demos/run.sh --tier 2 --record     # cluster demos on brainbox, stamp VERIFIED.md
./demos/run.sh 16-mesh-arbiter       # one demo by name
./demos/run.sh --index               # regenerate demos/README.md
```

### Multi-tier demos live in one directory

A flow that runs on both substrates keeps one `README.md` and ships `test.sh`
(tier 1) alongside `test-k8s.sh` (tier 2), each with its own header. The
walkthrough is the same story; only the substrate changes, and maintaining two
copies of that story in two directories is how they drift apart. The glob is
`test*.sh` for this reason.

This applies to new demos only. Demos 13 and 14 stay split, per the numbering
constraint.

### CI

One new job in `.github/workflows/tests.yml` runs `./demos/run.sh --tier 1` on
every push. The existing `go-test`, `policy-yaml-lint`, and `notify-coherence`
jobs are unchanged.

### Generated index

`demos/README.md` is generated by `--index` from the script headers plus
`VERIFIED.md`. This is what removes the class of error rather than the
instance: the demo count, the per-demo summary, the tier, and the last-verified
stamp all come from the demos themselves, so no one has to remember to correct
the index again.

---

## Disposition of the existing sixteen

| # | Demo | Disposition |
|---|---|---|
| 01 | basic-tool-filtering | Rework off camazotz onto the echo server. Becomes the home for the circuit breaker, which nothing currently exercises |
| 02 | jwt-identity-tracking | Rework self-contained with a local JWKS. Its token minter is reused by demo 17 |
| 03 | anomaly-detection | Rework self-contained; builds on 02's minter |
| 04 | sidecar-compose | **Retire.** Quickstart Part 1 is this demo now |
| 05 | sidecar-kubernetes | **Retire.** Duplicated by demo 15 plus the implementation guide |
| 06 | hold-action | Fix the `-v` mount breakage, add `test.sh` |
| 07 | budget-action | Fix the `-v` mount breakage, add `test.sh` |
| 08 | scope-action | Fix the `-v` mount breakage, add `test.sh` |
| 09 | controller-mode | Add `test.sh`; its compose stack already works |
| 10 | crd-policy | Add `test-k8s.sh` (tier 2); correct 30s to 10s |
| 11 | hot-reload | **Retire.** Quickstart step 5 is this demo now |
| 12 | response-inspection | Rework from prose into a tier-1 demo |
| 13 | agentic-flow-local | Keep; add header |
| 14 | agentic-flow-kubernetes | Keep; add header |
| 15 | proxy-baseline | Keep; add header |
| 16 | mesh-arbiter | Keep; add header |
| 17 | obo-delegation | **New** |
| 18 | credential-brokering | **New** |
| 19 | confused-deputy | **New** |

Sixteen live demos, every one with an assertion script. Twelve are tier 1 and
gated on every push (01, 02, 03, 06, 07, 08, 09, 12, 13, 17, 18, 19); three are
tier 2 (10, 14, 15) and one is tier 3 (16). Demos 17, 18, and 19 additionally
ship a tier-2 `test-k8s.sh`, so the cluster path is covered for all three new
flows. Directories 04, 05, and 11 are deleted; their numbers are not reused.

That ratio is the argument for the tiering. Today four demos are checkable and
none of them automatically; afterwards twelve are checked on every push, and
the four that cannot be are named, dated, and attributed to a substrate.

`integrations/camazotz/demo.sh` sits outside `demos/` and so outside the
harness, but its 57-versus-139 preflight is fixed in the same pass rather than
left as a broken entry point.

---

## The three new flows

### 17 — OBO delegation

**Claim:** a sub-agent cannot acquire authority the human never had.

Policy uses `identity.requireActChain` (RFC 8693),
`identity.audienceMustNarrow` (RFC 8707), and `delegation.maxDepth: 2`, all of
which are implemented in `pkg/policy/rules.go` and have no runnable
demonstration today.

Assertions:

1. A human-direct token still reaches tools it is authorized for.
2. An agent token with an `act` chain of depth 1 and a narrowed audience is
   allowed.
3. An `act` chain of depth 3 is refused — exceeds `maxDepth`.
4. A token whose audience *widens* relative to its parent is refused.
5. A token with no `act` claim, against a rule requiring one, falls through to
   default deny.

`test.sh` (tier 1) uses a local minter extended from demo 02: a signing script
plus a static JWKS served over HTTP. `test-k8s.sh` (tier 2) applies the same
policy via ConfigMap against a sidecar. `test-zitadel.sh` (tier 1, `ci: no`)
boots Zitadel in Compose and proves the JWKS provider configuration is not
vendor-specific — which also makes `examples/policy-identity.yaml`, which
already configures a Zitadel provider, agree with something that runs.

A Keycloak variant follows later, deferred rather than dropped.

### 18 — Credential brokering

**Claim:** the agent holds nothing, and a broker that fails open is worse than
no broker.

Vault runs in dev mode in Compose. Policy carries a SCOPE rule that injects a
credential from Vault for one declared tool and redacts it from the response.
The echo server makes injection observable because it echoes the arguments it
actually received.

Assertions:

1. The agent calls the tool with no credential; the upstream receives the
   request *with* the credential injected.
2. The agent's own view of the response has the secret redacted.
3. The audit event records that injection occurred and names the source.
4. A tool *not* declared for that credential does not receive it.
5. With Vault unreachable, the call is **refused**, not forwarded without the
   credential.

Assertions 4 and 5 are the ones that matter. A broker that leaks credentials to
undeclared tools, or that silently degrades to no-credential passthrough when
its backend is down, has negative value: it moves the secret without
constraining it.

All of this is demo work, not feature work. `pkg/proxy/handler.go` already
resolves `scope.request.injectCredentials` through the multi-provider and
already fails closed with `scope: credential injection failed` when a fetch
errors; `pkg/credentials` already ships Vault, Kubernetes Secret, env, static,
and cached providers. None of it has a demonstration.

`test-k8s.sh` (tier 2) runs the same flow with the Kubernetes Secret provider,
which is the path most clusters will actually use.

This flow directly satisfies the roadmap v0.13 item "full credential runtime
demos: Vault, K8s Secret, and OAuth-style paths, with proof that credentials
attach only to declared tool actions."

### 19 — Confused deputy

**Claim:** one agent process serving two principals is where attribution gets
hard, and nullfield closes part of that gap and not all of it.

Assertions:

1. The agent acting under Alice's grant, on Alice's resource, is allowed.
2. Replaying Alice's grant under a request Bob initiated is refused by session
   binding and replay detection.
3. **The gap.** The agent calling a tool Alice *is* authorized for, against
   *Bob's* resource, is allowed today, because resource-level scoping does not
   exist.

The third line is reported as `gap:` rather than `ok:`, and the assertion is
written to fail when resource scoping lands — forcing the demo to be updated
rather than allowing it to quietly overstate what nullfield does. Resource-level
contract scoping is already on the roadmap under "Later" as required to fully
close the confused-deputy case; this demo is the executable statement of that
gap.

A confused-deputy demo that showed only successes would be marketing.

---

## Sequencing

**Phase 0 — Harness and contract.** `demos/run.sh` with discovery, `--tier`,
`--list`, `--record`, `--index`; the header convention; `demos/VERIFIED.md`;
the CI job; generated `demos/README.md`. Deliberately first: when it lands,
only demos 13 through 16 pass, and the runner says so. That honest baseline is
the point of going first.

**Phase 1 — Repair and retire.** Fix `-v` in 06/07/08 and give them scripts;
add one to 09; add `test-k8s.sh` to 10 and correct the interval; retire 04, 05,
and 11; fix the camazotz preflight; add headers to 13 through 16. This is what
makes the CI gate meaningful.

**Phase 2 — Rework the camazotz-dependent demos.** 01, 02, 03, and 12 onto the
echo server. The long pole, and it gates Phase 3 because demo 17 reuses 02's
minter.

**Phase 3 — Demo 17, OBO delegation.** Tier 1, tier 2, and the Zitadel variant.

**Phase 4 — Demo 18, credential brokering.** Tier 1 and tier 2.

**Phase 5 — Demo 19, confused deputy.** Tier 1 and tier 2.

**Phase 6 — Keycloak variant**, and quickstart pointers into the new demos.

Phases 3 and 4 build the demo half of roadmap v0.13 rather than new scope,
which makes v0.13.0 the natural release for this work. ROADMAP and CHANGELOG
are updated as each phase lands, not in one pass at the end.

---

## Success criteria

1. `./demos/run.sh --tier 1` passes locally and in CI.
2. Every directory under `demos/` contains at least one assertion script, or
   has been removed.
3. `demos/README.md` is generated and its demo count matches the directory
   listing by construction.
4. `demos/VERIFIED.md` carries a dated entry for every tier-2 and tier-3 demo.
5. A reader with Docker and no cluster, no accounts, and no credentials can run
   every tier-1 demo.
6. Demo 19 asserts the resource-scoping gap and fails when the gap closes.

## Risks

**The rework in Phase 2 is larger than it looks.** Demos 01, 02, 03, and 12
were written against camazotz's tool vocabulary. Moving them to the echo server
means rewriting their policies, their example calls, and their prose. The
mitigation is that 02's minter is reused by 17, so the work compounds; the risk
is that Phase 2 stalls and Phase 3 is blocked behind it. If that happens, build
17's minter standalone and backport it into 02.

**Vault in Compose adds a dependency that can rot.** Dev-mode Vault is stable
and pinned by image tag, but it is the first external service in a tier-1 demo.
If it proves flaky in CI, demo 18's tier-1 script moves to `ci: no` and the
Kubernetes Secret variant becomes the gated one.

**`--record` is only as honest as the person running it.** Nothing stops a
stale entry in `VERIFIED.md`. The date and substrate are recorded so a reader
can judge for themselves, which is weaker than CI and stronger than silence.
