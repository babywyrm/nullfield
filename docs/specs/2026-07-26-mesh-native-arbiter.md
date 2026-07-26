# Mesh-Native Arbiter — Design

**Date:** 2026-07-26
**Status:** Design pending review, implementation pending
**Related:**
- [`docs/arbiter-model.md`](../arbiter-model.md) — the five actions this preserves
- [`docs/agentic-flows.md`](../agentic-flows.md) — the contract this makes load-bearing
- [`docs/specs/2026-04-26-per-lane-policy-templates.md`](2026-04-26-per-lane-policy-templates.md) — the lane vocabulary
- [Identity Flow Framework](https://github.com/babywyrm/agentic-sec/blob/main/docs/identity-flows.md) (agentic-sec hub)
- stoneburner `atomics toolcall` (v0.14.0) — the divergence measurements this consumes

---

## Goal

Make nullfield able to arbitrate **the vast majority of agentic traffic** —
MCP, HTTP APIs, CLI-driven calls, and model-proposed tool calls — through a
single funnel, where a workload may only do what its contract declared, and
where every decision can be attributed to a principal with a known level of
confidence.

Three shifts, in dependency order:

1. **nullfield becomes a policy decision point**, reached through the service
   mesh, rather than a proxy that agents must be configured to use. Proxy mode
   remains for non-mesh deployments.
2. **The contract becomes the unit of authorization.** An `AgenticFlow` binding
   is required before a workload gets a decision other than the mode default.
   A *binding* is the association between a workload identity and the compiled
   contract that governs it, carrying its own mode. It is what the arbiter
   resolves on each call, and what enforcement is switched on per-flow against.
3. **Identity is derived, not asserted** — from mesh mTLS — and separated from
   the credential that happens to satisfy the upstream.

Enforcement is explicitly *not* the first deliverable. Observation with
counterfactual recording comes first.

---

## Why

### The coverage problem

nullfield today intercepts MCP JSON-RPC `tools/call` over HTTP on `:9090`.
There is no interception of anything else: no `exec.Command` wrapping, no
iptables redirection, no CONNECT proxy, no egress mediation. Verified by
inspection — no match for any of those patterns in the Go sources.

Real agentic deployments call GitHub, PagerDuty, Atlassian, Slack, Grafana,
Teleport, the Kubernetes API, and credential providers. Most of that traffic is
plain HTTPS issued by an SDK or a CLI, and none of it traverses `:9090`.

Enforcement is also **cooperative**: it works only because the agent was
configured to point at the sidecar. An agent that calls the upstream directly
is not arbitrated, and a compromised one has no reason to cooperate.

The five-transport taxonomy (A–E) is already documented, but `Transport` exists
in the code only as a label stamped onto generated policy
(`labels["nullfield.io/n"]` in `pkg/flow/compiler.go`). No runtime behavior is
keyed on it. A–E is vocabulary, not enforcement.

### The identity problem

`pkg/identity/jwks.go:inferIdentityType` derives identity type from a
self-asserted `identity_type` claim, falling back to classifying any token with
`sub` and an `openid` scope as **human**. The lane model grants human callers
the most permissive treatment (lane 1: ALLOW + audit) and anonymous callers the
least (lane 5: deny by default), so the most consequential input to policy is a
claim the token makes about itself.

Two consequences:

- An OBO or token-exchange result derived from a user token commonly retains
  `openid` scope, so an agent acting on a user's behalf can be classified as
  that human — the confused-deputy case the lane model exists to prevent.
- `inferIdentityType` never consults the `act` claim, even though
  `pkg/policy/rules.go` already implements `requireActChain` (RFC 8693) and
  `audienceMustNarrow` (RFC 8707). The classifier and the guards disagree about
  what constitutes evidence of delegation.

There is no SPIFFE, SPIRE, mTLS, or x509 handling anywhere in the codebase. The
only service-account tokens read are outbound, for Vault and Kubernetes secret
auth. The workload's actual cluster identity never enters a decision.

### What the target environment already provides

Verified on the `bb` cluster (k3s v1.35.5, Istio 1.30.1, ambient mode):

- `ztunnel` and `istio-cni-node` running; no sidecars. Ambient mTLS is
  available, which means every enrolled workload has a SPIFFE identity.
- Waypoints programmed in `camazotz` and `zerotrust`; both namespaces labelled
  `istio.io/dataplane-mode=ambient`.
- An `ext_authz` provider already wired and serving for 35 days:

  ```yaml
  extensionProviders:
  - envoyExtAuthzGrpc:
      includeRequestBodyInCheck:
        allowPartialMessage: true
        maxRequestBytes: 8192
      port: 9191
      service: opa-extauthz.zerotrust.svc.cluster.local
    name: opa-ext-authz
  ```

- Two `AuthorizationPolicy` resources with `action: CUSTOM`, provider
  `opa-ext-authz`, in `camazotz` and `zerotrust`.
- An Envoy AI Gateway (`aigw`, `aigatewayroute...Accepted`) fronting LLM egress.
- OPA Gatekeeper deployed (`gatekeeper-system`).
- **nullfield deployed nowhere.**

The mediation architecture nullfield needs is therefore already proven in the
target environment, with a different decision engine plugged into it.

### Why not simply write better Rego

OPA answers *is this request permitted* — a boolean. nullfield answers *what
should happen to this request* — five outcomes. Three of them cannot be
expressed as a stateless decision: HOLD needs a state machine, a timeout, and a
human approval API; SCOPE mutates the request and redacts the response;
BUDGET needs counters shared across calls. Those live in nullfield's controller.

These compose rather than compete. OPA remains appropriate for stateless
admission questions. nullfield's own roadmap already lists Rego as an
alternative rule backend.

---

## The reframe

**One artifact is currently doing two jobs, which is why heterogeneous
credential paths make attribution impossible.**

| Question | Answered by | Today |
|---|---|---|
| Will the upstream accept this call? | The **credential** | Bot token, OBO token, stored OAuth — varies per integration |
| Who authorized this, via what delegation, for what declared purpose? | The **authority** | Not represented at all |

Because these are the same object today, whatever the credential says is the
whole of what is known. A shared bot token erases the user. A user-derived
token erases the agent. Neither carries the contract that permitted the call.

**This design does not unify the credentials.** It layers authority over them.
That is what makes it adoptable in an environment where integrations are at
different maturity levels and some will never be modernized.

---

## Architecture

### The funnel

Three interception points, each covering a transport class. One decision core
behind all of them.

| Point | Covers | Mechanism |
|---|---|---|
| Waypoint | MCP JSON-RPC, Kubernetes API, GitHub, Slack, Atlassian, Grafana, PagerDuty | `ext_authz` gRPC (decisions), `ext_proc` (mutation) |
| AI Gateway | Model-proposed tool calls, before a framework dispatches them | `ext_authz` / `ext_proc` on `aigw` |

Both points are network-level, which is what makes them non-cooperative. Work
that never touches the network is addressed by neither, and is a stated non-goal
below rather than a third point in this design.

**`kubectl` is an HTTPS client to the apiserver.** So are `gh`, `aws`, and every
SaaS SDK. There is no separate CLI-interception problem for anything that talks
to a network — the mesh already sees it as HTTP. What made MCP and CLI look like
different problems is that nullfield was a JSON-RPC proxy, so only MCP fit
through it. This reduces the integration surface to **one interception
mechanism and N semantic parsers**, which is why coverage can arrive before
understanding does.

The AI Gateway point is novel: arbitrating a dangerous tool call at the moment
the model proposes it, before any framework executes it. This is where
stoneburner's `atomics toolcall` divergence measurements become a control input
rather than a report — a model measured with high channel divergence can have
its proposed calls held rather than allowed.

### The decision core is preserved

`pkg/policy` is already transport-agnostic:

```go
type Engine interface {
	Evaluate(ctx context.Context, req Request) Decision
}
```

`pkg/policy` imports no `net/http`. Neither do `pkg/registry`, `pkg/budget`,
`pkg/circuit`, or hold's core — the only HTTP imports are `hold/admin.go` and
`hold/notify.go`, which are an admin API and a webhook sender and correctly
remain HTTP. `pkg/proxy/handler.go` already delegates rather than inlining:
`verifier.Verify`, `integrity.Check`, `breaker.Allow`, `engine.Evaluate`.

An `ext_authz` server makes the same four calls from a different front door.
This is an adapter, not a rewrite.

### Identity: three facts, never conflated

| Fact | Question | Source | Forgeable by the agent |
|---|---|---|---|
| Workload identity | Who is running? | SPIFFE ID from mesh mTLS (`source.principal`) | No |
| Authority | On whose behalf? | Signed grant: initiating principal + `act` chain | Only by substitution (see below) |
| Credential | What will the upstream accept? | Unchanged, heterogeneous | Not our concern |

Authorization is decided on the first two. A shared bot token therefore stops
functioning as a laundering mechanism: the call is permitted only if the grant
says *this flow, initiated by this principal, may touch this target*, regardless
of whose credential rides along.

`identity_type` demotes from verdict to hint. Classification precedence becomes:
mesh principal establishes *what* is calling; presence and depth of the `act`
chain establishes *whether it is delegated*; the claim is corroborating evidence
only. `requireActChain` and `audienceMustNarrow` become defaults for delegated
lanes rather than opt-in per rule.

`identity.Identity` gains a mesh-principal field and an assurance field. No
existing field changes meaning.

### Measured: ambient waypoints do not deliver peer identity to ext_authz

**Status: open blocker for phase 1, found on brainbox 2026-07-26.**

The premise that a waypoint's `ext_authz` check carries the caller's SPIFFE
identity is false in ambient mode as deployed. Measured, not inferred:

ztunnel knows exactly who the caller is:

```
src.workload="meshprobe" src.namespace="zerotrust"
src.identity="spiffe://cluster.local/ns/zerotrust/sa/default"
dst.identity="spiffe://cluster.local/ns/zerotrust/sa/zerotrust-waypoint"
```

The `CheckRequest` the waypoint sends to the decision service does not:

```
source_principal: ""     destination_principal: ""
source_address:   "10.42.0.x"
header_names: [:authority :method :path :scheme accept content-length
               content-type user-agent x-envoy-auth-partial-body
               x-forwarded-proto x-request-id]
```

No principal, and no `x-forwarded-client-cert` either. This is not a nullfield
defect: the OPA provider already running in that namespace receives the same
empty source, which is why its policy reads an `x-principal` **header** rather
than the peer certificate. Someone hit this before and worked around it.

The identity exists in the mesh and is simply not plumbed to the filter. Options,
none yet chosen:

| Option | Assurance | Cost |
|---|---|---|
| EnvoyFilter with a Lua filter ordered before ext_authz, setting a header from the downstream peer URI SAN | Equivalent to mTLS, if the SAN is readable at that point | An EnvoyFilter per waypoint; must be verified, not assumed |
| Resolve `source.address` to a workload via the Kubernetes API | Weaker — pod IPs are reused over time and the lookup races pod churn | Moderate; needs a cache and an API client |
| Have callers present a signed token, attested separately | Independent of the mesh | Reintroduces the self-asserted claim this design set out to eliminate |
| Intercept somewhere that does expose peer identity | Full | Reopens the architecture |

Until one is proven on real traffic, phase 1 reaches `NONE` assurance for
mesh-internal callers and the `mesh-spiffe` attester never fires in this
topology. Everything else in phase 1 does work: MCP is detected by body parse,
transport is classified, the decision is reached, and the counterfactual is
recorded.

This is exactly the failure the `WorkloadAttester` interface was introduced to
absorb. Whichever option wins becomes a new attester with its own name and
assurance rather than an edit to the decision path.

### Workload identity is attested, not assumed

Workload identity must not be hardcoded to SPIFFE. It is established by a
`WorkloadAttester`, and the provenance record names which attester answered:

| Attester | Source | Available |
|---|---|---|
| `mesh-spiffe` | `source.principal` from mesh mTLS | Now, both lab clusters |
| `aws-pod-identity` | IRSA / EKS Pod Identity → IAM role | EKS only |
| `k8s-serviceaccount` | `TokenReview` on a projected SA token | Any cluster; weaker |
| `none` | No attestation available | Proxy mode, off-cluster agents |

This is an interface decision to make now rather than a later refactor, because
every decision path and every provenance record depends on it. AWS support is
not built in the first phases; the seam for it is.

**Corroboration upgrades assurance.** Where two attesters are independently
available — a SPIFFE ID from the mesh and an IAM role from IRSA — requiring both
to resolve to the same workload is a stronger guarantee than either alone.
`STRONG` on EKS should mean corroborated, not merely mesh-derived.

### Assurance levels

Not all attribution is equally trustworthy, and pretending otherwise is worse
than recording the difference. Every decision carries an assurance level:

| Level | Conditions |
|---|---|
| `STRONG` | Attested workload identity — corroborated where two attesters exist — dedicated workload per session, grant bound to both |
| `MEDIUM` | Attested workload identity, grant bound to workload, shared worker serving multiple principals |
| `WEAK` | No attestation available (external CI, laptop, FaaS, Fargate); token-based identity via proxy mode |
| `NONE` | Unbound workload, or no grant presented |

This absorbs agents running outside the cluster instead of excluding them, and
it makes "who authorized this" a claim with a confidence rather than one
indistinguishable from a guess.

Every level above `WEAK` presumes a grant, which phase 2 introduces. Phase 1 can
therefore reach none of them, and forcing its decisions into `MEDIUM` would
claim a grant binding that does not exist. Phase 1 emits a fifth, transitional
level instead:

| Level | Conditions |
|---|---|
| `ATTESTED` | Attested workload identity, no grant mechanism yet (phase 1 only) |

`ATTESTED` is retired when phase 2 lands: with grants available, an attested
workload resolves to `STRONG` or `MEDIUM` by the table above, and the absence of
a grant becomes `NONE` rather than a phase artifact.

### Modes

`no-op`, `observe`, and `enforce`, set **per binding** rather than globally, so
rollout proceeds flow by flow.

Observe mode records the **counterfactual** — the action that *would* have been
taken — which makes "if I enforce this flow tomorrow, what breaks?" answerable
from data before anything is switched on. In an environment nobody has fully
mapped, that shadow diff is the difference between enforcement that ships and
enforcement that gets vetoed.

The counterfactual is honest for ALLOW and DENY. It is approximate for the
stateful actions: a HOLD that would have blocked for five minutes pending human
approval cannot be meaningfully shadowed, and neither can a redaction that never
occurred. Shadow reports must label these rather than imply equivalence.

### Integration maturity tiers

Coverage must not block on the least mature integration.

| Tier | Meaning | Cost |
|---|---|---|
| **T0 — Seen** | Mediated and attributed; host-level only, no semantics | Free once the waypoint exists |
| **T1 — Parsed** | Method and path map to an operation, so `DELETE /repos/{o}/{r}` is known-destructive | Per-integration parser |
| **T2 — Contracted** | Operations *and resources* map to the flow's declared capability set | Per-integration, expensive — see residual risk |
| **T3 — Brokered** | nullfield injects the credential; the agent holds nothing | Per-integration credential support |

Every target starts at T0 on the day its waypoint exists. GitHub can be at T2
while Grafana is at T0, and the provenance graph is coherent across both.

---

## What changes in the codebase

### New

- `pkg/extauthz` — gRPC server implementing
  `envoy.service.auth.v3.Authorization/Check`. Translates `CheckRequest` into
  `policy.Request`, and `policy.Decision` into `CheckResponse`.
- `pkg/grant` — mint, sign, verify, and bind authority grants. Binding covers
  workload identity, session, and contract version hash.
- `pkg/provenance` — the decision record: workload identity, authority chain,
  contract version, transport class, target, operation, action taken, action
  that would have been taken, assurance level, rule, reason class.
- `cmd/nullfield-extauthz` — entrypoint, or a mode flag on `cmd/nullfield`.

### Modified

- `pkg/identity` — `Verifier.Verify(*http.Request)` widens to accept a header
  accessor so both front doors can use it. `Identity` gains mesh-principal and
  assurance fields, additively.
- `pkg/policy` — `Request` gains transport class, target, operation, and grant.
  `Decision` gains the counterfactual action. Existing fields unchanged.
- `pkg/flow` — `AgenticFlow` gains transport declarations, connection-upgrade
  capability, forbidden combinations, and resource scoping where the tier
  supports it.
- `pkg/audit` — emits the provenance record; v0.10 decision context is the seed.

### Preserved unchanged

The rule engine, tool registry with lifecycle and rug-pull detection, budget and
cost attribution, hold state machine and controller, anomaly detection,
credential providers, the AgenticFlow compiler, and the CRD watcher. Proxy and
gateway modes remain as the non-mesh deployment path, so `pkg/proxy`, the
router, and the admission injector keep their purpose.

---

## Data flow

One MCP `tools/call` from a bound agent, in enforce mode:

1. Agent issues `POST /mcp` to an in-cluster MCP server.
2. ztunnel establishes mTLS; the waypoint receives the request with the peer's
   SPIFFE identity.
3. The waypoint calls nullfield's `Check` with headers, body (subject to the
   body limit), and `source.principal`.
4. `pkg/extauthz` resolves workload identity from `source.principal`, extracts
   and verifies the grant, and derives the assurance level.
5. The contract is resolved by workload identity; the grant's pinned contract
   hash is compared against the current one.
6. `identity`, `integrity`, `circuit` run as they do today.
7. `engine.Evaluate` returns a `Decision`.
8. `pkg/provenance` emits the record regardless of mode.
9. Mode governs the response: `no-op` and `observe` return OK with the
   counterfactual recorded; `enforce` returns OK, Denied, or defers to the hold
   state machine.

An unbound workload has no contract, so it receives the mode default — logged
under `observe`, denied under `enforce`.

---

## Non-goals

Stated as non-goals because each is a limit of the approach, not a backlog item.

- **In-stream content inspection.** Authorizing a connection is not authorizing
  what flows through it. See residual risk.
- **Attribution in downstream audit logs.** Unless an integration reaches T3,
  GitHub's own audit log still shows the bot. This design fixes attribution in
  *our* plane, which is sufficient for incident response and insufficient for
  downstream compliance.
- **Mediating non-network subprocess work.** Out of reach of the mesh. "Most
  scenarios" is the accurate claim.
- **Teleport through the funnel.** Teleport is an identity-aware proxy doing its
  own cert-based mTLS and tunneling; mesh-level L7 inspection is likely both
  infeasible and wrong. Integrate at Teleport's RBAC and audit layer instead.
- **Replacing OPA.** Gatekeeper and OPA ext_authz keep their roles.
- **Enforcement in the first phase.**

---

## Residual risk

Recorded because these survive the design and must not be discovered later.

### Connection upgrades defeat per-request mediation

`ext_authz` fires per request. `kubectl exec`, `port-forward`, `logs -f`, MCP
over SSE, gRPC streams, and WebSockets are long-lived: the upgrade is
authorized, and everything inside it is invisible. A single ALLOW on
`kubectl exec` is arbitrary code execution that appears in the provenance graph
as one tidy authorized call.

Mitigation, not solution: treat upgrades as a distinct capability class that a
contract must declare explicitly, default them to DENY, and require HOLD where
they are permitted. If an MCP transport is streaming, per-call mediation does
not apply and the contract must say so.

### Shared workers cap attribution at MEDIUM

When one process serves multiple principals concurrently, the grant must be
per-request, so the agent propagates it — and a compromised agent can swap
grants between concurrent requests. The mesh cannot detect this. Strong
attribution requires one workload per session or cooperation from the component
we do not trust. Hence assurance levels rather than a claim of strong
attribution everywhere.

### Individually-authorized calls compose into attacks

A flow permitted to read Atlassian and write Slack can exfiltrate: pull secrets
from a ticket, post to a public channel. Both calls pass; the violation is a
property of the sequence. v0.5 tool-chain sequence detection is the seed, but
contracts must express forbidden *combinations*, not only permitted operations.

### Operation-level scoping leaves the confused deputy alive

"This flow may call GitHub" does not say which repositories. Injection can aim
an authorized capability at a resource the initiating principal should never
touch. Real containment needs resource-level scoping, which varies per
integration and makes T2 substantially more expensive than the ladder suggests.

### Grant minting is a trust boundary

If the agent requests its own grant it can lie about the initiating principal.
Minting must live in whatever receives the human's request. Every entry point —
UI, chat bot, API, cron — is a separate integration, and any one of them getting
it wrong forges authority. Grants must bind to workload identity and session so
an agent holding two cannot present the more privileged one.

### The arbiter becomes a hard dependency

`ext_authz` must fail one way. Fail closed and nullfield being down stops all
agent traffic, including during its own upgrade. Fail open and the bypass
activates exactly under stress. Likely per-flow by criticality; must be decided
before anything is enforced.

### Body truncation is a bypass

The current provider sets `maxRequestBytes: 8192` with
`allowPartialMessage: true`, so an oversized body yields a decision rendered on
data the arbiter cannot see. Oversized bodies must fail closed. This applies to
the existing OPA deployment today, independent of this work.

### TLS termination for external egress

L7 policy on egress to `api.github.com` requires the waypoint to terminate and
re-originate TLS. Anything pinning certificates breaks.

---

## Phasing

This document is an architecture spec, not a single implementation unit. Each
phase is independently useful, independently shippable, and gets its own
implementation plan.

| Phase | Delivers | Gate to next |
|---|---|---|
| **0** | Deploy nullfield **as it exists today** — proxy mode, sidecar — against non-ambient camazotz on `system76-pc` | Helm chart and manifests verified against a live cluster; regression baseline captured |
| **1** | `pkg/extauthz` + SPIFFE identity + provenance records, observe-only, deployed beside OPA | Decisions recorded for real traffic with correct workload identity |
| **2** | Grants, contract binding, assurance levels, shadow counterfactuals | Shadow diff answers "what would enforcement break" |
| **3** | External egress: `ServiceEntry` + egress waypoint for one T1 integration (GitHub) | A non-MCP call mediated end to end |
| **4** | AI Gateway interception of model-proposed tool calls | A dangerous proposed call denied pre-dispatch |
| **5** | Selective enforcement per binding; upgrade-class denial | — |

Phase 0 exists because building the new front door first and *then* discovering
the existing deployment path had rotted is the expensive order to find out.
Demo 14 exercised it once on k3s, so re-establishing it should be short, and it
is what makes regression constraint 1 checkable rather than aspirational.

Phase 3 is the largest single item: no `ServiceEntry` exists on either cluster
today, so external SaaS egress is currently unregistered and unmediated.

---

## Deployment targets

### Lab clusters

Two k3s clusters, both v1.35.5 with the same Istio 1.30.1 `istiod` build in
ambient mode (`ztunnel` + `istio-cni`), each with a programmed waypoint and an
identical `envoyExtAuthzGrpc` provider already configured. Phase 1 therefore
requires no new mesh infrastructure on either — nullfield registers as a second
provider beside OPA.

| | `bb` | `system76-pc` (NUC) |
|---|---|---|
| Ambient namespaces | `camazotz`, `zerotrust` | `zerotrust` |
| camazotz | ambient-enrolled | **not** enrolled |
| Also present | Envoy AI Gateway, Gatekeeper | Teleport, cert-manager, kubegoat, dvmcp |
| Role | Mesh path; phase 4 AI-gateway work | Phase 0 proxy-mode baseline; Teleport reality check |

The asymmetry is deliberate and worth preserving. The NUC's non-ambient camazotz
provides a proxy-mode regression baseline in the same lab, which is what makes
regression constraint 1 testable. Its Teleport deployment lets the Teleport
non-goal be *verified* rather than asserted. Its long-running cert-manager is a
candidate PKI for phase 2 grant signing.

### EKS

The design depends on Istio capabilities — ambient, `ext_authz`, mesh mTLS
SPIFFE — rather than anything distribution-specific, which is the reason for not
writing bespoke interception. It should port. Four caveats:

- **Fargate cannot run ambient.** `ztunnel` and `istio-cni` are DaemonSets
  requiring node-level access. This is architectural, not configuration.
  Fargate workloads fall back to proxy mode at `WEAK` assurance.
- **`istio-cni` must chain with the AWS VPC CNI.** Generally works; Security
  Groups for Pods (branch ENIs) is a known friction area for traffic
  redirection and needs verifying against the actual VPC CNI configuration.
- **Apiserver mediation may differ.** Open question 3 depends on how the control
  plane is reached, which is local on k3s and managed behind ENIs on EKS. It
  must be answered per platform.
- **Image distribution is a prerequisite.** `ghcr.io/babywyrm/nullfield` is not
  anonymously pullable (unauthenticated manifest request returns 401). k3s can
  side-load via `ctr images import`; EKS needs a published image or an
  `imagePullSecret`. Because no git tag exists, `make docker` currently produces
  a commit-SHA tag and `:latest`, neither of which is pinnable in a real
  deployment.

EKS also offers something the lab cannot: IRSA / EKS Pod Identity is a second,
independent, cryptographically derived workload identity, which can corroborate
the SPIFFE ID. It also makes T3 credential brokering tractable for AWS targets
via STS.

Sequence: NUC, then `bb`, then EKS.

---

## Verification

Each phase must demonstrate on real traffic through a waypoint, not through
unit-level fakes. The existing `demos/` pattern (14 numbered runnable
walkthroughs with `test.sh`) is the vehicle; demo 14 already proves
CRD → controller → sidecar → runtime enforcement on k3s, so the pattern extends.

Non-negotiable per phase: a demo that a reviewer can run, and a provenance
record produced by real traffic.

---

## Regression safety

Constraints that must hold, because the value of the existing work depends on
them.

1. **Proxy mode keeps working unchanged.** `docker compose up` plus
   `tests/smoke.sh` (12 checks) must pass throughout. Proxy mode is the
   non-mesh deployment path, not deprecated.
2. **`policy.Engine` semantics do not change.** First-match, default-deny, and
   the five actions behave identically. Additions to `Request` and `Decision`
   are additive with zero-valued defaults.
3. **`go test ./...` stays green.** Baseline at design time: 17 packages, zero
   failures.
4. **No existing `NullfieldPolicy` or `ToolRegistry` document changes meaning.**
   Contract binding is additive; an unbound workload gets the mode default, and
   the default mode is `observe`.
5. **SCOPE and response inspection are not silently degraded.** `ext_authz`
   cannot mutate bodies or observe responses. Those features must either run via
   `ext_proc` or continue to require proxy mode — and nullfield must refuse to
   start, loudly, if a policy requires them in a mode that cannot deliver them.
   Silently ignoring a SCOPE rule would turn a redaction into a leak.
6. **The camazotz registry stays in sync.** CI already verifies 138/138.

---

## Open questions

Each needs an answer before the phase that depends on it.

1. **Does Istio 1.30.1 support `envoyExtProc` as an extension provider?** Not
   verified; could not confirm from the distribution files on `bb`. Blocks
   SCOPE and response inspection over the mesh (phases 4–5).
2. **What is the fail-open/fail-closed default for a `CUSTOM`
   `AuthorizationPolicy`, and is it configurable per policy?** Blocks phase 5.
3. **Can Kubernetes apiserver traffic be routed through a waypoint** so
   `kubectl` is mediated, given the apiserver is reached via
   `kubernetes.default.svc`? Blocks the kubectl claim in phase 3. Must be
   answered **per platform**: the control plane is node-local on k3s and managed
   behind ENIs on EKS, so a positive result in the lab does not transfer.
4. **Does the IdP support RFC 8693 token exchange** with audience narrowing for
   the integrations that matter? Determines whether T3 is reachable per
   integration, and whether downstream attribution is ever fixable.
5. **Which entry points can mint grants** — and who owns each? Determines the
   real size of phase 2.
6. **What latency budget is acceptable** per call, given a synchronous gRPC hop,
   body buffering, and a possible controller hop for shared budgets and holds?
