# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]

### Added

- **`ext_authz` decision service** (`pkg/extauthz`, `cmd/nullfield-extauthz`) — nullfield answers Envoy external authorization checks, a second inbound adapter onto the same decision core the HTTP proxy uses. Deployed and exercised against real waypoint traffic on a k3s + Istio 1.30.1 ambient cluster.

  Only enforce mode can deny; observe and no-op return OK unconditionally, and an unrecognised mode falls back to observe with a warning rather than failing to start, so a typo cannot begin refusing production traffic. Policy outcomes return a `CheckResponse` rather than a gRPC error, because an error makes Envoy apply its own failure-mode default and takes the decision out of nullfield's hands.

  MCP is detected by parsing the request body rather than by URL, since JSON-RPC is not distinguishable by path; anything else classifies as transport B with an operation of method plus path, which is what makes non-MCP traffic expressible in policy at all. The body is read from `raw_body` when `body` is empty, because Envoy populates the former under `pack_as_bytes` — reading only `body` would make every `tools/call` under that configuration parse as ordinary wire traffic, a silent total loss of MCP coverage rather than a visible failure.

  Assurance tops out at `ATTESTED`. `STRONG` and `MEDIUM` both presume a grant bound to the workload, so claiming either now would assert a binding that does not exist.

- **Workload attestation** (`pkg/identity`) — `WorkloadAttester` derives workload identity from transport evidence rather than a self-asserted claim, with the provenance record naming which attester answered. An interface from the first commit rather than a later refactor, because EKS brings IRSA and Pod Identity as independent attesters and, where two agree, the corroboration is worth more than either alone. `Attestation` is deliberately not an `Identity`: one answers what is running, the other whose authority is being exercised, and collapsing them is how a confused deputy happens.

- **Provenance on audit events** — `workload_principal`, `attester`, `assurance`, `transport`, and `counterfactual`, all `omitempty` so proxy-mode events serialize byte-identically and existing consumers see no new keys. The new `arbiter.decision` event type is distinct from `tool.allowed` and `tool.denied` on purpose: in observe mode the arbiter reaches a verdict without applying it, and reporting that as `tool.denied` would tell every dashboard traffic was blocked when none was.

- **Transport, target, and operation in policy requests** — the transport taxonomy previously existed only as a label on generated policy, so no rule could distinguish an MCP call from a wire API call to the same target. All additive with inert zero values.

### Fixed

- **Truncated request bodies are refused instead of authorized** — the reference `ext_authz` configuration pairs `maxRequestBytes: 8192` with `allowPartialMessage: true`, so a decision gets rendered on a body the arbiter cannot fully see. Put the dangerous arguments past the boundary and the gate approves what it never read. nullfield's provider sets `allowPartialMessage: false` and refuses before consulting the engine, trusting Envoy's own `x-envoy-auth-partial-body` header over any inference from `content-length` or the size attribute.

- **Mesh identity at ambient waypoints** (`deploy/manifests/peer-principal-envoyfilter.yaml`) — an ambient waypoint does not deliver peer identity to an external authorization service. Measured on brainbox, not inferred: ztunnel logs the caller's SPIFFE ID correctly while the `CheckRequest` arrives with an empty `source.principal`, no destination principal, and no `x-forwarded-client-cert`. Not a nullfield defect — the OPA provider in the same namespace receives the same empty source, which is why its policy reads an `x-principal` header rather than the peer certificate.

  Probing every source reachable from that filter chain located it: the waypoint terminates HBONE upstream of the listener running `ext_authz`, so there is no TLS object there at all, and Istio publishes the terminated connection's identity into Envoy **filter state** instead. That is how `AuthorizationPolicy` principals keep working at waypoints; `ext_authz` simply does not read filter state.

  A Lua filter ordered before `ext_authz` copies the filter-state principal into `x-nullfield-peer-principal`. nullfield does not trust that header: the filter strips any inbound value of the same name first, so a workload cannot assert its own identity by sending it. Because that property lives in the deployed filter rather than in cryptography, header-derived identity is a distinct `mesh-header` attester rather than a fallback inside `mesh-spiffe` — same identity, different binding, and the provenance record says which one answered.

  Rejected: resolving `source.address` through the Kubernetes API. Pod IPs are recycled and the lookup races pod churn, so a workload landing on a recently-freed address inherits another's attribution — weaker than the self-asserted claim this replaces.

### Known limits

- **`allowPartialMessage` must match the mode, or observe mode breaks traffic** — measured. With `allowPartialMessage: false`, Envoy rejects any body exceeding `maxRequestBytes` with a 413 *before* calling the check: nullfield never sees the request and cannot observe it, yet the traffic is already broken. A rollout declared read-only starts failing large requests. Observe and no-op therefore require `true`, where Envoy forwards what fit plus `x-envoy-auth-partial-body` and nullfield records a `body_truncated` counterfactual without touching the response. Enforce should use `false`, since failing closed at the proxy is stronger than denying after the fact, with the in-process guard remaining as defence in depth.

  The reference OPA provider in the test mesh runs `true` while enforcing, which is the live bypass this guard exists for: confirmed on real traffic, OPA rendered a decision having seen 8192 bytes of a 20109-byte request.

- **Deploying beside an existing provider needs a feature flag** — Istio rejects multiple `CUSTOM` authorization providers per workload unless `PILOT_ENABLE_MULTIPLE_CUSTOM_AUTHZ_PROVIDERS` is set on istiod. Without it the second policy is silently dropped and the incumbent decides alone.

- **`CUSTOM` policies must name the waypoint in `targetRefs`** — an unbound policy in ambient mode attaches to ztunnel, which is L4 only. The policy is accepted, reports healthy, and never fires.

- **Design: mesh-native arbiter** (`docs/specs/2026-07-26-mesh-native-arbiter.md`) — nullfield becomes a policy *decision* point reached through the service mesh rather than a proxy agents must be configured to use. No code yet; the spec, roadmap, and known limits are recorded first.

  Three shifts. nullfield speaks `ext_authz` gRPC behind an Istio waypoint, so the mesh performs interception and nullfield decides — which extends coverage from MCP JSON-RPC to any HTTP-borne agentic traffic, since a CLI calling an API is just HTTP the mesh already sees. Workload identity is derived from mesh mTLS (`source.principal`) instead of the self-asserted `identity_type` claim, whose `openid`-scope fallback can classify a delegated agent as the human it acts for. And an `AgenticFlow` binding becomes required, making the contract the unit of authorization rather than the individual rule.

  The decision core needs no rewrite: `pkg/policy` already exposes a single `Evaluate(ctx, Request) Decision` interface and imports no `net/http`, as do `pkg/registry`, `pkg/budget`, and `pkg/circuit`. `ext_authz` is an adapter onto the same four calls `pkg/proxy/handler.go` already makes. Proxy and gateway modes remain the non-mesh deployment path.

  Recorded as known limits rather than future work, because they are properties of the approach: connection upgrades (`kubectl exec`, streaming MCP over SSE) are authorized once and then invisible; shared workers cap attribution, which is why decisions carry an assurance level instead of an unqualified claim; and attribution stops at the mesh boundary until credentials are brokered per principal.

  Verified against the target environment rather than assumed — Istio 1.30.1 in ambient mode with programmed waypoints, an `ext_authz` provider already serving for 35 days, and an Envoy AI Gateway fronting LLM egress. The architecture is proven there with a different decision engine plugged into it.

  Deployment targets are recorded with their asymmetries: two k3s v1.35.5 clusters on the same Istio build, one with camazotz ambient-enrolled and one without — the latter is what makes the proxy-mode regression baseline testable rather than aspirational, and it carries a live Teleport deployment so the Teleport non-goal can be verified instead of asserted. EKS should port, since the design depends on Istio capabilities rather than distribution specifics, with four caveats: Fargate cannot run ambient at all, `istio-cni` must chain with the AWS VPC CNI, apiserver mediation must be re-answered per platform, and `ghcr.io/babywyrm/nullfield` is not anonymously pullable so EKS needs a published image or a pull secret.

- **AgenticFlow least-privilege authoring layer** — new `AgenticFlow` YAML format compiles known acceptable paths into existing nullfield enforcement artifacts:
  - `cmd/nullfield-compile` emits multi-document YAML from an `AgenticFlow`
  - `pkg/flow` compiler emits `NullfieldPolicy`, `ToolRegistry`, optional `NetworkPolicy`, Istio `AuthorizationPolicy`, Cilium `CiliumNetworkPolicy`, and Linkerd `Server` / `ServerAuthorization`
  - Central `credentials:` declarations with per-tool `credentialRefs`; undeclared credential refs fail compilation
  - OAuth audience/scope metadata is preserved as rule audit labels
  - Network/mesh generation is opt-in and fail-closed: selectors, destinations, ports, methods, principals, and identities must be explicit
- **Decision context in audit events** — policy decisions now carry stable `gate`, `reason_class`, `rule_id`, `rule_index`, route/session/target context, and bounded audit labels through logs, metrics, OTLP, and controller events. Prometheus labels use low-cardinality `gate` and `reason_class` instead of raw denial reasons
- **AgenticFlow CRD reconciliation** — `deploy/crds/agenticflow-crd.yaml` and `pkg/crdwatcher` support `agenticflows.nullfield.io`; the controller compiles each flow into a managed `nullfield-flow-<name>` ConfigMap containing `compiled.yaml`, `policy.yaml`, and `tools.yaml`
- **AgenticFlow demos**:
  - Demo 13 — local compile demo proving ALLOW / SCOPE credential / HOLD / DENY / default-deny output
  - Demo 14 — Kubernetes runtime demo proving `AgenticFlow` CRD → controller compile → sidecar-mounted ConfigMap → real MCP ALLOW / DENY / registry-deny behavior

### Verified

- `go test ./...`
- `go run ./cmd/nullfield-compile examples/agentic-flow.yaml`
- NUC k3s: `bash demos/14-agentic-flow-kubernetes/test.sh camazotz` verifies live CRD reconciliation and runtime MCP enforcement through a nullfield sidecar

### Documented

- **`includeRequestBodyInCheck` truncation is a bypass, not a tuning knob.** The reference `ext_authz` configuration pairs `maxRequestBytes: 8192` with `allowPartialMessage: true`, so a body larger than the limit yields an authorization decision rendered on data the arbiter cannot see. The design spec requires `allowPartialMessage: false` so oversized bodies fail closed. This applies to any existing ext_authz deployment, independent of this work.

### Changed

- **Camazotz tool registry re-sync to 138 tools** — `integrations/camazotz/tools.yaml` and `policy.yaml` updated from 85 to 138 tools against live camazotz `tools/list` (2026-05-23). 53 new tools categorized: +21 read-only (tier 1), +22 write/action (tier 2), +10 high-risk deny (tier 3). New lab modules covered: agent HTTP bypass, chain delegation, code review, DPoP, exec gateway, LangChain tool injection, LLM chain, platform ops, pre-auth, RAG, rate limiting, schema probing, shell wrapper, and subchain spawning. All entries alpha-sorted within tiers. `sync-tools.sh` confirms 138/138 in sync

---

## [0.9.0] — 2026-05-22

### Added

- **Tool lifecycle + rug-pull detection** — `pkg/registry/lifecycle.go` implements continuous tool-set reconciliation against upstream `tools/list`. `LifecycleTracker` stores a `ComputeHash` of the registered tool set at init; `Reconcile` diffs periodically and emits a `DriftReport` when tools appear, disappear, or mutate schema post-startup. Detects MCP-T03 rug-pull attacks (tool behavior/definition changes after the session is established). 14 unit tests
- **Response inspection in handler pipeline** — inspection findings detected in upstream MCP responses (system prompt leakage, PII, sensitive patterns). Configurable per-rule via `onFinding:` with three actions: `DENY` (reject the response with `-32007`), `REDACT` (strip the finding and forward), `AUDIT` (log and forward unchanged). New `InspectionConfig` type in `api/v1alpha1/types.go`. New audit event types: `inspection.finding`, `inspection.redact`. New JSON-RPC error code `-32007` (inspection policy violation). 6 unit tests
- **Cost attribution** — `GetUsageReport` aggregates tool-call cost per identity and per session using `CostConfig` / `CostRate` definitions in policy. `GetToolCost` helper returns the cost of a single call. Reports sorted by highest cost first. 6 unit tests

- **Full camazotz tool coverage in starter bundle** — `integrations/camazotz/tools.yaml` and `policy.yaml` now register all 85 tools exposed by camazotz `tools/list` (was 57 of 85, with 28 silently default-denied). The 28 newly-tiered tools split as +11 read-only (tier 1), +8 write/action (tier 2), +9 high-risk (tier 3). High-risk additions cover bot-identity replay (`bot_identity_theft.read_tbot_secret`, `replay_identity`), cert replay (`cert_replay.replay_cert`), policy mutation (`policy_authoring.submit_policy`), SDK token-cache exposure (`sdk.get_cached_token`, `sdk.invoke_as_cached`), subprocess execution (`subprocess.invoke_worker`, Transport D), and Teleport role escalation (`teleport_role_escalation.{request_role,privileged_operation}`)
- **`integrations/camazotz/sync-tools.sh`** — portable diff-only sync script. Takes any MCP endpoint URL (Compose, K3s NodePort, EKS/GKE ingress, port-forward), fetches `tools/list`, and prints `added` / `removed` against the local registry. Exits 0 if in sync, 1 if drift. Does not auto-modify files — tier placement stays a human judgment
- **Camazotz K8s reference integration** — `brain-gateway-policed` Service exposes a nullfield-enforced entry point alongside the bypass path
  - NodePort `:30090` → sidecar listen `:9090` (policy enforcement on)
  - NodePort `:31591` → sidecar admin `:9091` (status, holds, metrics)
  - Default `:30080` remains the direct-to-`brain-gateway` bypass for comparison
  - Manifest in camazotz: `kube/brain-gateway-policed.yaml`
  - Smoke verification: `make smoke-k8s-policed` (`scripts/smoke_test.py --target k8s --require-policed`)
  - Live behavior on NUC: unauthenticated MCP requests via `:30090` return JSON-RPC `-32001 identity verification failed`; `:30080` returns 200
- **Per-rule guard primitives enforced** — `identity.requireActChain` (RFC 8693), `identity.audienceMustNarrow` (RFC 8707), and `delegation.maxDepth` are evaluated in `pkg/policy/rules.go` (`evaluateIdentityGuards`, `evaluateDelegationGuards`); failing guards short-circuit the rule and continue the match loop
- **Per-lane policy templates** — `policies/by-lane/lane-{1..5}-{name}.yaml` ship as starter `NullfieldPolicy` per agentic-identity lane; transport label `A`-`E` follows [camazotz ADR 0001](https://github.com/babywyrm/camazotz/blob/main/docs/adr/0001-five-transport-taxonomy.md)

### Documentation

- README marks the CRD bridge shipped (was "planned"), cites ADR 0001 for the five-transport taxonomy, and adds a per-lane templates table
- `docs/mesh-integration.md` adds a "K8s sidecar mode (camazotz reference)" section
- `docs/quickstart.md` references the camazotz `:30090` policed entry point as the canonical K8s sidecar smoke target
- `integrations/camazotz/README.md` refreshed to 52 lab modules / 138 tools (verified live), adds the policed `:30090` invocation, and updates the L4 delegation row to reflect `requireActChain` + `maxDepth` enforcement
- `policies/by-lane/README.md` confirms the three primitives are enforced as of 2026-05-01

---

## [0.8.0] — 2026-04-23

### Added

- **CRD controller** — NullfieldPolicy and ToolRegistry as native K8s Custom Resources
  - `deploy/crds/nullfieldpolicy-crd.yaml` — NullfieldPolicy CRD (`nfp` shortname)
  - `deploy/crds/toolregistry-crd.yaml` — ToolRegistry CRD (`nftr` shortname)
  - `pkg/crdwatcher/` — lightweight watcher, no client-go dependency
  - Polls CRDs on configurable interval (default 30s), syncs to ConfigMaps
  - ConfigMaps named `nullfield-policy-{name}` and `nullfield-registry-{name}`
  - Managed-by labels for GitOps identification
  - Opt-in via `NULLFIELD_CRD_WATCH=true` on the controller
  - `examples/crd/` — example NullfieldPolicy and ToolRegistry CRs
  - 5 unit tests (create, update, empty list, API error)

### Usage

```bash
kubectl apply -f deploy/crds/
kubectl apply -f examples/crd/policy-example.yaml
# Controller syncs to ConfigMap: nullfield-policy-camazotz-policy
```

---

## [0.7.0] — 2026-04-20

### Added

- **Credential injection** — SCOPE rules can now fetch real secrets at request time
  - Vault provider (HTTP API, K8s auth or token auth)
  - K8s Secret provider (in-cluster API, no client-go dependency)
  - Env provider (backward compatible with existing `injectArguments`)
  - MultiProvider router — `from: "vault"`, `from: "k8s"`, `from: "env"`
  - `injectCredentials` on SCOPE request config — resolve and inject as tool args
  - TTL cache (default 5 min) wraps external providers, configurable via `NULLFIELD_CREDENTIAL_CACHE_TTL`
  - Credential fetch failures fail closed (deny the request, never forward without the secret)
  - 9 unit tests (provider, cache, vault mock, multi-provider)
- **Gateway mode** — single nullfield instance proxying multiple MCP servers
  - Per-route policy engine and tool registry, shared identity verification
  - Tool routing by prefix match (`github.*`) or exact tool name list
  - Exact match takes priority over prefix match
  - `NULLFIELD_ROUTES_PATH` config, mutually exclusive with `NULLFIELD_UPSTREAM_ADDR`
  - Unmatched tools rejected with `-32003 no route for tool`
  - `docker-compose-gateway.yaml` with 2-upstream local dev example
  - Example routes config + per-route policy/registry in `examples/gateway/`
  - 5 unit tests (exact match, prefix match, priority, no match, all tools)
- **Mutating admission webhook** (`nullfield-injector`) for automatic sidecar injection
  - Annotation-driven: `nullfield.io/inject: "true"` to opt in
  - Auto-detects upstream port from first container, override with `nullfield.io/upstream-port`
  - Per-pod policy/registry via `nullfield.io/policy` and `nullfield.io/registry` annotations
  - Idempotent — skips pods with existing nullfield container or `nullfield.io/status: injected`
  - Hardened sidecar: nonroot UID 65534, read-only rootfs, all capabilities dropped
  - Zero k8s.io/api dependency — uses minimal admission review types and JSON Patch (RFC 6902)
  - TLS support for production, plaintext for dev mode
  - `Dockerfile.injector` — distroless container image
  - 9 unit tests (inject, skip, annotations, security context, idempotency)

### Verified On

- Docker Compose sidecar mode (macOS, Docker Desktop) — 11/12 smoke tests
- Docker Compose gateway mode (macOS, Docker Desktop) — 5/5 routing scenarios
- K3s v1.34.6+k3s1 (single-node, Ubuntu 24.04) — sidecar on camazotz brain-gateway, 57 tools

---

## [0.6.0] — 2026-04-19

### Added

- **Controller pod** — standalone control plane for stateful coordination
  - Centralized holds — all sidecars delegate HOLD decisions to the controller via gRPC
  - Shared budget state — per-identity/session counters are centralized (no N× budget with N replicas)
  - Webhook/Slack alerting — controller dispatches alerts with dedup and rate limiting
  - Admin dashboard — unified /admin API (holds, budgets, events, targets)
  - Sidecar registration — sidecars announce to controller on startup
  - Backward compatible — controller is opt-in via `NULLFIELD_CONTROLLER_ADDR`
- **Universal Helm chart** — target-agnostic distribution
  - `targets[]` list with per-target ConfigMaps for policy and registry
  - `files/` directory for bundled per-target policy/registry YAML
  - ServiceMonitor, PrometheusRule, Grafana dashboard as chart templates
  - Controller Deployment/Service/ConfigMap when `controller.enabled`
- **gRPC proto** — NullfieldController service: CheckBudget, CreateHold, ReportEvent, RegisterSidecar
- **Demos 04-09** — sidecar compose, sidecar kubernetes, hold action, budget action, scope action, controller mode
- **Quickstart guide** — `docs/quickstart.md`
- 24 new tests

---

## [0.5.0] — 2026-04-18

### Added

- **OTLP trace export** — OpenTelemetry spans for every decision (opt-in via `NULLFIELD_AUDIT_ENDPOINT`)
- **Tool-chain sequence detection** — configurable suspicious call patterns per session (8 tests)
- **Claims drift detection** — detect scope/group changes mid-session (8 tests)
- **Observability stack** (`deploy/operations/`): Grafana dashboard (8 panels), ServiceMonitor, 5 Alertmanager rules

---

## [0.4.0] — 2026-04-18

### Added

- **SCOPE action** — modify tool call requests and responses in transit. Strip dangerous arguments, inject scoped credentials, redact sensitive patterns in responses. Standalone action with full audit trail of what was modified. 9 unit tests.

---

## [0.3.0] — 2026-04-18

### Added

- **HOLD action** — park tool calls for human approval
  - `pkg/hold/manager.go` — hold state machine (pending -> approved/denied/timeout)
  - `pkg/hold/admin.go` — REST API: GET /admin/holds, POST approve/deny
  - `pkg/hold/notify.go` — webhook notification on hold creation
  - Hold config in policy YAML: timeout, onTimeout, notify.webhook
  - Error code -32005 (ErrCodeHoldTimeout) for timed-out holds
  - 9 unit tests covering approve, deny, timeout, list, history, double-approve
- **BUDGET enforcement** — per-identity and per-session call/token budgets. Attach `budget:` to any ALLOW rule to enforce hourly/daily call limits and daily token limits. `onExhausted: DENY` rejects with `-32004`.
- **Arbiter model** — `docs/arbiter-model.md` defining the five nullfield actions (ALLOW, DENY, HOLD, SCOPE, BUDGET), decision chain, YAML spec, error codes

---

## [0.2.0] — 2026-04-17

### Added

- **L2: Identity-aware policy** — opt-in identity validation and conditional policy rules
  - JWT/JWKS verification with multi-provider support (RS256, ES256, key caching)
  - `when:` blocks on rules — match by identity type (human/agent/autonomous), provider, and claims
  - Session binding — detect mid-session identity swaps
  - Token replay detection — reject reused JTI claims
  - All features off by default — existing policies work unchanged
  - `docs/identity-policy.md` — four-level configuration guide
  - 15 unit tests
- **Prometheus metrics** — `/metrics` endpoint on admin port (tool call counters, deny counters, identity failures, circuit trips, anomaly alerts)
- **Velocity detection** — per-identity tool call rate tracking with configurable threshold and alertAction
- **Demos** — `demos/` directory with runnable walkthroughs (basic filtering, JWT identity tracking, anomaly detection)
- **Observability guide** — `docs/observability.md`
- **Repo restructure** — `integrations/`, `meshes/`, `docs/` as top-level concerns
- **Camazotz integration** — 57 tools registered, three-tier policy, 15-point integration test
- **Architecture docs** — `docs/architecture.md` (request lifecycle, decision chain, package map, L1-L4 security model)
- **Diagrams** — `docs/diagrams/traffic-flow.md` and `docs/diagrams/policy-eval.md`
- **Service mesh overlays** — Istio, Linkerd, Cilium in `meshes/`
- **Mesh integration guide** — `docs/mesh-integration.md`
- **Helm mesh support** — `mesh.provider` value
- **Kustomize base** — `deploy/manifests/kustomization.yaml`

---

## [0.1.0] — 2026-04-17

Initial release. MCP/agentic traffic sidecar proxy with default-deny posture.

### Added

- **MCP JSON-RPC proxy** — intercepts `tools/call`, `tools/list`, `resources/read`, `initialize`, `ping` and all other MCP methods
- **Tool registry** — file-backed allowlist loaded from YAML at startup
- **Policy engine** — first-match rule evaluation (ALLOW/DENY) per tool name, per MCP method
- **Identity verification** — extracts Bearer token from configurable header. Noop verifier for dev mode.
- **Circuit breaker** — per-session tool call count and duration limits
- **Structured audit logging** — every proxied action emits a JSON audit event
- **Admin endpoints** — `/healthz` and `/readyz` on a separate port
- **Docker Compose** — local dev environment with nullfield proxy + echo MCP server
- **K8s manifests** — namespace, deployment (sidecar pattern), service, RBAC, ConfigMaps
- **Helm chart** — sidecar template helper, ConfigMap template, values file
- **Smoke tests** — 12-point test script
- **Echo MCP server** — test fixture for local and CI testing
- **Implementation guide** — cluster adoption guide

### Security

- Distroless container image (`gcr.io/distroless/static-debian12:nonroot`)
- Runs as UID 65534 (nonroot), read-only root filesystem, all capabilities dropped
- Default-deny posture — no rules loaded means all `tools/call` requests are rejected
- 1 MiB request body cap to prevent payload abuse

### Verified On

- Docker Compose (macOS, Docker Desktop)
- K3s v1.34.5 (single-node, Ubuntu 24.04)
