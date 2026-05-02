# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]

### Added

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
- `integrations/camazotz/README.md` refreshed to 35 lab modules / 86 tools (verified live), adds the policed `:30090` invocation, and updates the L4 delegation row to reflect `requireActChain` + `maxDepth` enforcement
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
