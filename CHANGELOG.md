# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]

### Added

- **v0.5: Observability + Anomaly Detection**
  - OTLP trace export — OpenTelemetry spans for every decision (opt-in via `NULLFIELD_AUDIT_ENDPOINT`)
  - Tool-chain sequence detection — configurable suspicious call patterns per session (8 tests)
  - Claims drift detection — detect scope/group changes mid-session (8 tests)
  - Observability stack (`deploy/operations/`): Grafana dashboard (8 panels), ServiceMonitor, 5 Alertmanager rules
- **SCOPE action** — modify tool call requests and responses in transit. Strip dangerous arguments, inject scoped credentials, redact sensitive patterns in responses. Standalone action with full audit trail of what was modified. 9 unit tests.
- **HOLD action** — park tool calls for human approval. When a HOLD rule matches, the request is held until a human approves or denies via the admin API, or the timeout expires. Includes:
  - `pkg/hold/manager.go` — hold state machine (pending -> approved/denied/timeout)
  - `pkg/hold/admin.go` — REST API: GET /admin/holds, POST approve/deny
  - `pkg/hold/notify.go` — webhook notification on hold creation
  - Hold config in policy YAML: timeout, onTimeout, notify.webhook
  - Error code -32005 (ErrCodeHoldTimeout) for timed-out holds
  - Audit events: hold.created, hold.approved
  - 9 unit tests covering approve, deny, timeout, list, history, double-approve
- **Arbiter model** — `docs/arbiter-model.md` defining the five nullfield actions (ALLOW, DENY, HOLD, SCOPE, BUDGET), decision chain, YAML spec, error codes, and how every roadmap feature maps to an action
- **BUDGET enforcement** — per-identity and per-session call/token budgets. Attach `budget:` to any ALLOW rule to enforce hourly/daily call limits and daily token limits. Automatically detected from policy YAML — no config flag needed. `onExhausted: DENY` rejects with `-32004`.
- **Demos** — `demos/` directory with 3 runnable walkthroughs: basic tool filtering, JWT identity tracking (with generate-test-jwt.sh), and anomaly detection patterns
- **Prometheus metrics** — `/metrics` endpoint on admin port with tool call counters, deny counters, identity failures, circuit trips, and anomaly alerts. Always on, zero config.
- **Velocity detection** — per-identity tool call rate tracking with configurable threshold and alertAction (LOG or DENY). Opt-in via `anomaly.enabled: true` in policy.
- **Observability guide** — `docs/observability.md` covering Prometheus scraping, PromQL queries, audit log filtering, and anomaly detection setup
- **L2: Identity-aware policy** — opt-in identity validation and conditional policy rules:
  - JWT/JWKS verification with multi-provider support (RS256, ES256, key caching)
  - `when:` blocks on rules — match by identity type (human/agent/autonomous), provider, and claims
  - Session binding — detect mid-session identity swaps
  - Token replay detection — reject reused JTI claims
  - All features off by default — existing policies work unchanged
  - `docs/identity-policy.md` — four-level configuration guide
  - 15 unit tests covering rule matching, session binding, and replay detection
  - Example policies: `policy-minimal.yaml` (5 lines) and `policy-identity.yaml` (full L2)
- **Repo restructure** — three clear top-level concerns:
  - `integrations/` — per-target configs (camazotz first, extensible)
  - `meshes/` — service mesh overlays (independent of integrations)
  - `docs/` — architecture, diagrams, guides
- **Camazotz integration** (`integrations/camazotz/`) — 57 tools registered, three-tier policy, 15-point integration test, README with gap analysis
- **Architecture docs** — `docs/architecture.md` (request lifecycle, decision chain, package map, L1-L4 security model)
- **Diagrams** — `docs/diagrams/traffic-flow.md` (all deployment modes) and `docs/diagrams/policy-eval.md` (four-gate chain)
- **Service mesh overlays** — moved to top-level `meshes/` directory:
  - `meshes/istio/` — PeerAuthentication (STRICT mTLS) + AuthorizationPolicy
  - `meshes/linkerd/` — Server + ServerAuthorization + opaque port annotations
  - `meshes/cilium/` — CiliumNetworkPolicy with L7 HTTP rules
- **Mesh integration guide** — `docs/mesh-integration.md` covering four profiles
- **Helm mesh support** — `mesh.provider` value (`none | istio | linkerd | cilium`)
- **Kustomize base** — `deploy/manifests/kustomization.yaml`

## [0.1.0] — 2026-04-17

Initial release. MCP/agentic traffic sidecar proxy with default-deny posture.

### Added

- **MCP JSON-RPC proxy** — intercepts `tools/call`, `tools/list`, `resources/read`, `initialize`, `ping` and all other MCP methods. Non-`tools/call` methods pass through; `tools/call` goes through the full enforcement pipeline.
- **Tool registry** — file-backed allowlist loaded from YAML at startup. Unregistered tool calls are rejected with JSON-RPC error `-32003` before policy evaluation runs.
- **Policy engine** — first-match rule evaluation (ALLOW/DENY) per tool name, per MCP method. Policy loaded from YAML file via `NULLFIELD_POLICY_PATH`. Falls back to deny-all if no policy file is provided.
- **Identity verification** — extracts Bearer token from configurable header. Noop verifier for dev mode (no JWKS URL configured). JWKS validation is wired as an interface but not yet implemented.
- **Circuit breaker** — per-session tool call count and duration limits. Rejects with `-32002` when tripped. Background sweep cleans up expired sessions.
- **Structured audit logging** — every proxied action emits a JSON audit event to stdout via `slog` with event type, MCP method, tool name, identity, arguments, and reason for denials.
- **Admin endpoints** — `/healthz` and `/readyz` on a separate port for liveness and readiness probes.
- **Docker Compose** — local dev environment with nullfield proxy + echo MCP server. Mount policy and tool registry from `examples/`.
- **K8s manifests** — namespace, deployment (sidecar pattern), service, RBAC, and ConfigMaps. Distribution-agnostic — works on K8s, K3s, EKS, GKE, AKS.
- **Helm chart** — sidecar template helper, ConfigMap template, values file.
- **Smoke tests** — 12-point test script covering admin health, MCP passthrough, registry enforcement, policy allow/deny, and non-JSON-RPC passthrough.
- **Echo MCP server** — test fixture that implements `initialize`, `tools/list`, `tools/call`, and `ping` for local and CI testing.
- **Implementation guide** — full cluster adoption guide covering sidecar injection, service rewiring, policy design, verification checklist, operational runbook, and migration checklist.

### Security

- Distroless container image (`gcr.io/distroless/static-debian12:nonroot`)
- Runs as UID 65534 (nonroot), read-only root filesystem, all capabilities dropped
- Default-deny posture — no rules loaded means all `tools/call` requests are rejected
- 1 MiB request body cap to prevent payload abuse

### Verified On

- Docker Compose (macOS, Docker Desktop)
- K3s v1.34.5 (single-node, Ubuntu 24.04)
