# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]

### Added

- **Service mesh integration** — Kustomize overlays for Istio, Linkerd, and Cilium. Each overlay layers mesh-specific annotations and CRDs on top of the base manifests without modifying them.
  - `deploy/overlays/istio/` — PeerAuthentication (STRICT mTLS) + AuthorizationPolicy
  - `deploy/overlays/linkerd/` — Server + ServerAuthorization + opaque port annotations
  - `deploy/overlays/cilium/` — CiliumNetworkPolicy with L7 HTTP rules
- **Mesh integration guide** — `docs/mesh-integration.md` covering four deployment profiles (bare, Istio, Linkerd, Cilium) with traffic flow diagrams, annotations, responsibility matrices, and gotchas.
- **Helm mesh support** — `mesh.provider` value in Helm chart (`none | istio | linkerd | cilium`) with conditional pod annotation template.
- **Kustomize base** — `deploy/manifests/kustomization.yaml` so overlays can reference base manifests.

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
