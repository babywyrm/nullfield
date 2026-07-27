# Roadmap

Release notes with detail live in [CHANGELOG.md](CHANGELOG.md). This file is the
shape of the work: what exists, what is next, and what is deliberately not
planned.

---

## Implemented

- **v0.1** — MCP `tools/call` interception, rule engine, policy-from-file, audit logging, circuit breaker, K8s manifests, Docker Compose, smoke tests
- **v0.2** — L2 identity-aware policy: JWKS validation, multi-provider support, `when:` conditions (identity type, provider, claims), session binding, replay detection
- **v0.2** — Prometheus `/metrics` endpoint, velocity anomaly detection, runnable demo walkthroughs
- **v0.3** — Arbiter model: BUDGET (per-identity/session call + token limits), HOLD (human approval gates with admin API, webhook notify, timeout)
- **v0.4** — SCOPE action: request argument stripping/injection, response pattern redaction, full audit trail of modifications
- **v0.5** — OTLP trace export, tool-chain sequence detection, claims drift detection, observability stack (Grafana dashboard, ServiceMonitor, alert rules)
- **v0.6** — Controller pod (centralized holds, shared budgets, webhook alerting, admin dashboard), universal Helm chart with per-target config
- **v0.7** — Credential injection from Vault/K8s Secrets with TTL cache, wired into SCOPE rules
- **v0.7** — Gateway mode: one instance proxying multiple MCP servers with per-upstream policy routing and per-route registry
- **v0.7** — Mutating admission webhook for automatic sidecar injection via `nullfield.io/inject`
- **v0.8** — CRD controller: `NullfieldPolicy` + `ToolRegistry` as native Custom Resources, synced to ConfigMaps by `pkg/crdwatcher`
- **v0.8** — Per-rule guard primitives: `identity.requireActChain` (RFC 8693), `identity.audienceMustNarrow` (RFC 8707), `delegation.maxDepth`
- **v0.8** — Five lane policy templates in `policies/by-lane/`
- **v0.9** — L3 tool governance: lifecycle tracking and rug-pull detection
- **v0.9** — Response inspection: findings in upstream responses, per-rule `onFinding: DENY/REDACT/AUDIT`
- **v0.9** — Cost attribution: usage reports per identity and session
- **v0.10** — AgenticFlow authoring layer compiled to policy, registry, credential-scoped SCOPE rules, and optional network artifacts
- **v0.10** — AgenticFlow CRD reconciliation, decision context in audit/OTLP/metrics, status conditions, portable demos
- **v0.11** — Proxy mode re-verified against a live k3s cluster as a regression baseline before a second front door was added — [demo 15](demos/15-proxy-baseline/)
- **v0.12** — `ext_authz` decision service behind an Istio waypoint: workload identity attested from the mesh rather than a self-asserted claim, provenance on every decision, observe-only — [demo 16](demos/16-mesh-arbiter/)

  Verified on k3s with Istio 1.30 ambient, with one correction to the plan worth
  recording. Identity does **not** arrive as `source.principal`. A waypoint
  terminates HBONE upstream of the listener running `ext_authz`, so no peer
  certificate is readable there and the check arrives anonymous. Istio publishes
  the identity into Envoy filter state, and an EnvoyFilter copies it into a
  header the check does receive — reported as the `mesh-header` attester, since
  the binding depends on that filter rather than on TLS.

---

## Next

The through-line: nullfield becomes a policy *decision* point reached through
the service mesh, rather than a proxy agents must be configured to use. The mesh
intercepts; nullfield decides. That extends coverage from MCP JSON-RPC to any
HTTP-borne agentic traffic — Kubernetes API, GitHub, Slack, Atlassian, Grafana,
PagerDuty — because a CLI calling an API is just HTTP the mesh already sees.
Proxy and gateway modes remain the non-mesh path.

Design: [`docs/specs/2026-07-26-mesh-native-arbiter.md`](docs/specs/2026-07-26-mesh-native-arbiter.md).

- **v0.13** — Authority grants: initiating principal and `act` chain bound to workload identity, session, and contract version; contract binding required; assurance levels; shadow counterfactuals answering "what would enforcement break"
- **v0.13** — Apply generated network/mesh artifacts from AgenticFlow through an explicit, previewable reconciler mode
- **v0.13** — Full credential runtime demos: Vault, K8s Secret, and OAuth-style paths, with proof that credentials attach only to declared tool actions
- **v0.14** — External egress: `ServiceEntry` plus egress waypoint, one integration at operation-level parsing
- **v0.15** — AI Gateway interception of model-proposed tool calls, before an agent framework dispatches them; consumes stoneburner `atomics toolcall` divergence data as a policy input
- **v1.0** — Selective enforcement per binding, connection-upgrade capability class, production hardening

---

## Later

- `ext_proc` mode for SCOPE and response inspection over the mesh, which `ext_authz` cannot do because it sees requests only and cannot mutate bodies
- Resource-level contract scoping (repository, channel, project, namespace), required to fully close the confused-deputy case
- Forbidden-combination contracts: catching exfiltration composed from individually-authorized calls
- Credential brokering, so agents hold no credentials at all
- Transparent iptables-based proxy for non-mesh clusters
- WASM filter compilation for Envoy (in-process, zero-sidecar)
- OPA/Rego as an alternative to first-match rules
- Multi-cluster federation (shared policy, distributed audit)
- Terraform/Pulumi modules for ECS, Lambda, and Cloud Run
- SDK/middleware for in-process agent frameworks

---

## Known limits

Stated because they are properties of the approach, not backlog items. A
network-level arbiter cannot fix any of them by trying harder. Detail in the
[design spec](docs/specs/2026-07-26-mesh-native-arbiter.md).

- **Authorizing a connection is not authorizing its contents.** `kubectl exec`,
  `port-forward`, streaming MCP over SSE, and WebSockets are authorized once at
  upgrade; traffic inside them is invisible to per-request mediation.
- **Shared workers cap attribution.** One process serving several principals
  must propagate a per-request grant, and a compromised agent can substitute
  one. Recorded as an assurance level rather than claimed as strong attribution.
- **Attribution stops at the mesh boundary.** Until credentials are brokered per
  principal, the downstream system's own audit log still shows the shared
  identity.
- **Non-network work is out of reach.** Subprocess activity that never touches
  the network is not mediated by any network-level arbiter.
- **`ext_authz` mode runs one gate.** The decision service evaluates policy
  only — no registry, integrity, circuit breaker, budget, or velocity. See
  [policy-eval.md](docs/diagrams/policy-eval.md#two-entries-different-chains).
