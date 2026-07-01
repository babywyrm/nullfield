# nullfield Quickstart — From Zero to Production

nullfield is a sidecar proxy that intercepts every MCP tool call and decides — based on configurable policy — whether to allow, deny, hold, scope, or budget-limit it. This guide walks you through every feature in a progressive sequence, from your first sidecar to a production-hardened Kubernetes deployment.

## What you'll build

By the end of this path you will have:

1. A nullfield sidecar filtering MCP traffic via Docker Compose
2. Policy rules exercising all five actions (ALLOW, DENY, HOLD, BUDGET, SCOPE)
3. Identity-aware policy with JWT validation
4. Anomaly detection catching suspicious patterns
5. A controller coordinating multiple sidecars
6. AgenticFlow YAML compiled into runtime policy, registry, credentials, and optional network/mesh controls
7. A Helm-based Kubernetes deployment ready for production

## Prerequisites

- **Docker** and **Docker Compose** (all phases except Phase 5)
- **kubectl** + a Kubernetes cluster (Phase 5 only — minikube/kind/k3s works)
- **curl** and **python3** (for testing)
- Clone the repo: `git clone https://github.com/babywyrm/nullfield && cd nullfield`

---

## Phase 1: Your First Sidecar

**Goal:** Get nullfield running in front of an MCP server and see it enforce policy.

Follow **[Demo 04 — Sidecar with Docker Compose](../demos/04-sidecar-compose/)**.

You'll start an echo server and a nullfield sidecar with `docker compose up`, then send tool calls and observe allow/deny decisions based on a tiered policy.

**What you'll see:**
- Allowed tools forwarded to upstream
- Denied tools rejected with JSON-RPC errors
- Unregistered tools blocked at the registry gate
- Structured audit logs on stdout

---

## Phase 2: Understanding the Five Actions

nullfield's five actions are the fundamental verbs of agentic traffic control. Phase 1 covered ALLOW and DENY. Now explore the remaining three.

### HOLD — Human Approval Gates

Follow **[Demo 06 — Hold Action](../demos/06-hold-action/)** (if available, or test HOLD rules directly using the controller demo below).

HOLD parks a request and waits for a human to approve or deny it (or for a timeout). You'll trigger a held tool call, inspect it via the admin API, approve it, and watch the original request complete.

### BUDGET — Call and Token Limits

Follow **[Demo 07 — Budget Action](../demos/07-budget-action/)** (if available, or test BUDGET rules directly using the controller demo below).

BUDGET enforces call quotas per identity or session. You'll hit the limit, see the rejection, and check budget counters via the admin API.

### SCOPE — Request/Response Modification

Follow **[Demo 08 — Scope Action](../demos/08-scope-action/)** (if available).

SCOPE modifies requests and responses in flight — stripping dangerous arguments, injecting credentials, or redacting sensitive data from responses. You'll configure scope rules and observe the modifications in the audit trail.

---

## Phase 3: Identity and Anomaly Detection

### Identity-Aware Policy

Follow **[Demo 02 — JWT Identity Tracking](../demos/02-jwt-identity-tracking/)**.

Configure nullfield to validate JWTs against a JWKS endpoint and write policy rules that differentiate humans from agents from autonomous callers. You'll generate test tokens, send requests as each identity type, and observe how the same tool gets different decisions based on who's calling.

### Anomaly Detection

Follow **[Demo 03 — Anomaly Detection](../demos/03-anomaly-detection/)**.

Enable session binding, replay detection, and velocity alerts. You'll trigger each anomaly pattern and see how nullfield detects and responds to suspicious traffic.

---

## Phase 4: Controller Mode

**Goal:** Deploy the controller for centralized hold management, shared budgets, and a unified admin API.

Follow **[Demo 09 — Controller Mode](../demos/09-controller-mode/)**.

You'll start a three-container stack (echo server + sidecar + controller), test centralized holds and budgets, and compare the experience to sidecar-only mode.

**Key difference:** In sidecar-only mode, each sidecar tracks its own holds and budgets. With the controller, there's one set of counters for the entire fleet — adding more sidecars doesn't multiply quotas.

---

## Phase 5: AgenticFlow Least-Privilege Paths

**Goal:** Define a known acceptable path for an agent and compile it into enforceable nullfield artifacts.

Start with **[Demo 13 — AgenticFlow Local Compile](../demos/13-agentic-flow-local/)**. It does not require Kubernetes or private services. You'll compile a flow that demonstrates:

- `ALLOW` for a safe tool
- credential-scoped `SCOPE`
- `HOLD` for an operational write
- explicit `DENY`
- default deny

Then run **[Demo 14 — AgenticFlow Kubernetes Reconciliation](../demos/14-agentic-flow-kubernetes/)** on k3s, kind, or minikube. It verifies the full runtime path:

```text
AgenticFlow CRD
  -> controller compile
  -> ConfigMap policy.yaml/tools.yaml
  -> nullfield sidecar mount
  -> real MCP allow/deny calls
```

---

## Phase 6: Kubernetes Deployment

**Goal:** Deploy nullfield on a real cluster with Helm.

Follow **[Demo 05 — Sidecar on Kubernetes](../demos/05-sidecar-kubernetes/)**.

The Helm chart deploys:
- nullfield sidecars injected alongside your MCP server pods
- The controller as a standalone Deployment (opt-in)
- Per-target policy and registry ConfigMaps
- ServiceMonitor, PrometheusRule, and Grafana dashboard

```bash
helm install nullfield deploy/helm/nullfield \
  --namespace nullfield --create-namespace \
  --set controller.enabled=true
```

### K8s sidecar quick demo (camazotz reference)

If you want a fully wired example to point real MCP traffic at, deploy the camazotz reference stack. It exposes two `NodePort` Services over the same `brain-gateway` pod: `:30080` is the bypass (direct to the app, no policy) and `:30090` is the policed path (through the nullfield sidecar listening on `:9090`). The sidecar admin port is exposed at `:31591` for `/healthz`, `/metrics`, and `/admin/holds`. The manifest is [`kube/brain-gateway-policed.yaml`](https://github.com/babywyrm/camazotz/blob/main/kube/brain-gateway-policed.yaml) in the camazotz repo, and the canonical verification target is `make smoke-k8s-policed` (which runs `scripts/smoke_test.py --target k8s --require-policed`). Unauthenticated requests to `:30090` return JSON-RPC error `-32001 identity verification failed`; the same request to `:30080` returns 200 — that asymmetry is the proof the sidecar is in the path. See [Mesh Integration → K8s sidecar mode (camazotz reference)](mesh-integration.md#k8s-sidecar-mode-camazotz-reference) for the traffic-flow diagram and ports table.

---

## Phase 7: Production Hardening

Once you have nullfield deployed, walk through this checklist before going to production.

### Identity verification

- [ ] Configure at least one JWKS provider in `spec.identity.providers`
- [ ] Set `requireIdentity: true` on all sensitive rules
- [ ] Set `allowedAlgorithms` to restrict to RS256/ES256 (no HMAC)
- [ ] Configure `clockSkew` to a tight value (30s)
- [ ] See [Identity Policy Guide](identity-policy.md)

### Integrity checks

- [ ] Enable `integrity.bindToSession: true` — prevents identity swaps mid-session
- [ ] Enable `integrity.detectReplay: true` — prevents token reuse
- [ ] See [Demo 03](../demos/03-anomaly-detection/) for testing

### Anomaly detection

- [ ] Enable `anomaly.velocity` with an appropriate threshold per identity
- [ ] Configure suspicious tool-chain sequences for your workload
- [ ] Set `alertAction: DENY` for high-risk patterns (or `LOG` for observation period)
- [ ] See [Observability Guide](observability.md)

### Budgets and holds

- [ ] Set `budget.perIdentity` and `budget.perSession` limits on LLM-calling tools
- [ ] Use HOLD for any tool that mutates external state (deployments, secrets, billing)
- [ ] Deploy the controller for centralized enforcement across sidecars
- [ ] Configure `NULLFIELD_ALERTING_WEBHOOK` on the controller for hold notifications

### Observability

- [ ] Deploy the ServiceMonitor (`deploy/helm/nullfield/templates/servicemonitor.yaml`)
- [ ] Deploy the PrometheusRule (`deploy/helm/nullfield/templates/prometheusrule.yaml`) — 5 alert rules included
- [ ] Import the Grafana dashboard (`deploy/helm/nullfield/templates/grafana-dashboard-cm.yaml`)
- [ ] Set `NULLFIELD_AUDIT_ENDPOINT` for OTLP trace export if using an OpenTelemetry collector
- [ ] See [Observability Guide](observability.md)

### Service mesh integration

- [ ] Apply the appropriate mesh overlay if running Istio, Linkerd, or Cilium
- [ ] See [Mesh Integration Guide](mesh-integration.md)

---

## Full documentation

| Document | What it covers |
|---|---|
| [Architecture](architecture.md) | Sidecar/controller split, decision pipeline, gRPC protocol |
| [Arbiter Model](arbiter-model.md) | The five actions, composition rules, why "arbiter" not "firewall" |
| [Identity Policy](identity-policy.md) | JWKS providers, when-conditions, claims matching |
| [Implementation Guide](implementation-guide.md) | Cluster adoption, migration, multi-tenant patterns |
| [Observability](observability.md) | Metrics, traces, alert rules, Grafana dashboard |
| [Mesh Integration](mesh-integration.md) | Istio, Linkerd, Cilium overlays and traffic flow |
