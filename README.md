# nullfield

Lightweight arbiter for MCP and agentic traffic.

nullfield is a sidecar proxy that intercepts every MCP tool call and decides — based on configurable policy — whether to **allow**, **deny**, **hold for human approval**, **modify**, or **budget-limit** it. It enforces identity, scope, and cost controls at the network layer so the AI never has the final say.

Runs anywhere containers run. One binary, one YAML policy, zero dependencies on any cloud provider or orchestrator.

> The AI advises. The gates decide. nullfield is the gate.

---

## The Five Actions

Every tool call that reaches nullfield results in one of five actions — the fundamental verbs of agentic traffic control:

```text
ALLOW    Forward the request immediately.
DENY     Reject the request immediately.
HOLD     Park the request. Notify a human. Wait for approval or timeout.
SCOPE    Allow but modify — strip parameters, inject credentials, redact response. (planned)
BUDGET   Allow but track — enforce call quotas, token limits, cost caps.
```

These compose. A single request may pass through multiple actions:

```text
BUDGET check (within quota?) → HOLD (wait for approval) → ALLOW (forward to upstream)
```

### In YAML

```yaml
rules:
  # Humans can use read tools freely
  - action: ALLOW
    toolNames: [cost.check_usage, audit.list_actions]
    when: { identity: human }

  # LLM-backed tools are budget-limited
  - action: ALLOW
    toolNames: [config.ask_agent]
    budget:
      perIdentity: { maxCallsPerHour: 20 }
      perSession: { maxCallsPerHour: 10 }

  # Agent delegation requires human approval
  - action: HOLD
    toolNames: [delegation.invoke_agent]
    when: { identity: agent }
    hold: { timeout: "5m", onTimeout: DENY }

  # Dangerous tools are blocked
  - action: DENY
    toolNames: [secrets.leak_config, egress.fetch_url]

  # Default deny
  - action: DENY
    toolNames: ["*"]
    reason: "no matching rule"
```

### When to use each action

| Scenario | Action | Why |
|---|---|---|
| Agent reads a status check | ALLOW | Safe, no side effects |
| Agent tries to exfiltrate secrets | DENY | Blocked unconditionally |
| Agent wants to deploy to production | HOLD | Human must approve before it proceeds |
| Agent reads credentials from vault | SCOPE (planned) | Allow but redact the secret value in the response |
| Agent calls an LLM 100 times/hour | BUDGET | Allow but enforce a quota to prevent cost runaway |
| Unknown tool name appears | DENY (registry) | Not in the approved list — rejected before policy even runs |
| Same JWT used twice | DENY (integrity) | Replay detection catches reused tokens |
| Identity changes mid-session | DENY (integrity) | Session binding catches context swaps |

See [docs/arbiter-model.md](docs/arbiter-model.md) for the full specification.

---

## Deployment Model

nullfield is lightweight by design. Two deployment patterns:

**Sidecar** — one nullfield container per pod, next to your MCP server. Traffic enters through nullfield before reaching the app. This is the default.

**Gateway** (planned) — one nullfield instance proxying multiple MCP servers. For teams that want centralized enforcement.

### What lives in the sidecar (per-pod)

- nullfield proxy (:9090) — intercepts MCP traffic
- Admin API (:9091) — /healthz, /readyz, /metrics, /admin/holds
- Policy + registry — mounted from ConfigMap

### What lives outside the sidecar (cluster-level, deploy once)

- ServiceMonitor — tells Prometheus to scrape nullfield sidecars
- Grafana dashboard — pre-built visibility into tool calls, denials, budgets
- Alertmanager rules — fire on anomalies, budget exhaustion, identity failures
- CRD definitions — when using native K8s policy resources (planned)

Every layer is opt-in. The minimum deployment is the sidecar + a policy YAML. Everything else bolts on.

---

## Architecture

```text
  MCP Client
      │
      │  POST /mcp (JSON-RPC)
      ▼
┌──────────────────────────────────────────────────────────────┐
│  Pod                                                         │
│                                                              │
│  ┌──────────────────────────────────────────────────────┐    │
│  │  nullfield (:9090)                                   │    │
│  │                                                      │    │
│  │  1. Identity ── verify JWT, extract type/claims      │    │
│  │  2. Registry ── is this tool registered?             │    │
│  │  3. Integrity ── session binding, replay detection   │    │
│  │  4. Circuit breaker ── session within limits?        │    │
│  │  5. Policy ── first-match rule → action:             │    │
│  │     ├─ DENY ──── reject immediately                  │    │
│  │     ├─ HOLD ──── park, notify human, wait            │    │
│  │     ├─ BUDGET ── check quota, reject if exhausted    │    │
│  │     ├─ SCOPE ─── modify request (planned)            │    │
│  │     └─ ALLOW ─── forward to upstream                 │    │
│  │  6. Audit ── structured JSON event for every action  │    │
│  └──────────────────────┬───────────────────────────────┘    │
│                         │                                    │
│                         ▼                                    │
│  ┌──────────────────────────────┐   :9091 admin              │
│  │  Your MCP Server (:8080)    │   /healthz /readyz          │
│  │  (camazotz, your app, etc.) │   /metrics /admin/holds     │
│  └──────────────────────────────┘                            │
└──────────────────────────────────────────────────────────────┘
```

---

## Quickstart

### Build

```bash
make build
```

### Run locally (dev mode)

```bash
# Start your MCP server on :8080, then:
export NULLFIELD_UPSTREAM_ADDR=localhost:8080
export NULLFIELD_REGISTRY_PATH=examples/tools.yaml
./bin/nullfield
```

nullfield listens on `:9090` (proxy) and `:9091` (admin). Point your MCP client at `localhost:9090` instead of `localhost:8080`.

### Docker Compose (recommended for local dev)

```bash
docker compose up -d
bash tests/smoke.sh       # 12 tests: admin, passthrough, registry, policy
docker compose logs -f nullfield   # watch the audit trail
```

This starts nullfield + an echo MCP server with a demo policy and tool registry from `examples/`.

### Docker (standalone)

```bash
make docker
docker run -p 9090:9090 -p 9091:9091 \
  -e NULLFIELD_UPSTREAM_ADDR=host.docker.internal:8080 \
  ghcr.io/babywyrm/nullfield:latest
```

### Kubernetes / K3s / EKS sidecar

Apply the raw manifests to any cluster:

```bash
kubectl apply -f deploy/manifests/namespace.yaml
kubectl apply -f deploy/manifests/
```

Or use the Helm chart with the sidecar template helper:

```yaml
containers:
  - name: my-mcp-server
    image: my-app:latest
    ports:
      - containerPort: 8080
  {{- include "nullfield.sidecar" . | nindent 2 }}
```

Or manually add the container (see `deploy/helm/nullfield/templates/sidecar-snippet.yaml`).

The manifests and Helm chart are distribution-agnostic — no assumptions about CNI, ingress controller, or cloud provider.

### With a service mesh (Istio, Linkerd, Cilium)

Kustomize overlays add mesh-specific annotations and CRDs on top of the base manifests:

```bash
kubectl apply -k meshes/istio/    # Istio: PeerAuthentication + AuthorizationPolicy
kubectl apply -k meshes/linkerd/  # Linkerd: Server + ServerAuthorization
kubectl apply -k meshes/cilium/   # Cilium: CiliumNetworkPolicy
```

See [docs/mesh-integration.md](docs/mesh-integration.md) for traffic flow diagrams, annotations, and gotchas per mesh.

---

## Configuration

All configuration via environment variables:

| Variable | Default | Description |
|---|---|---|
| `NULLFIELD_LISTEN_ADDR` | `:9090` | Proxy listen address |
| `NULLFIELD_UPSTREAM_ADDR` | `localhost:8080` | Application upstream address |
| `NULLFIELD_ADMIN_ADDR` | `:9091` | Admin/health endpoint address |
| `NULLFIELD_POLICY_PATH` | `/etc/nullfield/policy.yaml` | Path to NullfieldPolicy YAML |
| `NULLFIELD_REGISTRY_PATH` | `/etc/nullfield/tools.yaml` | Path to ToolRegistry YAML |
| `NULLFIELD_IDENTITY_HEADER` | `Authorization` | Header to extract Bearer token from |
| `NULLFIELD_JWKS_URL` | _(empty)_ | JWKS endpoint for token validation. Empty = noop verifier (dev mode) |
| `NULLFIELD_CIRCUIT_MAX_CALLS` | `100` | Max tool calls per session before circuit opens |
| `NULLFIELD_CIRCUIT_MAX_DURATION` | `5m` | Max session duration before circuit opens |
| `NULLFIELD_AUDIT_LOG_LEVEL` | `FULL` | Audit verbosity: `FULL`, `SUMMARY`, `NONE` |
| `NULLFIELD_AUDIT_ENDPOINT` | _(empty)_ | OTLP gRPC endpoint for audit events |

---

## Policy (NullfieldPolicy)

Rules are evaluated in order — first match wins. Default is deny if no rule matches.

```yaml
apiVersion: nullfield.io/v1alpha1
kind: NullfieldPolicy
metadata:
  name: kosmos-agents
  namespace: kosmos
spec:
  selector:
    matchLabels:
      app: kosmos-agent
  rules:
    - action: ALLOW
      mcpMethod: tools/call
      toolNames: ["github_create_pr", "pagerduty_resolve"]
      requireIdentity: true
      maxCallsPerMinute: 30

    - action: DENY
      mcpMethod: tools/call
      toolNames: ["*"]

  circuitBreaker:
    maxToolCallsPerSession: 100
    maxSessionDuration: 300s
    onTrip: KILL_POD

  audit:
    emitTo: otel-collector.observability:4317
    logLevel: FULL
```

See `examples/policy.yaml` for a full example.

---

## Tool Registry (ToolRegistry)

Every tool that nullfield allows must be registered:

```yaml
apiVersion: nullfield.io/v1alpha1
kind: ToolRegistry
metadata:
  name: kosmos-tools
tools:
  - name: github_create_pr
    description: Create a pull request
    allowedScopes: ["repo:write"]
    maxCallsPerMinute: 10
```

See `examples/tools.yaml` for the full registry.

---

## Error Responses

nullfield returns standard JSON-RPC 2.0 errors with application-defined codes:

| Code | Meaning |
|---|---|
| `-32000` | Policy denied the tool call |
| `-32001` | Identity verification failed |
| `-32002` | Circuit breaker open |
| `-32003` | Tool not in registry |
| `-32004` | Rate limit exceeded |

---

## Project Structure

```
nullfield/
├── cmd/nullfield/        # Entrypoint
├── pkg/
│   ├── proxy/            # MCP JSON-RPC reverse proxy + handler
│   ├── policy/           # Rule engine (first-match ALLOW/DENY)
│   ├── identity/         # Token extraction + verification
│   ├── audit/            # Structured audit event emitter
│   ├── registry/         # Tool registry (file-backed, hot-reloadable)
│   ├── circuit/          # Per-session circuit breaker
│   └── credentials/      # Secret provider interface (Vault/ASM/env)
├── api/v1alpha1/         # CRD type definitions
├── internal/config/      # Environment-based configuration
├── integrations/
│   └── camazotz/         # Camazotz vulnerable MCP server (57 tools, tiered policy)
├── meshes/               # Service mesh overlays (Istio, Linkerd, Cilium)
├── deploy/
│   ├── helm/nullfield/   # Helm chart with sidecar template
│   └── manifests/        # Raw K8s manifests (works on any distro)
├── examples/             # Example policy + tool registry
├── demos/                # Runnable walkthroughs (basic, JWT, anomaly)
├── tests/
│   ├── echo-server/      # Echo MCP server for testing
│   └── smoke.sh          # 12-point smoke test
├── docs/
│   ├── architecture.md
│   ├── identity-policy.md
│   ├── implementation-guide.md
│   ├── mesh-integration.md
│   ├── observability.md
│   └── diagrams/
├── Dockerfile
├── Makefile
├── docker-compose.yaml
├── CHANGELOG.md
├── LICENSE
└── README.md
```

---

## Roadmap

### Implemented

- [x] **v0.1** — MCP `tools/call` interception, rule engine, policy-from-file, audit logging, circuit breaker, K8s manifests, Docker Compose, smoke tests
- [x] **v0.2** — L2 identity-aware policy: JWKS validation, multi-provider support, `when:` conditions (identity type, provider, claims), session binding, replay detection
- [x] **v0.2** — Prometheus `/metrics` endpoint, velocity anomaly detection, 3 runnable demo walkthroughs
- [x] **v0.3** — Arbiter model: BUDGET (per-identity/session call + token limits), HOLD (human approval gates with admin API, webhook notify, timeout)
- [x] **v0.4** — SCOPE action: request argument stripping/injection, response pattern redaction, full audit trail of modifications

- [x] **v0.5** — OTLP trace export, tool-chain sequence detection (8 tests), claims drift detection (8 tests), observability stack (Grafana dashboard, ServiceMonitor, 5 alert rules)

### Next

- [ ] **v0.6** — Webhook/Slack alerting for denials and anomalies, time-of-day rules
- [ ] **v0.6** — Credential injection from Vault/ASM, outbound LLM API proxying
- [ ] **v0.6** — Gateway mode: single nullfield instance proxying multiple MCP servers with per-upstream policy routing
- [ ] **v0.7** — Mutating admission webhook for automatic sidecar injection
- [ ] **v0.8** — CRD controller (watch NullfieldPolicy + ToolRegistry as native K8s resources)
- [ ] **v0.9** — L3 tool governance: registration workflow, tool lifecycle, rug-pull detection
- [ ] **v0.9** — L4 agentic flow control: identity chaining, delegation depth limits, human-in-the-loop
- [ ] **v0.9** — Response inspection (detect system prompt leakage, PII in tool responses), cost attribution per identity/session
- [ ] **v1.0** — Transparent iptables-based proxy (Istio-style), production hardening, ext_authz gRPC mode

### Future

- [ ] WASM filter compilation for Envoy (in-process, zero-sidecar)
- [ ] OPA/Rego policy engine as alternative to first-match rules
- [ ] Multi-cluster federation (shared policy, distributed audit)
- [ ] Terraform/Pulumi modules for cloud deployment (ECS, Lambda, Cloud Run)
- [ ] SDK/middleware for in-process agent frameworks (LangChain, CrewAI, AutoGen)

See [CHANGELOG.md](CHANGELOG.md) for detailed release notes.
See [docs/implementation-guide.md](docs/implementation-guide.md) for cluster adoption guide.
See [docs/mesh-integration.md](docs/mesh-integration.md) for service mesh integration.
See [docs/identity-policy.md](docs/identity-policy.md) for identity-aware policy configuration.
See [docs/observability.md](docs/observability.md) for metrics and monitoring.
See [demos/](demos/) for runnable walkthroughs.
