# nullfield

MCP and agentic traffic sidecar proxy.

nullfield sits beside any pod that sends or receives MCP JSON-RPC, LLM API calls, or agentic workflow signals. It intercepts, validates, and audits every tool call before it reaches the application — enforcing identity, policy, and scope at the network layer.

Runs anywhere containers run: Kubernetes, K3s, EKS, GKE, AKS, or plain Docker Compose.

> The AI advises. The gates decide. nullfield is the gate.

---

## What It Does

| Capability | Description |
|---|---|
| **MCP JSON-RPC interception** | Parses `tools/call`, `tools/list`, `resources/read` etc. and applies policy before forwarding |
| **Tool registry enforcement** | Only registered, approved tools can execute. Unregistered tool calls are rejected. |
| **Identity verification** | Every request must carry a valid identity token. No anonymous tool execution. |
| **Policy engine** | First-match rule evaluation: ALLOW/DENY per tool, per method, with CEL expressions |
| **Circuit breaker** | Per-session call count and duration limits. Kill runaway agent loops. |
| **Credential injection** | Outbound LLM API calls get credentials injected from Vault/ASM. Apps never see raw keys. |
| **Structured audit** | Every proxied action emits a JSON audit event with trace ID, identity, tool, and arguments |

---

## Architecture

```text
┌─────────────────────────────────────────────────────┐
│  Pod                                                │
│                                                     │
│  ┌──────────────┐        ┌───────────────────────┐  │
│  │              │  :9090 │                       │  │
│  │  Application ├───────►│  nullfield (sidecar)  │  │
│  │  (MCP server │        │                       │  │
│  │   or client) │◄───────┤  ┌─ Identity verify   │  │
│  │              │        │  ├─ Tool registry chk │  │
│  └──────────────┘        │  ├─ Policy evaluate   │  │
│                          │  ├─ Circuit breaker   │  │
│                          │  ├─ Audit emit        │  │
│                          │  └─ Forward / reject  │  │
│                          └───────────┬───────────┘  │
│                                      │ :9091 admin  │
│                                      │ /healthz     │
│                                      │ /readyz      │
└──────────────────────────────────────┘
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

### Next

- [ ] **v0.4** — SCOPE action (request/response modification, credential injection, response redaction)
- [ ] **v0.4** — OTLP trace/span export, tool-chain sequence detection, claims drift detection
- [ ] **v0.5** — Webhook/Slack alerting for denials and anomalies, time-of-day rules
- [ ] **v0.5** — Credential injection from Vault/ASM, outbound LLM API proxying
- [ ] **v0.6** — Mutating admission webhook for automatic sidecar injection
- [ ] **v0.7** — CRD controller (watch NullfieldPolicy + ToolRegistry as native K8s resources)
- [ ] **v0.8** — L3 tool governance: registration workflow, tool lifecycle, rug-pull detection
- [ ] **v0.9** — L4 agentic flow control: identity chaining, delegation depth limits, human-in-the-loop
- [ ] **v0.9** — Response inspection (detect system prompt leakage, PII in tool responses), cost attribution per identity/session
- [ ] **v1.0** — Transparent iptables-based proxy (Istio-style), production hardening, ext_authz gRPC mode

### Future

- [ ] WASM filter compilation for Envoy (in-process, zero-sidecar)
- [ ] OPA/Rego policy engine as alternative to first-match rules
- [ ] Multi-cluster federation (shared policy, distributed audit)

See [CHANGELOG.md](CHANGELOG.md) for detailed release notes.
See [docs/implementation-guide.md](docs/implementation-guide.md) for cluster adoption guide.
See [docs/mesh-integration.md](docs/mesh-integration.md) for service mesh integration.
See [docs/identity-policy.md](docs/identity-policy.md) for identity-aware policy configuration.
See [docs/observability.md](docs/observability.md) for metrics and monitoring.
See [demos/](demos/) for runnable walkthroughs.
