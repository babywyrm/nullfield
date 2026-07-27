# nullfield

Lightweight arbiter for MCP and agentic traffic.

nullfield decides whether an agent's action is allowed to happen — **allow**,
**deny**, **hold for human approval**, **modify**, or **budget-limit** it — and
records who asked, for what, and what was decided. It runs as a proxy in front
of an MCP server, or as a decision service the service mesh consults for any
HTTP-borne agentic traffic.

One binary, one YAML policy, no dependency on a cloud provider or orchestrator.

> The AI advises. The gates decide. nullfield is the gate.

---

## The five actions

Every mediated call ends in one of five outcomes:

```text
ALLOW    Forward the request immediately.
DENY     Reject the request immediately.
HOLD     Park the request. Notify a human. Wait for approval or timeout.
SCOPE    Allow but modify — strip parameters, inject credentials, redact response.
BUDGET   Allow but track — enforce call quotas, token limits, cost caps.
```

They compose: a request can pass a BUDGET check, wait on a HOLD, then be
ALLOWed. Full specification, YAML, and error codes in
[arbiter-model.md](docs/arbiter-model.md).

---

## Try it in sixty seconds

```bash
docker compose up -d
bash tests/smoke.sh
```

That runs nullfield in front of an echo MCP server with the demo policy in
`examples/`. The smoke test exercises admin, passthrough, registry, and policy.
To watch it decide in real time:

```bash
docker compose logs -f nullfield
```

Then walk through scenarios in the **[Quickstart](docs/quickstart.md)** —
blocking a dangerous call, watching before enforcing, and identifying the
caller.

<details>
<summary>Building from source, or running the container directly</summary>

```bash
make build          # -> bin/nullfield
make build-all      # also the controller, injector, and ext_authz binaries
make test           # unit tests
make docker         # build the sidecar image locally
```

Run the binary against an MCP server already listening on `:8080`:

```bash
NULLFIELD_UPSTREAM_ADDR=localhost:8080 \
NULLFIELD_REGISTRY_PATH=examples/tools.yaml \
  ./bin/nullfield
```

It listens on `:9090` for proxied traffic and `:9091` for admin — point your MCP
client at `9090` instead of `8080`. Same thing as a container:

```bash
docker run -p 9090:9090 -p 9091:9091 \
  -e NULLFIELD_UPSTREAM_ADDR=host.docker.internal:8080 \
  ghcr.io/babywyrm/nullfield:latest
```

Every setting is in [configuration.md](docs/configuration.md); cluster install
is in the [implementation guide](docs/implementation-guide.md).

</details>

---

## Deployment shapes

| Shape | What it is | Use when |
|---|---|---|
| **Sidecar** | One container per pod, in front of your MCP server | The default. Stateless enforcement per workload |
| **Gateway** | One instance proxying several MCP servers, routed per upstream | You want central enforcement without N sidecars |
| **Controller** | One per cluster, alongside sidecars | You need shared state: central holds, shared budgets, alerting |
| **Decision service** | One per namespace, called by an Istio waypoint over `ext_authz` | You cannot modify pods, or you want to identify callers from the mesh |

The minimum deployment is a sidecar and a policy file. Everything else is
opt-in.

The decision service is the newest and differs most: nothing flows through it,
no pod is modified, and the caller is identified from the mesh rather than from
a token it presents — so a workload cannot claim to be something else. It also
runs genuinely read-only, recording what enforcement *would* have done against
production traffic. The cost is that `ext_authz` sees requests only, so it
cannot inspect responses or modify requests. See
[mesh-integration.md](docs/mesh-integration.md#istio-ambient--nullfield-as-an-ext_authz-decision-service).

---

## Documentation

**Start here**

- [Quickstart](docs/quickstart.md) — scenario-driven walkthrough, local first
- [Arbiter model](docs/arbiter-model.md) — the five actions, the decision chain, YAML, error codes
- [Architecture](docs/architecture.md) — how the pieces fit, and the two front doors

**Deploying**

- [Implementation guide](docs/implementation-guide.md) — adding nullfield to an existing cluster
- [Configuration](docs/configuration.md) — every environment variable and port
- [Mesh integration](docs/mesh-integration.md) — Istio, Linkerd, Cilium, and the `ext_authz` decision service

**Operating**

- [Observability](docs/observability.md) — audit events, metrics, provenance, and `scripts/observe-mesh.sh`
- [Identity and policy](docs/identity-policy.md) — identity types, attestation, assurance
- [Agentic flows](docs/agentic-flows.md) — compiling a least-privilege flow into policy and registry

**Diagrams** — [traffic flow](docs/diagrams/traffic-flow.md) ·
[policy evaluation](docs/diagrams/policy-eval.md) ·
[mesh arbiter](docs/diagrams/mesh-arbiter.md)

**Runnable** — [demos/](demos/) has sixteen walkthroughs, each with a README.

---

## Status

Current release **v0.12.0**, working through the [roadmap](ROADMAP.md) toward
v1.0. The proxy is the mature path; the mesh decision service is newer and
currently observe-first. Release notes are in [CHANGELOG.md](CHANGELOG.md).

Four limits are worth knowing before you adopt it, because they are properties
of network-level mediation rather than gaps to be closed: authorizing a
connection is not authorizing its contents (`kubectl exec`, SSE, WebSockets);
shared workers cap attribution; attribution stops at the mesh boundary until
credentials are brokered per principal; and work that never touches the network
is out of reach entirely. Detail in [ROADMAP.md](ROADMAP.md#known-limits).

---

## Ecosystem

Part of **[agentic-sec](https://github.com/babywyrm/agentic-sec)** — shared
architecture and cross-project guides for camazotz, nullfield, and mcpnuke.

[LICENSE](LICENSE)
