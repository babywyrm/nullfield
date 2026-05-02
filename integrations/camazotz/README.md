# Camazotz Integration

Test nullfield against [camazotz](https://github.com/babywyrm/camazotz), a vulnerable-by-design MCP security training platform with **35 lab modules and 86 tools** (verified live against the reference K3s deployment) mapped to OWASP MCP Top 10 and the MCP Red Team Playbook.

The bundled `policy.yaml` and `tools.yaml` ship a 57-tool starter allowlist (25 read-only + 25 write-action + 7 high-risk denied); the remaining tools fall under registry default-deny and need explicit registration before they pass the gate.

## Prerequisites

- camazotz running locally (`make up` from the camazotz repo, or `uv run uvicorn brain_gateway.app.main:app --port 8080`)
- nullfield binary built (`make build` from the nullfield repo)

## Start

```bash
# From the nullfield repo root:
NULLFIELD_UPSTREAM_ADDR=localhost:8080 \
NULLFIELD_POLICY_PATH=integrations/camazotz/policy.yaml \
NULLFIELD_REGISTRY_PATH=integrations/camazotz/tools.yaml \
./bin/nullfield
```

nullfield proxies on `:9090`, camazotz is on `:8080`. Point your MCP client at `http://localhost:9090/mcp`.

## Policy Tiers

The policy uses three tiers:

| Tier | Action | Tools | Rate limit | Rationale |
|------|--------|-------|------------|-----------|
| 1 | ALLOW | 25 read-only tools (list, check, read, recall) | 60/min | Safe operations — no state mutation |
| 2 | ALLOW | 25 write/action tools (send, issue, invoke, store) | 20/min | State-changing but not inherently dangerous |
| 3 | DENY | 7 high-risk tools | blocked | SSRF, exfiltration, supply chain, rug pull, prompt injection, shadow webhook, unvalidated plan execution |

### Tier 3 (blocked) tools

| Tool | Vulnerability | OWASP / Playbook |
|------|--------------|------------------|
| `egress.fetch_url` | SSRF via AI proxy | — |
| `indirect.fetch_and_summarize` | Indirect prompt injection | MCP-T02 |
| `secrets.leak_config` | Credential exfiltration | MCP01 |
| `shadow.register_webhook` | Unvalidated persistent callback | MCP09 |
| `supply.install_package` | Malicious supply chain install | MCP04 |
| `tool.mutate_behavior` | Rug pull / tool drift | MCP03 |
| `hallucination.execute_plan` | Destructive LLM-generated plan | MCP-T10 |

## Test

```bash
bash integrations/camazotz/test.sh
```

Expected: tier 1+2 tools forwarded to camazotz, tier 3 tools blocked, unregistered tools rejected, full audit trail.

## Canonical K8s integration: `:30090` policed Service

For Kubernetes (the target most of the camazotz / nullfield co-development happens against), the canonical integration point is the [`brain-gateway-policed`](https://github.com/babywyrm/camazotz/blob/main/kube/brain-gateway-policed.yaml) `Service` shipped in the camazotz repo. It exposes both paths over the same pod for direct A/B comparison:

| Endpoint | NodePort | Pod port | Path | Policy |
|----------|----------|----------|------|--------|
| `brain-gateway` (default) | `:30080` | `8080` | client → `brain-gateway` | **bypass** (no nullfield) |
| `brain-gateway-policed` (mcp) | `:30090` | `9090` | client → nullfield → `brain-gateway` `:8080` | **enforced** |
| `brain-gateway-policed` (admin) | `:31591` | `9091` | client → nullfield admin | n/a (status / holds / metrics) |

Verification target (run from the camazotz repo):

```bash
make smoke-k8s-policed
# wraps: uv run python scripts/smoke_test.py --target k8s --require-policed
```

Live behavior on the reference NUC: an unauthenticated MCP request to `:30090` returns JSON-RPC error `-32001 identity verification failed`; the same request to `:30080` returns 200. That asymmetry is the integration test.

Use `:30090` whenever you want to exercise nullfield in front of the full 35 / 86 attack surface; keep `:30080` around for "is the upstream still healthy?" debugging and for demos that contrast the two paths.

### Lane templates

For lane-aware policy on top of camazotz, drop the relevant template from [`policies/by-lane/`](../../policies/by-lane/) onto the workload — the five files (`lane-1-human.yaml`, `lane-2-delegated.yaml`, `lane-3-machine.yaml`, `lane-4-chain.yaml`, `lane-5-anonymous.yaml`) match the canonical agentic-identity lane vocabulary and pre-wire the per-rule guards (`requireActChain`, `audienceMustNarrow`, `maxDepth`) where they apply. See [`policies/by-lane/README.md`](../../policies/by-lane/README.md) for the transport-code mapping (A–E per [camazotz ADR 0001](https://github.com/babywyrm/camazotz/blob/main/docs/adr/0001-five-transport-taxonomy.md)).

## What nullfield catches vs. what it doesn't (yet)

| Attack | nullfield today | Future layer needed |
|--------|----------------|---------------------|
| Calling a blocked tool (SSRF, exfil) | Blocked at policy | L1 (works now) |
| Calling an unknown tool | Blocked at registry | L1 (works now) |
| Agent loop exhaustion | Circuit breaker trips | L1 (works now) |
| Agent impersonating a human | Not detected | L2 (identity-aware policy) |
| Tool appearing after init (rug pull) | Not detected post-startup | L3 (tool governance) |
| Unbounded delegation chains | L4 — enforced via `identity.requireActChain` and `delegation.maxDepth` (`pkg/policy/rules.go`); see `policies/by-lane/lane-4-chain.yaml` | further HITL prompting still future |
| Cross-tenant memory access | Forwarded (allowed tool) | L2 (identity + tenant scoping) |
