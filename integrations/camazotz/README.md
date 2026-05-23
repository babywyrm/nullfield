# Camazotz Integration

Test nullfield against [camazotz](https://github.com/babywyrm/camazotz), a vulnerable-by-design MCP security training platform with **52 lab modules** mapped to OWASP MCP Top 10 and the MCP Red Team Playbook.

The bundled `policy.yaml` and `tools.yaml` cover all **138 tools** exposed by camazotz's `tools/list` (verified 2026-05-23 against the local Docker Compose deployment with [`sync-tools.sh`](sync-tools.sh)). 57 read-only tools land in tier 1 (ALLOW, 60 calls/min), 55 write/action tools in tier 2 (ALLOW, 20 calls/min), and 26 high-risk tools in tier 3 (DENY). Anything not on this list falls under the trailing `*` default-deny rule.

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

The policy uses three tiers, covering all 138 live tools (verified
in-sync 2026-05-23):

| Tier | Action | Tools | Rate limit | Rationale |
|------|--------|-------|------------|-----------|
| 1 | ALLOW | 57 read-only tools (list, check, read, recall, inspect, get, show, simulate) | 60/min | Safe operations — no state mutation, no credential exposure |
| 2 | ALLOW | 55 write/action tools (send, issue, invoke, store, submit, delegate, access) | 20/min | State-changing but not inherently dangerous |
| 3 | DENY | 26 high-risk tools | blocked | SSRF, exfiltration, supply chain, rug pull, prompt injection, shadow webhook, unvalidated plan execution, identity replay, role escalation, subprocess execution, policy mutation, DoS, KB poisoning, shell exec |

### Tier 3 (blocked) tools

| Tool | Vulnerability | OWASP / Playbook |
|------|--------------|------------------|
| `agent_http_bypass.call_direct` | Bypass MCP gateway via direct HTTP | MCP-T45 |
| `bot_identity_theft.read_tbot_secret` | tbot credential exfiltration | MCP-T18 |
| `bot_identity_theft.replay_identity` | Bot identity replay across services | MCP-T18 |
| `cert_replay.replay_cert` | Expired-certificate replay | MCP-T19 |
| `egress.fetch_url` | SSRF via AI proxy | — |
| `gateway.register_asset` | Register arbitrary URL with CDN proxy | — |
| `hallucination.execute_plan` | Destructive LLM-generated plan | MCP-T10 |
| `indirect.fetch_and_summarize` | Indirect prompt injection | MCP-T02 |
| `platform.execute_privileged_op` | Privileged platform operation | MCP-T05 |
| `platform.mint_token` | JWT minting via client credentials | MCP01 |
| `policy_authoring.submit_policy` | Policy mutation (LLM rewriting its own gate) | MCP-T03 |
| `rag.add_document` | Knowledge base poisoning | MCP-T02 |
| `ratelimit.flood_calls` | Anonymous rate-limit exhaustion (DoS) | MCP-T51 |
| `schema.extract_credentials` | Credential pattern extraction from tool schemas | MCP01 |
| `schema.probe_error` | Error probing for info leak | — |
| `secrets.leak_config` | Credential exfiltration | MCP01 |
| `shadow.register_webhook` | Unvalidated persistent callback | MCP09 |
| `shellwrap.exec` | Shell command execution wrapper | MCP-T53 |
| `subchain.spawn_agent` | Subprocess agent spawning with caller credentials | MCP-T10 |
| `subprocess.invoke_worker` | Subprocess execution (Transport D) | MCP-T10 |
| `supply.install_package` | Malicious supply chain install | MCP04 |
| `sdk.get_cached_token` | SDK token-cache exposure (Transport C) | MCP01 |
| `sdk.invoke_as_cached` | SDK token replay (Transport C) | MCP-T04 |
| `teleport_role_escalation.privileged_operation` | Action requiring escalated role | MCP-T28 |
| `teleport_role_escalation.request_role` | Self-escalation to higher-privilege Teleport role | MCP-T28 |
| `tool.mutate_behavior` | Rug pull / tool drift | MCP-T03 |

### Re-syncing against your deployment

If you fork camazotz, add new lab modules, or run a downstream version,
re-derive the registry by pointing the sync script at any MCP endpoint:

```bash
bash integrations/camazotz/sync-tools.sh http://localhost:8080/mcp
# or:  ./sync-tools.sh http://<node>:30080/mcp
# or:  ./sync-tools.sh https://camazotz.example.com/mcp
```

Exits 0 if the bundled registry already covers every live tool. Otherwise
prints `added` (tools the deployment has but the registry does not — these
are silently default-denied today, triage them into tier 1 / 2 / 3) and
`removed` (tools the registry has but the deployment no longer exposes —
likely renamed). Tier placement is left to the operator on purpose:
silently appending unknowns to ALLOW would defeat the bundle's whole
point.

## Test

```bash
bash integrations/camazotz/test.sh
```

Expected: tier 1+2 tools forwarded to camazotz, tier 3 tools blocked, unregistered tools rejected, full audit trail. The bundled registry now covers every live tool, so "unregistered tools rejected" only fires for tools added in your fork — re-run [`sync-tools.sh`](sync-tools.sh) and re-tier them before testing.

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

Use `:30090` whenever you want to exercise nullfield in front of the full 52 / 86 attack surface; keep `:30080` around for "is the upstream still healthy?" debugging and for demos that contrast the two paths.

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
