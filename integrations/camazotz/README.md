# Camazotz Integration

Test nullfield against [camazotz](https://github.com/babywyrm/camazotz), a vulnerable-by-design MCP security training platform with 25 lab modules and 57 tools mapped to OWASP MCP Top 10 and the MCP Red Team Playbook.

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

## What nullfield catches vs. what it doesn't (yet)

| Attack | nullfield today | Future layer needed |
|--------|----------------|---------------------|
| Calling a blocked tool (SSRF, exfil) | Blocked at policy | L1 (works now) |
| Calling an unknown tool | Blocked at registry | L1 (works now) |
| Agent loop exhaustion | Circuit breaker trips | L1 (works now) |
| Agent impersonating a human | Not detected | L2 (identity-aware policy) |
| Tool appearing after init (rug pull) | Not detected post-startup | L3 (tool governance) |
| Unbounded delegation chains | Not inspected | L4 (agentic flow control) |
| Cross-tenant memory access | Forwarded (allowed tool) | L2 (identity + tenant scoping) |
