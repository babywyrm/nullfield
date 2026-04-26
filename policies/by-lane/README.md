# Per-Lane Policy Templates

Starting-point `NullfieldPolicy` per agentic-identity lane. Pick the lane
your workload lives on, copy the file, narrow the tool list to your
deployment, and apply.

Vocabulary (lane slugs + transport codes) is the canonical set published
by camazotz `GET /api/lanes` (schema v1) and defined in
[agentic-sec/docs/identity-flows.md](https://github.com/babywyrm/agentic-sec/blob/main/docs/identity-flows.md).
Do not rename the labels — mcpnuke reporting and cross-project tooling
look for them verbatim.

## The Five Lanes

| File | Lane | Default action | Use when |
|------|------|----------------|----------|
| `lane-1-human.yaml` | Human Direct | ALLOW + audit | A human talks to the MCP server with their own OIDC token |
| `lane-2-delegated.yaml` | Human → Agent | SCOPE + audit | An agent calls MCP on a human's behalf via token exchange |
| `lane-3-machine.yaml` | Machine Identity | SCOPE + audit | A bot, CI job, or daemon authenticates with a cert or SPIFFE ID |
| `lane-4-chain.yaml` | Agent → Agent | HOLD past depth=2, DENY past depth=3 | Multi-hop agent delegation chains |
| `lane-5-anonymous.yaml` | Anonymous | DENY (allowlist only) | Pre-auth discovery, health checks |

## Applying a Template

### Direct as YAML

```bash
# Pick the right lane file, edit identity providers + tool list, then:
kubectl apply -n <your-namespace> -f lane-2-delegated.yaml
```

### Select workloads by label

Each template's selector matches on `nullfield.io/lane=<slug>`. Tag your
workloads accordingly:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: my-agent
  labels:
    nullfield.io/lane: "delegated"
    nullfield.io/transport: "A"
```

## What's Enforced Today vs Spec'd

The templates reference three primitives from
[`docs/specs/2026-04-26-per-lane-policy-templates.md`](../docs/specs/2026-04-26-per-lane-policy-templates.md):

- `rules[].identity.requireActChain` — RFC 8693 `act` claim required
- `rules[].delegation.maxDepth` — bound the act-chain depth
- `rules[].identity.audienceMustNarrow` — RFC 8707 downscoping

These fields are **declared in the templates but not yet enforced by the
runtime engine** as of 2026-04-26. Upgrading to a nullfield build that
implements them activates enforcement automatically — no policy change
required. Until then, the surrounding rules (action, `requireIdentity`,
`maxCallsPerMinute`, `budget`) are fully enforced and meaningful on their
own.

## Composition

These are starting points, not exhaustive. Most real deployments will:

- Combine multiple lanes (e.g. Lane 1 for human operators + Lane 4 for
  the agent fleet)
- Add workload-specific tool allowlists inside the ALLOW rules
- Tune budgets to their actual traffic pattern (see
  `camazotz/camazotz_modules/budget_tuning_lab` for a guided exercise)
- Override `audit.logLevel` from FULL → NONE for high-volume tool call
  patterns where sampling is preferable

The templates ship with FULL audit so first-time deployers can see every
decision. Turn it down later.
