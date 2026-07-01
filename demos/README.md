# Demonstration Flows

Runnable walkthroughs showing how to configure and test nullfield features. Each demo is self-contained with its own README, config files, and scripts.

## Prerequisites

- nullfield binary built (`make build`)
- An MCP server running (camazotz on `:8080`, or the echo server via `docker compose up -d`)

## Demos

| # | Demo | What it covers |
|---|------|---------------|
| 01 | [Basic Tool Filtering](01-basic-tool-filtering/) | Tool registry, tiered policy, circuit breaker, audit trail |
| 02 | [JWT Identity Tracking](02-jwt-identity-tracking/) | Identity providers, JWT validation, when-conditions, identity types |
| 03 | [Anomaly Detection](03-anomaly-detection/) | Session binding, replay detection, velocity alerts |
| 04 | [Sidecar — Docker Compose](04-sidecar-compose/) | Full sidecar deployment with compose, policy + registry enforcement |
| 05 | [Sidecar — Kubernetes](05-sidecar-kubernetes/) | Sidecar injection, ConfigMap policy, service rewiring, Helm |
| 06 | [Hold Action](06-hold-action/) | Human approval gates, admin API, timeout behavior |
| 07 | [Budget Action](07-budget-action/) | Per-identity and per-session call quotas |
| 08 | [Scope Action](08-scope-action/) | Request/response modification, argument stripping, redaction |
| 09 | [Controller Mode](09-controller-mode/) | Centralized holds, shared budgets, unified admin API |
| 10 | [CRD Policy Management](10-crd-policy/) | Kubernetes custom resources, GitOps policy apply, controller sync |
| 11 | [Hot Policy Reload](11-hot-reload/) | Live policy updates without restart, ConfigMap reload |
| 12 | [Response Inspection](12-response-inspection/) | Credential/PII/prompt detection and redaction in tool responses |
| 13 | [AgenticFlow — Local Compile](13-agentic-flow-local/) | Least-privilege flow YAML compiled to policy + registry |
| 14 | [AgenticFlow — Kubernetes Runtime](14-agentic-flow-kubernetes/) | AgenticFlow CRD compiled by the controller and enforced by a sidecar |

Demos 01–03 run against a local binary. Demos 04+ deploy nullfield as a containerized sidecar.

Start with the [Quickstart](../docs/quickstart.md) for a guided path through all demos.
