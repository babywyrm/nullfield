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

Each demo builds on the previous one. Start with 01 if you're new to nullfield.
