# Verified Runs

Tiers 2 and 3 need a cluster or an Istio ambient mesh and are never run in CI,
so their status is a claim a human made on a specific substrate rather than
something a badge covers. Each line below was appended by
`demos/run.sh --tier N --record`.

A stale line here is possible. That is the trade: a dated claim about a named
substrate is weaker than CI and considerably stronger than silence.

```bash
NULLFIELD_SUBSTRATE="k3s 1.34 / Istio 1.30.1 ambient" ./demos/run.sh --tier 3 --record
```

| Date | Demo | Tier | Result | Substrate |
|---|---|---|---|---|
| 2026-07-27 | 01-basic-tool-filtering | 1 | PASS | unspecified |
| 2026-07-27 | 02-jwt-identity-tracking | 1 | PASS | unspecified |
| 2026-07-27 | 03-anomaly-detection | 1 | PASS | unspecified |
| 2026-07-27 | 06-hold-action | 1 | PASS | unspecified |
| 2026-07-27 | 07-budget-action | 1 | PASS | unspecified |
| 2026-07-27 | 08-scope-action | 1 | PASS | unspecified |
| 2026-07-27 | 09-controller-mode | 1 | PASS | unspecified |
| 2026-07-27 | 12-response-inspection | 1 | PASS | unspecified |
| 2026-07-27 | 13-agentic-flow-local | 1 | PASS | unspecified |
| 2026-07-27 | 10-crd-policy | 2 | PASS | k3s v1.35.5 / Istio 1.30.1 ambient (brainbox) |
| 2026-07-27 | 14-agentic-flow-kubernetes | 2 | PASS | k3s v1.35.5 / Istio 1.30.1 ambient (brainbox) |
| 2026-07-27 | 15-proxy-baseline | 2 | PASS | k3s v1.35.5 / Istio 1.30.1 ambient (brainbox) |
| 2026-07-27 | 16-mesh-arbiter | 3 | PASS | k3s v1.35.5 / Istio 1.30.1 ambient (brainbox) |
| 2026-10-24 | 10-crd-policy | 2 | PASS | k3s v1.36.3 / Istio 1.30.1 ambient (brainbox), grpc 1.84 |
| 2026-10-24 | 14-agentic-flow-kubernetes | 2 | PASS | k3s v1.36.3 / Istio 1.30.1 ambient (brainbox), grpc 1.84 |
| 2026-10-24 | 15-proxy-baseline | 2 | PASS | k3s v1.36.3 / Istio 1.30.1 ambient (brainbox), grpc 1.84 |
| 2026-10-24 | 16-mesh-arbiter | 3 | PASS | k3s v1.36.3 / Istio 1.30.1 ambient (brainbox), grpc 1.84 |
| 2026-10-25 | 18-operation-maps | 3 | PASS | k3s v1.36.5 / Istio 1.30.1 ambient (brainbox); check 7 (Host checked against destination) fails on the prior image; 16, 17, 19 re-run green |
| 2026-10-25 | 20-proxy-signals | 1 | PASS | Docker Desktop, macOS (all ten tier-1 demos green) |
| 2026-10-25 | 19-signals | 3 | PASS | k3s v1.36.5 / Istio 1.30.1 ambient (brainbox); re-run after the receiver moved to receiver.py |
| 2026-10-25 | 19-signals | 3 | PASS | k3s v1.36.5 / Istio 1.30.1 ambient (brainbox); 17, 18, 16 re-run green after it |
| 2026-10-25 | 18-operation-maps | 3 | PASS | k3s v1.36.5 / Istio 1.30.1 ambient (brainbox); 17 and 16 re-run green after it |
| 2026-10-25 | 17-run-tokens | 3 | PASS | k3s v1.36.5 / Istio 1.30.1 ambient (brainbox) |
| 2026-10-25 | 16-mesh-arbiter | 3 | PASS | k3s v1.36.5 / Istio 1.30.1 ambient (brainbox), run after 17 |
