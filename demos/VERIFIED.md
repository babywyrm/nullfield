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
