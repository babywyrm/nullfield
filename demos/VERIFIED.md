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
