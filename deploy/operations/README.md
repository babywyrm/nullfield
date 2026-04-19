# Operations — Cluster-Level Observability

Deploy-once resources for monitoring nullfield across all pods in the cluster.

## What's here

| File | What it does | Requires |
|------|-------------|----------|
| `servicemonitor.yaml` | Tells Prometheus to scrape nullfield `/metrics` endpoints | Prometheus Operator |
| `alertmanager-rules.yaml` | Pre-built alert rules for denials, identity failures, circuit trips, anomalies, budget exhaustion | Prometheus Operator |
| `grafana-dashboard.json` | 8-panel dashboard: call rates, top denied tools, methods, identity failures, circuit trips, anomalies, budget events | Grafana |

## Deploy

```bash
# ServiceMonitor + alert rules (requires Prometheus Operator)
kubectl apply -f deploy/operations/servicemonitor.yaml
kubectl apply -f deploy/operations/alertmanager-rules.yaml

# Grafana dashboard — import via Grafana UI or API
# Dashboards > Import > paste grafana-dashboard.json
```

## Alert rules

| Alert | Condition | Severity |
|-------|-----------|----------|
| NullfieldHighDenyRate | >1 deny/sec for 2min | warning |
| NullfieldIdentityFailures | >0.1 failures/sec for 1min | warning |
| NullfieldCircuitBreakerTrips | Any trip in 5min | critical |
| NullfieldAnomalyDetected | Any anomaly in 5min | warning |
| NullfieldBudgetExhausted | Budget limits hit for 1min | info |

## Grafana panels

1. Tool Call Rate (allowed vs denied over time)
2. Top 10 Denied Tools (table)
3. Requests by MCP Method
4. Identity Failures (stat counter)
5. Circuit Breaker Trips (stat counter)
6. Anomaly Alerts (by type)
7. Top 10 Tools by Volume (bar gauge)
8. Budget Exhaustion Events (by tool)
