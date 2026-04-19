# Observability Guide

How to monitor nullfield: Prometheus metrics, structured audit logs, and anomaly detection alerts.

---

## Prometheus Metrics

nullfield exposes Prometheus metrics on the admin port at `/metrics`. Always enabled, zero-cost if nobody scrapes.

**Endpoint:** `http://<admin-addr>/metrics` (default `:9091/metrics`)

### Available metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `nullfield_tool_calls_total` | counter | tool, action, reason | Tool call decisions (allowed/denied) |
| `nullfield_requests_total` | counter | method | All MCP requests by method |
| `nullfield_identity_failures_total` | counter | — | Identity verification failures |
| `nullfield_circuit_trips_total` | counter | — | Circuit breaker trips |
| `nullfield_anomaly_alerts_total` | counter | type | Anomaly detection alerts by type |

### Scrape config

Add to your Prometheus config:

```yaml
scrape_configs:
  - job_name: nullfield
    metrics_path: /metrics
    static_configs:
      - targets: ["nullfield-admin:9091"]
```

On Kubernetes with a ServiceMonitor:

```yaml
apiVersion: monitoring.coreos.com/v1
kind: ServiceMonitor
metadata:
  name: nullfield
spec:
  selector:
    matchLabels:
      app: brain-gateway
  endpoints:
    - port: nullfield-admin
      path: /metrics
      interval: 15s
```

### Useful PromQL queries

```promql
# Tool call rate (allowed vs denied)
sum by (action) (rate(nullfield_tool_calls_total[5m]))

# Top denied tools
topk(5, sum by (tool) (rate(nullfield_tool_calls_total{action="denied"}[5m])))

# Identity failure rate
rate(nullfield_identity_failures_total[5m])

# Anomaly alert rate
rate(nullfield_anomaly_alerts_total[5m])
```

---

## Structured Audit Logs

Every decision emits a JSON log line to stdout with these fields:

```json
{
  "time": "2026-04-18T20:28:43Z",
  "level": "INFO",
  "msg": "audit",
  "event_type": "tool.denied",
  "method": "tools/call",
  "tool": "secrets.leak_config",
  "identity": "dev-user",
  "payload": "{...}"
}
```

### Event types

| Event | When |
|-------|------|
| `mcp.request` | Non-tools/call MCP method (initialize, tools/list, ping) |
| `tool.allowed` | Tool call passed all gates and was forwarded |
| `tool.denied` | Tool call blocked (registry, policy, or circuit breaker) |
| `identity.failed` | Identity verification or integrity check failed |
| `circuit.tripped` | Session exceeded call count or duration limit |
| `anomaly.velocity` | Tool call velocity exceeded threshold |

### Filtering audit logs

```bash
# All denials
kubectl -n camazotz logs -l app=brain-gateway -c nullfield | grep "tool.denied"

# Identity failures
kubectl -n camazotz logs -l app=brain-gateway -c nullfield | grep "identity.failed"

# Anomaly alerts
kubectl -n camazotz logs -l app=brain-gateway -c nullfield | grep "anomaly"
```

---

## Anomaly Detection

### Velocity tracking

Detects abnormal tool call rates per identity. Enable in the policy:

```yaml
anomaly:
  enabled: true
  velocity:
    threshold: 30       # calls per minute per identity
    alertAction: LOG    # LOG = alert but allow, DENY = block
```

When a velocity alert fires, the audit log shows:

```json
{
  "event_type": "anomaly.velocity",
  "tool": "cost.invoke_llm",
  "identity": "runaway-agent",
  "reason": "velocity 45/min exceeds threshold 30"
}
```

And the `nullfield_anomaly_alerts_total{type="velocity"}` Prometheus counter increments.

### Session binding (integrity)

Detects mid-session identity changes. Enable in the policy:

```yaml
integrity:
  enabled: true
  bindToSession: true
```

### Replay detection (integrity)

Detects reused JWT tokens. Enable in the policy:

```yaml
integrity:
  enabled: true
  detectReplay: true
```

---

## Combining everything

A full observability setup:

1. **Prometheus** scrapes `/metrics` every 15s
2. **Grafana** dashboard shows tool call rates, deny rates, anomaly alerts
3. **kubectl logs** or a log aggregator captures the structured audit trail
4. **Alertmanager** fires on `nullfield_anomaly_alerts_total` or `nullfield_identity_failures_total` spikes
