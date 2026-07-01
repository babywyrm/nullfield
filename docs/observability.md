# Observability Guide

How to monitor nullfield: Prometheus metrics, structured audit logs, and anomaly detection alerts.

---

## Prometheus Metrics

nullfield exposes Prometheus metrics on the admin port at `/metrics`. Always enabled, zero-cost if nobody scrapes.

**Endpoint:** `http://<admin-addr>/metrics` (default `:9091/metrics`)

### Available metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `nullfield_tool_calls_total` | counter | tool, action, gate, reason_class | Tool call decisions (allowed/denied) |
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

# Denials by enforcement gate
sum by (gate, reason_class) (rate(nullfield_tool_calls_total{action="denied"}[5m]))

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
  "gate": "policy",
  "reason_class": "policy_denied",
  "rule_id": "deny-secret-exfil",
  "payload": "{...}"
}
```

The top-level log fields are intentionally compact. The `payload` contains the full audit event, including `session_id`, `target`, `gate`, `reason_class`, `rule_index`, `rule_id`, `policy_ref`, `registry_ref`, `route`, and bounded operator-defined `labels` when available. Prometheus keeps only low-cardinality labels; use logs, OTLP, or controller events for high-cardinality details such as identity/session and policy references.

### Event types

| Event | When |
|-------|------|
| `mcp.request` | Non-tools/call MCP method (initialize, tools/list, ping) |
| `tool.allowed` | Tool call passed all gates and was forwarded |
| `tool.denied` | Tool call blocked (registry, policy, or circuit breaker) |
| `identity.failed` | Identity verification or integrity check failed |
| `circuit.tripped` | Session exceeded call count or duration limit |
| `anomaly.velocity` | Tool call velocity exceeded threshold |
| `anomaly.sequence` | Suspicious tool call sequence detected |
| `identity.drift` | Claims (scopes/groups) changed mid-session |

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

## OTLP Trace Export

nullfield can emit OpenTelemetry spans for every decision. Each audit event becomes a span with attributes for event type, tool, identity, session, gate, reason class, rule id, policy/registry refs, route, and reason. Opt-in via environment variable:

```bash
NULLFIELD_AUDIT_ENDPOINT=otel-collector.observability:4317
```

When configured, the tracer creates spans named `nullfield.<event_type>` (e.g. `nullfield.tool.allowed`, `nullfield.tool.denied`) with error status set automatically for denials, identity failures, and circuit trips.

Works with any OTLP-compatible collector (Jaeger, Tempo, Datadog, Honeycomb, etc.).

---

## Tool-Chain Sequence Detection

Detects suspicious ordered patterns of tool calls within a session. Configure patterns in the policy:

```yaml
anomaly:
  enabled: true
  sequences:
    - name: recon-then-exfil
      tools: [audit.list_actions, secrets.read_credential, egress.fetch_url]
      alertAction: DENY
    - name: enumerate-then-invoke
      tools: [tools.list, delegation.invoke_agent]
      alertAction: LOG
```

The tracker maintains a sliding window of recent tool calls per session (default 20). When a pattern matches (tools appear in order, not necessarily consecutively), it emits an alert and optionally denies the request.

---

## Claims Drift Detection

Detects when an identity's JWT claims (scopes, groups) change mid-session without re-authentication. Enable via:

```yaml
integrity:
  enabled: true
  detectDrift: true
```

On the first request in a session, nullfield snapshots the identity's scopes and groups. Subsequent requests are compared against the baseline. If scopes or groups change, the request is rejected with `-32001` and an `identity.failed` audit event.

This catches token manipulation where an attacker escalates privileges by modifying claims between requests.

---

## Controller Metrics

The nullfield-controller exposes its own `/metrics` endpoint on `:9091` with controller-specific counters:

| Metric | Type | Description |
|--------|------|-------------|
| `nullfield_controller_holds_total` | counter | Hold operations by outcome (approved/denied/timeout) |
| `nullfield_controller_budget_checks_total` | counter | Budget check requests from sidecars |
| `nullfield_controller_events_total` | counter | Audit events received from sidecars |
| `nullfield_controller_alerts_total` | counter | Webhook/Slack alerts dispatched |
| `nullfield_controller_sidecars_registered` | gauge | Currently registered sidecars |

---

## Cluster-Level Observability Stack

Pre-built resources in `deploy/operations/` (standalone) and `deploy/helm/nullfield/templates/` (Helm chart):

| File | Purpose | Requires |
|------|---------|----------|
| `servicemonitor.yaml` | Prometheus scrape config for nullfield sidecars and controller | Prometheus Operator |
| `alertmanager-rules.yaml` / `prometheusrule.yaml` | 5 alert rules (high deny rate, identity failures, circuit trips, anomalies, budget exhaustion) | Prometheus Operator |
| `grafana-dashboard.json` / `grafana-dashboard-cm.yaml` | 8-panel dashboard covering all nullfield metrics | Grafana |

The Helm chart includes these as templates — they deploy automatically with `helm install`. The ServiceMonitor scrapes both the sidecar admin ports and the controller's `:9091` endpoint, so all metrics land in the same Prometheus instance.

Deploy standalone (without Helm):

```bash
kubectl apply -f deploy/operations/servicemonitor.yaml
kubectl apply -f deploy/operations/alertmanager-rules.yaml
# Import grafana-dashboard.json via Grafana UI
```

---

## Combining everything

A full observability setup:

1. **Prometheus** scrapes `/metrics` every 15s via ServiceMonitor (sidecars + controller)
2. **Grafana** dashboard shows tool call rates, deny rates, anomaly alerts (8 panels)
3. **OTLP collector** receives trace spans for every decision (Jaeger/Tempo/etc.)
4. **kubectl logs** or a log aggregator captures the structured audit trail
5. **Alertmanager** fires on deny rate spikes, identity failures, circuit trips, anomalies, or budget exhaustion
6. **Controller admin API** provides a unified view of holds, budgets, events, and registered sidecars at `/admin`
