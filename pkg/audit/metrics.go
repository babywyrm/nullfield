package audit

import (
	"context"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	toolCallsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "nullfield_tool_calls_total",
		Help: "Total tool call decisions by tool name and action",
	}, []string{"tool", "action", "reason"})

	requestsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "nullfield_requests_total",
		Help: "Total MCP requests by method",
	}, []string{"method"})

	identityFailuresTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "nullfield_identity_failures_total",
		Help: "Total identity verification failures",
	})

	circuitTripsTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "nullfield_circuit_trips_total",
		Help: "Total circuit breaker trips",
	})

	anomalyAlertsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "nullfield_anomaly_alerts_total",
		Help: "Total anomaly detection alerts by type",
	}, []string{"type"})
)

// MetricsEmitter increments Prometheus counters based on audit events.
type MetricsEmitter struct{}

func NewMetricsEmitter() *MetricsEmitter {
	return &MetricsEmitter{}
}

func (m *MetricsEmitter) Emit(_ context.Context, event Event) {
	switch event.Type {
	case EventToolAllowed:
		toolCallsTotal.WithLabelValues(event.ToolName, "allowed", "").Inc()
		requestsTotal.WithLabelValues(event.Method).Inc()

	case EventToolDenied:
		reason := truncateReason(event.Reason)
		toolCallsTotal.WithLabelValues(event.ToolName, "denied", reason).Inc()
		requestsTotal.WithLabelValues(event.Method).Inc()

	case EventMCPRequest:
		requestsTotal.WithLabelValues(event.Method).Inc()

	case EventIdentityFailed:
		identityFailuresTotal.Inc()
		requestsTotal.WithLabelValues(event.Method).Inc()

	case EventCircuitTripped:
		circuitTripsTotal.Inc()
		requestsTotal.WithLabelValues(event.Method).Inc()

	case EventAnomalyVelocity:
		anomalyAlertsTotal.WithLabelValues("velocity").Inc()
	}
}

func truncateReason(reason string) string {
	if len(reason) > 40 {
		return reason[:40]
	}
	return reason
}
