package audit

import (
	"context"
	"strings"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	toolCallsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "nullfield_tool_calls_total",
		Help: "Total tool call decisions by tool name, action, gate, and reason class",
	}, []string{"tool", "action", "gate", "reason_class"})

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
		labels := toolCallMetricLabels(event)
		toolCallsTotal.WithLabelValues(labels.tool, labels.action, labels.gate, labels.reasonClass).Inc()
		requestsTotal.WithLabelValues(event.Method).Inc()

	case EventToolDenied:
		labels := toolCallMetricLabels(event)
		toolCallsTotal.WithLabelValues(labels.tool, labels.action, labels.gate, labels.reasonClass).Inc()
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

type toolCallLabels struct {
	tool        string
	action      string
	gate        string
	reasonClass string
}

func toolCallMetricLabels(event Event) toolCallLabels {
	action := "allowed"
	if event.Type == EventToolDenied {
		action = "denied"
	}
	gate := event.Gate
	if gate == "" {
		gate = inferGate(event)
	}
	return toolCallLabels{
		tool:        metricToolLabel(event),
		action:      action,
		gate:        gate,
		reasonClass: classifyReason(event),
	}
}

func metricToolLabel(event Event) string {
	switch event.Gate {
	case "registry":
		return "unregistered"
	case "route":
		return "unrouted"
	default:
		return event.ToolName
	}
}

func inferGate(event Event) string {
	switch event.Type {
	case EventToolDenied:
		return "policy"
	case EventToolAllowed:
		return "policy"
	default:
		return "unknown"
	}
}

func classifyReason(event Event) string {
	if event.ReasonClass != "" {
		return event.ReasonClass
	}
	reason := strings.ToLower(event.Reason)
	switch {
	case event.Type == EventToolAllowed:
		return "allowed"
	case strings.Contains(reason, "tool not registered"):
		return "tool_not_registered"
	case strings.Contains(reason, "budget exhausted"):
		return "budget_exhausted"
	case strings.Contains(reason, "hold timed out"):
		return "hold_timeout"
	case strings.Contains(reason, "hold") && strings.Contains(reason, "denied"):
		return "hold_denied"
	case strings.Contains(reason, "circuit breaker"):
		return "circuit_open"
	case strings.Contains(reason, "no route for tool"):
		return "no_route"
	case reason == "":
		return "unspecified"
	default:
		return "policy_denied"
	}
}
