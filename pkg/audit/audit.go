package audit

import (
	"context"
	"encoding/json"
	"log/slog"
	"time"
)

type EventType string

const (
	EventMCPRequest        EventType = "mcp.request"
	EventToolAllowed       EventType = "tool.allowed"
	EventToolDenied        EventType = "tool.denied"
	EventIdentityFailed    EventType = "identity.failed"
	EventCircuitTripped    EventType = "circuit.tripped"
	EventUpstreamError     EventType = "upstream.error"
	EventAnomalyVelocity   EventType = "anomaly.velocity"
	EventHoldCreated       EventType = "hold.created"
	EventHoldApproved      EventType = "hold.approved"
	EventScopeModified     EventType = "scope.modified"
	EventAnomalySequence   EventType = "anomaly.sequence"
	EventClaimsDrift       EventType = "claims.drift"
	EventInspectionFinding EventType = "inspection.finding"
	EventInspectionRedact  EventType = "inspection.redact"
	EventToolDrift         EventType = "tool.drift"
	EventToolRugPull       EventType = "tool.rug_pull"

	// EventArbiterDecision is a decision reached by the ext_authz decision
	// service. It is deliberately distinct from tool.allowed and tool.denied,
	// which the proxy emits for calls it actually allowed or blocked: in observe
	// mode the arbiter reaches a verdict without applying it, and reporting that
	// as tool.denied would tell every dashboard traffic was blocked when none
	// was. Whether the verdict was applied is the Counterfactual field.
	EventArbiterDecision EventType = "arbiter.decision"
)

type Event struct {
	Type        EventType         `json:"type"`
	Method      string            `json:"method,omitempty"`
	ToolName    string            `json:"tool_name,omitempty"`
	Identity    string            `json:"identity,omitempty"`
	SessionID   string            `json:"session_id,omitempty"`
	Target      string            `json:"target,omitempty"`
	Gate        string            `json:"gate,omitempty"`
	ReasonClass string            `json:"reason_class,omitempty"`
	RuleIndex   *int              `json:"rule_index,omitempty"`
	RuleID      string            `json:"rule_id,omitempty"`
	PolicyRef   string            `json:"policy_ref,omitempty"`
	RegistryRef string            `json:"registry_ref,omitempty"`
	Route       string            `json:"route,omitempty"`
	Labels      map[string]string `json:"labels,omitempty"`
	Reason      string            `json:"reason,omitempty"`
	Error       string            `json:"error,omitempty"`
	Args        map[string]any    `json:"args,omitempty"`

	// Provenance. Empty in proxy mode, where there is no mesh-attested peer, so
	// existing events serialize byte-identically and current consumers see no
	// new keys.
	WorkloadPrincipal string `json:"workload_principal,omitempty"`
	Attester          string `json:"attester,omitempty"`
	Assurance         string `json:"assurance,omitempty"`
	Transport         string `json:"transport,omitempty"`
	Counterfactual    string `json:"counterfactual,omitempty"`

	Time time.Time `json:"timestamp"`
}

// Emitter sends audit events to a sink.
type Emitter interface {
	Emit(ctx context.Context, event Event)
}

// LogEmitter writes structured JSON audit events via slog.
type LogEmitter struct {
	logger *slog.Logger
}

func NewLogEmitter(logger *slog.Logger) *LogEmitter {
	return &LogEmitter{logger: logger}
}

func (e *LogEmitter) Emit(_ context.Context, event Event) {
	event.Time = time.Now().UTC()

	data, _ := json.Marshal(event)
	e.logger.Info("audit",
		"event_type", string(event.Type),
		"method", event.Method,
		"tool", event.ToolName,
		"identity", event.Identity,
		"gate", event.Gate,
		"reason_class", event.ReasonClass,
		"rule_id", event.RuleID,
		"payload", string(data),
	)
}

// MultiEmitter fans out events to multiple sinks.
type MultiEmitter struct {
	emitters []Emitter
}

func NewMultiEmitter(emitters ...Emitter) *MultiEmitter {
	return &MultiEmitter{emitters: emitters}
}

func (m *MultiEmitter) Emit(ctx context.Context, event Event) {
	if event.Time.IsZero() {
		event.Time = time.Now().UTC()
	}
	for _, e := range m.emitters {
		e.Emit(ctx, event)
	}
}
