package extauthz

import (
	"context"

	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"

	"github.com/babywyrm/nullfield/pkg/audit"
	"github.com/babywyrm/nullfield/pkg/identity"
	"github.com/babywyrm/nullfield/pkg/policy"
)

// Assurance levels reachable in this phase.
//
// The spec's STRONG and MEDIUM both presume a grant bound to the workload, which
// arrives in a later phase. Emitting MEDIUM now would claim a binding that does
// not exist, so an attested workload with no grant mechanism gets its own level
// until there is something truer to say.
const (
	AssuranceAttested = "ATTESTED"
	AssuranceNone     = "NONE"
)

// Config is the server's dependencies.
type Config struct {
	Mode   Mode
	Engine policy.Engine
	Audit  audit.Emitter
}

// Server answers Envoy's external authorization checks using nullfield's
// existing decision core.
type Server struct {
	authv3.UnimplementedAuthorizationServer

	mode   Mode
	engine policy.Engine
	audit  audit.Emitter
}

// NewServer builds a decision server. An absent or unrecognised mode becomes
// observe rather than enforce, so a typo in configuration cannot start blocking
// traffic.
func NewServer(cfg Config) *Server {
	mode := cfg.Mode
	if !mode.Valid() {
		mode = ModeObserve
	}
	return &Server{mode: mode, engine: cfg.Engine, audit: cfg.Audit}
}

// Mode reports the mode this server is running in.
func (s *Server) Mode() Mode { return s.mode }

// Check decides one request.
//
// Policy outcomes return a response rather than a gRPC error. An error makes
// Envoy fall back to its own failure-mode default, which takes the decision out
// of nullfield's hands entirely — the opposite of the point.
func (s *Server) Check(ctx context.Context, req *authv3.CheckRequest) (*authv3.CheckResponse, error) {
	translated, err := Translate(req)
	if err != nil {
		// The only translation failures are an absent HTTP context and a
		// truncated body. Both mean we cannot see what we would be authorizing.
		s.emit(ctx, audit.Event{
			Type:           audit.EventArbiterDecision,
			Gate:           "translate",
			ReasonClass:    "body_truncated",
			Reason:         err.Error(),
			Attester:       identity.AttesterNone,
			Assurance:      AssuranceNone,
			Counterfactual: "DENY",
		})
		return Respond(s.mode, policy.Decision{Allowed: false, Reason: err.Error()}), nil
	}

	decision := s.engine.Evaluate(ctx, translated.Policy)

	event := audit.Event{
		Type:           audit.EventArbiterDecision,
		Method:         translated.Policy.Method,
		ToolName:       translated.Policy.ToolName,
		Target:         translated.Policy.Target,
		Transport:      translated.Policy.Transport,
		Gate:           decision.Gate,
		ReasonClass:    decision.ReasonClass,
		RuleID:         decision.RuleID,
		Reason:         decision.Reason,
		Labels:         decision.Labels,
		Counterfactual: Counterfactual(decision),
		Attester:       identity.AttesterNone,
		Assurance:      AssuranceNone,
	}
	if translated.Attestation != nil {
		event.WorkloadPrincipal = translated.Attestation.Principal
		event.Attester = translated.Attestation.Attester
		event.Assurance = AssuranceAttested
	}
	s.emit(ctx, event)

	return Respond(s.mode, decision), nil
}

func (s *Server) emit(ctx context.Context, e audit.Event) {
	if s.audit == nil {
		return
	}
	s.audit.Emit(ctx, e)
}
