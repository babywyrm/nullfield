package extauthz

import (
	"context"
	"io"
	"log/slog"
	"sort"

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

	// Logger receives peer diagnostics when LogPeer is set. Optional.
	Logger *slog.Logger
	// LogPeer logs the source attributes and header names of every check.
	//
	// Whether a mesh populates source.principal varies by topology — sidecar
	// versus waypoint, and by how the peer certificate reaches the filter. When
	// it arrives empty there is nothing in an audit trail to distinguish "the
	// caller is outside the mesh" from "this deployment does not deliver peer
	// identity to ext_authz", and those need opposite fixes. This answers it
	// without attaching a debugger to a production decision path.
	//
	// Off by default: it logs header names on every request.
	LogPeer bool
}

// Server answers Envoy's external authorization checks using nullfield's
// existing decision core.
type Server struct {
	authv3.UnimplementedAuthorizationServer

	mode    Mode
	engine  policy.Engine
	audit   audit.Emitter
	logger  *slog.Logger
	logPeer bool
}

// NewServer builds a decision server. An absent or unrecognised mode becomes
// observe rather than enforce, so a typo in configuration cannot start blocking
// traffic.
func NewServer(cfg Config) *Server {
	mode := cfg.Mode
	if !mode.Valid() {
		mode = ModeObserve
	}
	logger := cfg.Logger
	if logger == nil {
		logger = slog.New(slog.NewJSONHandler(io.Discard, nil))
	}
	return &Server{
		mode:    mode,
		engine:  cfg.Engine,
		audit:   cfg.Audit,
		logger:  logger,
		logPeer: cfg.LogPeer,
	}
}

// describePeer logs what the mesh actually delivered about the caller.
func (s *Server) describePeer(req *authv3.CheckRequest) {
	if !s.logPeer {
		return
	}
	src := req.GetAttributes().GetSource()
	attrs := req.GetAttributes().GetRequest().GetHttp()

	names := make([]string, 0, len(attrs.GetHeaders()))
	for k := range attrs.GetHeaders() {
		names = append(names, k)
	}
	sort.Strings(names)

	s.logger.Info("ext_authz peer",
		"source_principal", src.GetPrincipal(),
		"source_service", src.GetService(),
		"source_address", src.GetAddress().GetSocketAddress().GetAddress(),
		"destination_principal", req.GetAttributes().GetDestination().GetPrincipal(),
		"header_names", names)
}

// Mode reports the mode this server is running in.
func (s *Server) Mode() Mode { return s.mode }

// Check decides one request.
//
// Policy outcomes return a response rather than a gRPC error. An error makes
// Envoy fall back to its own failure-mode default, which takes the decision out
// of nullfield's hands entirely — the opposite of the point.
func (s *Server) Check(ctx context.Context, req *authv3.CheckRequest) (*authv3.CheckResponse, error) {
	s.describePeer(req)

	translated, err := Translate(req)
	if err != nil {
		// The only translation failures are an absent HTTP context and a
		// truncated body. Both mean we cannot see what we would be authorizing.
		event := audit.Event{
			Type:           audit.EventArbiterDecision,
			Gate:           "translate",
			ReasonClass:    "body_truncated",
			Reason:         err.Error(),
			Attester:       identity.AttesterNone,
			Assurance:      AssuranceNone,
			Counterfactual: CounterfactualFor(s.mode, policy.Decision{Allowed: false}),
		}
		// Attribution still applies to a request we are refusing to decide, and
		// it matters more here than on an ordinary allow.
		if translated != nil {
			event.Target = translated.Policy.Target
			event.WorkloadPrincipal = translated.RawPrincipal
			if translated.Attestation != nil {
				event.Attester = translated.Attestation.Attester
				event.Assurance = AssuranceAttested
			}
		}
		s.emit(ctx, event)
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
		Counterfactual: CounterfactualFor(s.mode, decision),
		// Record what the mesh actually presented, attested or not. Attester is
		// what says whether we could make anything of it.
		WorkloadPrincipal: translated.RawPrincipal,
		Attester:          identity.AttesterNone,
		Assurance:         AssuranceNone,
	}
	if translated.Attestation != nil {
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
