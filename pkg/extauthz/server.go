package extauthz

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"slices"
	"sort"
	"strings"
	"time"

	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"

	"github.com/babywyrm/nullfield/pkg/audit"
	"github.com/babywyrm/nullfield/pkg/gates"
	"github.com/babywyrm/nullfield/pkg/identity"
	"github.com/babywyrm/nullfield/pkg/operations"
	"github.com/babywyrm/nullfield/pkg/policy"
)

// Assurance levels reachable in this phase.
//
// MEDIUM is an attested workload holding a run token bound to it. STRONG also
// needs a workload dedicated to one session, which nothing here can verify, so
// it is not claimed. An attested workload with no run token is ATTESTED.
const (
	AssuranceMedium   = "MEDIUM"
	AssuranceAttested = "ATTESTED"
	AssuranceNone     = "NONE"
)

const (
	GateRunToken = "run_token"

	ReasonRunTokenMissing = "run_token_missing"
	ReasonRunTokenUnbound = "run_token_unbound"
	ReasonRunTokenInvalid = "run_token_invalid"

	GateOperation            = "operation"
	ReasonOperationAmbiguous = "operation_ambiguous"

	GateTarget           = "target"
	ReasonTargetMismatch = "target_mismatch"
)

// Config is the server's dependencies.
type Config struct {
	Mode   Mode
	Engine policy.Engine
	Audit  audit.Emitter
	// Gates are the same registry, breaker, budget and velocity checks the
	// proxy runs around policy. The zero value runs none of them.
	Gates gates.Gates

	// RunTokens, when set, verifies the Txn-Token on every call and binds it to
	// the attested workload. A call without one is refused unless
	// RunTokenOptional; a token that is present and fails is always refused.
	RunTokens        *identity.RunTokenVerifier
	RunTokenOptional bool

	// Operations, when set, names each call from its target's operation map.
	// A path on a mapped target that the map cannot read one way only is
	// refused.
	Operations *operations.Map

	// LookupAddr, when set, reverse-resolves the address Envoy routed to. A
	// call whose Host names a different Service is refused: a waypoint routes
	// on the address, so Host is only the caller's claim about where it is
	// going. net.DefaultResolver.LookupAddr in a cluster.
	LookupAddr func(ctx context.Context, addr string) ([]string, error)

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
	gates   gates.Gates
	audit   audit.Emitter
	logger  *slog.Logger
	logPeer bool

	runTokens        *identity.RunTokenVerifier
	runTokenOptional bool
	operations       *operations.Map
	lookupAddr       func(ctx context.Context, addr string) ([]string, error)
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
		gates:   cfg.Gates,
		audit:   cfg.Audit,
		logger:  logger,
		logPeer: cfg.LogPeer,

		runTokens:        cfg.RunTokens,
		runTokenOptional: cfg.RunTokenOptional,
		operations:       cfg.Operations,
		lookupAddr:       cfg.LookupAddr,
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
		"destination_address", req.GetAttributes().GetDestination().GetAddress().GetSocketAddress().GetAddress(),
		"destination_service", req.GetAttributes().GetDestination().GetService(),
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
		return s.respond(policy.Decision{Allowed: false, Reason: err.Error()}), nil
	}

	decision := s.decide(ctx, translated)

	event := audit.Event{
		Type:           audit.EventArbiterDecision,
		Method:         translated.Policy.Method,
		ToolName:       translated.Policy.ToolName,
		Target:         translated.Policy.Target,
		Action:         translated.Policy.Action,
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
	if run := translated.Policy.Run; run != nil {
		event.RunID, event.SessionID = run.ID, run.ID
		event.Identity = translated.Policy.Identity.Subject
		event.Assurance = AssuranceMedium
	}
	s.emit(ctx, event)

	return s.respond(decision), nil
}

// respond strips the run token from anything Envoy will forward, so it never
// reaches the upstream, a SaaS API included.
func (s *Server) respond(d policy.Decision) *authv3.CheckResponse {
	resp := Respond(s.mode, d)
	if ok := resp.GetOkResponse(); ok != nil && s.runTokens != nil {
		ok.HeadersToRemove = append(ok.HeadersToRemove, strings.ToLower(identity.RunTokenHeader))
	}
	return resp
}

// verifyRun checks the run token and, when it holds, puts its identity and run
// on the policy request.
func (s *Server) verifyRun(t *Translated) *gates.Refusal {
	principal := ""
	if t.Attestation != nil {
		principal = t.Attestation.Principal
	}
	id, run, err := s.runTokens.Verify(t.Headers.Get(identity.RunTokenHeader), principal)
	switch {
	case err == nil:
		t.Policy.Identity, t.Policy.Run = id, run
		return nil
	case errors.Is(err, identity.ErrRunTokenMissing):
		if s.runTokenOptional {
			return nil
		}
		return &gates.Refusal{Gate: GateRunToken, ReasonClass: ReasonRunTokenMissing, Reason: "a run token is required"}
	case errors.Is(err, identity.ErrRunTokenUnbound):
		return &gates.Refusal{Gate: GateRunToken, ReasonClass: ReasonRunTokenUnbound, Reason: err.Error()}
	default:
		return &gates.Refusal{Gate: GateRunToken, ReasonClass: ReasonRunTokenInvalid, Reason: err.Error()}
	}
}

// verifyTarget checks Host against the Service the call is routed to. A
// destination DNS cannot name, such as a ServiceEntry VIP, leaves Host
// unverified and Service empty.
func (s *Server) verifyTarget(ctx context.Context, t *Translated) *gates.Refusal {
	if s.lookupAddr == nil || t.Destination == "" {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	names, _ := s.lookupAddr(ctx, t.Destination)
	names = slices.DeleteFunc(names, func(n string) bool { return !isService(hostOf(n)) })
	if len(names) == 0 {
		return nil
	}
	h := hostOf(t.Policy.Target)
	for _, n := range names {
		// Any dot-boundary prefix is how the resolver's search path names it:
		// name, name.ns, name.ns.svc.
		if n = hostOf(n); h == t.Destination || h == n || strings.HasPrefix(n, h+".") {
			t.Service = n
			return nil
		}
	}
	return &gates.Refusal{Gate: GateTarget, ReasonClass: ReasonTargetMismatch,
		Reason: fmt.Sprintf("Host %q does not name %s, where the call is routed", t.Policy.Target, hostOf(names[0]))}
}

// isService reports a Service VIP's name, name.ns.svc.<cluster domain>. A pod
// IP reverse-resolves too, behind a sidecar or a headless Service, but Host
// names the Service rather than the pod, so those are left unverified.
func isService(name string) bool {
	labels := strings.Split(name, ".")
	return len(labels) >= 4 && labels[2] == "svc"
}

func hostOf(target string) string {
	if h, _, err := net.SplitHostPort(target); err == nil {
		target = h
	}
	return strings.TrimSuffix(strings.ToLower(target), ".")
}

// decide runs the gates around policy in the order the proxy does: registry and
// circuit first, then policy, then budget, circuit accounting and velocity for
// a call policy allowed.
func (s *Server) decide(ctx context.Context, t *Translated) policy.Decision {
	call := gates.Call{Tool: t.Policy.ToolName}
	// Charge only an attested principal. RawPrincipal is whatever the mesh
	// presented, parseable or not, and a value nobody vouched for is not an
	// identity to bill.
	if t.Attestation != nil {
		call.Subject = t.Attestation.Principal
	}
	if r := s.verifyTarget(ctx, t); r != nil {
		return refuse(policy.Decision{RuleIndex: -1}, r)
	}
	if s.operations != nil {
		p := &t.Policy
		var err error
		if p.Action, p.Params, err = s.operations.Resolve(p.Target, p.Operation); err != nil {
			return refuse(policy.Decision{RuleIndex: -1}, &gates.Refusal{
				Gate: GateOperation, ReasonClass: ReasonOperationAmbiguous, Reason: err.Error()})
		}
	}
	if s.runTokens != nil {
		if r := s.verifyRun(t); r != nil {
			return refuse(policy.Decision{RuleIndex: -1}, r)
		}
		if t.Policy.Run != nil {
			call.Session = t.Policy.Run.ID
		}
	}

	if r := s.gates.Admit(call); r != nil {
		if r.Gate == gates.GateCircuit && s.gates.Breaker.FirstTrip(call.Session) {
			s.emit(ctx, audit.Event{
				Type: audit.EventCircuitTripped, Target: t.Policy.Target, ToolName: t.Policy.ToolName,
				Gate: r.Gate, ReasonClass: r.ReasonClass, Reason: r.Reason,
				RunID: call.Session, SessionID: call.Session, Identity: t.Policy.Identity.Subject,
				WorkloadPrincipal: t.RawPrincipal, Attester: t.Attestation.Attester, Assurance: AssuranceMedium,
			})
		}
		return refuse(policy.Decision{RuleIndex: -1}, r)
	}
	decision := s.engine.Evaluate(ctx, t.Policy)
	if !decision.Allowed {
		return decision
	}
	r, warning := s.gates.Charge(call, decision)
	if r != nil {
		return refuse(decision, r)
	}
	// A refusal lands on the decision event. A warning has nowhere else to go.
	if warning != nil {
		s.emit(ctx, audit.Event{
			Type:              audit.EventAnomalyVelocity,
			ToolName:          t.Policy.ToolName,
			Target:            t.Policy.Target,
			Gate:              warning.Gate,
			ReasonClass:       warning.ReasonClass,
			Reason:            warning.Reason,
			WorkloadPrincipal: t.RawPrincipal,
		})
	}
	return decision
}

// refuse turns a decision into a refusal by a gate, keeping the rule that
// matched so the audit trail says whose budget or limit it was.
func refuse(d policy.Decision, r *gates.Refusal) policy.Decision {
	d.Allowed, d.Held, d.Scoped = false, false, false
	d.Gate, d.ReasonClass, d.Reason = r.Gate, r.ReasonClass, r.Reason
	return d
}

func (s *Server) emit(ctx context.Context, e audit.Event) {
	if s.audit == nil {
		return
	}
	s.audit.Emit(ctx, e)
}
