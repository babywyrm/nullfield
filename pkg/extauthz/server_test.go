package extauthz

import (
	"context"
	"testing"

	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"google.golang.org/grpc/codes"

	"github.com/babywyrm/nullfield/pkg/audit"
	"github.com/babywyrm/nullfield/pkg/policy"
)

type fakeEngine struct {
	decision policy.Decision
	got      policy.Request
	calls    int
}

func (f *fakeEngine) Evaluate(_ context.Context, req policy.Request) policy.Decision {
	f.got = req
	f.calls++
	return f.decision
}

type recorder struct{ events []audit.Event }

func (r *recorder) Emit(_ context.Context, e audit.Event) { r.events = append(r.events, e) }

func newServer(mode Mode, d policy.Decision) (*Server, *fakeEngine, *recorder) {
	eng := &fakeEngine{decision: d}
	rec := &recorder{}
	return NewServer(Config{Mode: mode, Engine: eng, Audit: rec}), eng, rec
}

const spiffeRunner = "spiffe://cluster.local/ns/agents/sa/job-runner"

const toolsCallBody = `{"jsonrpc":"2.0","id":1,"method":"tools/call",` +
	`"params":{"name":"secrets.leak_config","arguments":{}}}`

func TestCheckPassesTheTranslatedRequestToTheEngine(t *testing.T) {
	s, eng, _ := newServer(ModeObserve, policy.Decision{Allowed: true})

	if _, err := s.Check(context.Background(),
		checkRequest(spiffeRunner, toolsCallBody, map[string]string{})); err != nil {
		t.Fatalf("Check: %v", err)
	}
	if eng.calls != 1 {
		t.Fatalf("engine called %d times, want 1", eng.calls)
	}
	if eng.got.ToolName != "secrets.leak_config" {
		t.Errorf("engine saw tool %q, want secrets.leak_config", eng.got.ToolName)
	}
	if eng.got.Transport != policy.TransportMCP {
		t.Errorf("engine saw transport %q, want %q", eng.got.Transport, policy.TransportMCP)
	}
}

func TestCheckEmitsProvenanceIncludingTheAttester(t *testing.T) {
	s, _, rec := newServer(ModeObserve, policy.Decision{Allowed: false, Reason: "no matching rule"})

	if _, err := s.Check(context.Background(),
		checkRequest(spiffeRunner, toolsCallBody, map[string]string{})); err != nil {
		t.Fatalf("Check: %v", err)
	}
	if len(rec.events) != 1 {
		t.Fatalf("emitted %d events, want 1", len(rec.events))
	}
	e := rec.events[0]
	if e.Type != audit.EventArbiterDecision {
		t.Errorf("type = %q, want %q", e.Type, audit.EventArbiterDecision)
	}
	if e.WorkloadPrincipal != spiffeRunner {
		t.Errorf("principal = %q, want %q", e.WorkloadPrincipal, spiffeRunner)
	}
	if e.Attester != "mesh-spiffe" {
		t.Errorf("attester = %q, want mesh-spiffe", e.Attester)
	}
	if e.Assurance != AssuranceAttested {
		t.Errorf("assurance = %q, want %q", e.Assurance, AssuranceAttested)
	}
	if e.Counterfactual != "DENY" {
		t.Errorf("counterfactual = %q, want DENY", e.Counterfactual)
	}
}

func TestObserveModeRecordsADenialWithoutBlocking(t *testing.T) {
	// The whole point of observe mode. If this ever fails, a rollout that was
	// declared read-only has started breaking production traffic.
	s, _, rec := newServer(ModeObserve, policy.Decision{Allowed: false, Reason: "no matching rule"})

	resp, err := s.Check(context.Background(),
		checkRequest(spiffeRunner, toolsCallBody, map[string]string{}))
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if resp.GetStatus().GetCode() != int32(codes.OK) {
		t.Fatalf("status = %d, want OK — observe mode must never block",
			resp.GetStatus().GetCode())
	}
	if rec.events[0].Counterfactual != "DENY" {
		t.Error("a denial that was not applied must still be recorded")
	}
}

func TestEnforceModeAppliesTheDenial(t *testing.T) {
	s, _, _ := newServer(ModeEnforce, policy.Decision{Allowed: false, Reason: "no matching rule"})

	resp, err := s.Check(context.Background(),
		checkRequest(spiffeRunner, toolsCallBody, map[string]string{}))
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if resp.GetStatus().GetCode() != int32(codes.PermissionDenied) {
		t.Errorf("status = %d, want PermissionDenied", resp.GetStatus().GetCode())
	}
	if resp.GetDeniedResponse().GetBody() != "no matching rule" {
		t.Errorf("denial body = %q, want the decision reason",
			resp.GetDeniedResponse().GetBody())
	}
}

func TestATruncatedBodyDeniesInEnforceAndRecordsInObserve(t *testing.T) {
	truncating := func() *authv3.CheckRequest {
		r := checkRequest(spiffeRunner, "{}", map[string]string{})
		r.Attributes.Request.Http.Size = 999999
		return r
	}

	enforce, eng, _ := newServer(ModeEnforce, policy.Decision{Allowed: true})
	resp, err := enforce.Check(context.Background(), truncating())
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if resp.GetStatus().GetCode() != int32(codes.PermissionDenied) {
		t.Errorf("enforce status = %d, want PermissionDenied for a truncated body",
			resp.GetStatus().GetCode())
	}
	if eng.calls != 0 {
		t.Errorf("engine was consulted %d times on a body we cannot read; want 0",
			eng.calls)
	}

	observe, _, rec := newServer(ModeObserve, policy.Decision{Allowed: true})
	resp, err = observe.Check(context.Background(), truncating())
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if resp.GetStatus().GetCode() != int32(codes.OK) {
		t.Errorf("observe status = %d, want OK", resp.GetStatus().GetCode())
	}
	if len(rec.events) != 1 || rec.events[0].ReasonClass != "body_truncated" {
		t.Errorf("expected one body_truncated event, got %+v", rec.events)
	}
}

// A counterfactual answers "what would enforcement have done?". In enforce
// mode it did it, so the field must be absent: an operator filtering on
// counterfactual to size up a rollout is asking which calls a shadow
// deployment *would* have blocked, and enforce-mode events answering that
// query inflate the count with denials that already happened.
func TestEnforceModeDoesNotLabelAnAppliedDenialACounterfactual(t *testing.T) {
	s, _, rec := newServer(ModeEnforce, policy.Decision{Allowed: false, Reason: "no matching rule"})

	if _, err := s.Check(context.Background(),
		checkRequest(spiffeRunner, toolsCallBody, map[string]string{})); err != nil {
		t.Fatalf("Check: %v", err)
	}
	if got := rec.events[0].Counterfactual; got != "" {
		t.Errorf("counterfactual = %q on an applied denial, want empty", got)
	}
	// The decision itself must still be fully recorded.
	if rec.events[0].ReasonClass == "" && rec.events[0].Reason == "" {
		t.Error("suppressing the counterfactual must not suppress the decision")
	}
}

func TestEnforceModeDoesNotLabelAnAppliedAllowACounterfactual(t *testing.T) {
	s, _, rec := newServer(ModeEnforce, policy.Decision{Allowed: true})

	if _, err := s.Check(context.Background(),
		checkRequest(spiffeRunner, toolsCallBody, map[string]string{})); err != nil {
		t.Fatalf("Check: %v", err)
	}
	if got := rec.events[0].Counterfactual; got != "" {
		t.Errorf("counterfactual = %q on an applied allow, want empty", got)
	}
}

func TestNoOpModeRecordsTheCounterfactualItDeclinedToApply(t *testing.T) {
	s, _, rec := newServer(ModeNoOp, policy.Decision{Allowed: false, Reason: "no matching rule"})

	if _, err := s.Check(context.Background(),
		checkRequest(spiffeRunner, toolsCallBody, map[string]string{})); err != nil {
		t.Fatalf("Check: %v", err)
	}
	if got := rec.events[0].Counterfactual; got != "DENY" {
		t.Errorf("counterfactual = %q, want DENY — no-op applies nothing", got)
	}
}

// The refusal path builds its event separately, so it needs its own guard.
func TestEnforceModeRefusingATruncatedBodyRecordsNoCounterfactual(t *testing.T) {
	truncating := func() *authv3.CheckRequest {
		r := checkRequest(spiffeRunner, "{}", map[string]string{})
		r.Attributes.Request.Http.Size = 999999
		return r
	}

	enforce, _, rec := newServer(ModeEnforce, policy.Decision{Allowed: true})
	if _, err := enforce.Check(context.Background(), truncating()); err != nil {
		t.Fatalf("Check: %v", err)
	}
	if got := rec.events[0].Counterfactual; got != "" {
		t.Errorf("counterfactual = %q on an applied refusal, want empty", got)
	}
	if rec.events[0].ReasonClass != "body_truncated" {
		t.Errorf("reason_class = %q, want body_truncated", rec.events[0].ReasonClass)
	}

	observe, _, rec2 := newServer(ModeObserve, policy.Decision{Allowed: true})
	if _, err := observe.Check(context.Background(), truncating()); err != nil {
		t.Fatalf("Check: %v", err)
	}
	if got := rec2.events[0].Counterfactual; got != "DENY" {
		t.Errorf("observe counterfactual = %q, want DENY", got)
	}
}

func TestAnUnattestedPeerIsRecordedAtNoAssurance(t *testing.T) {
	s, _, rec := newServer(ModeObserve, policy.Decision{Allowed: true})

	if _, err := s.Check(context.Background(),
		checkRequest("", toolsCallBody, map[string]string{})); err != nil {
		t.Fatalf("Check: %v", err)
	}
	e := rec.events[0]
	if e.Attester != "none" {
		t.Errorf("attester = %q, want none", e.Attester)
	}
	if e.Assurance != AssuranceNone {
		t.Errorf("assurance = %q, want %q", e.Assurance, AssuranceNone)
	}
	if e.WorkloadPrincipal != "" {
		t.Errorf("principal = %q, want empty when nothing attested it", e.WorkloadPrincipal)
	}
}

func TestAnUnrecognisedModeFallsBackToObserveNotEnforce(t *testing.T) {
	// A typo in configuration must not start denying production traffic.
	s := NewServer(Config{Mode: Mode("enfroce"), Engine: &fakeEngine{}})
	if s.Mode() != ModeObserve {
		t.Errorf("mode = %q, want observe as the safe default", s.Mode())
	}
}

func TestAnEmptyModeFallsBackToObserve(t *testing.T) {
	s := NewServer(Config{Engine: &fakeEngine{}})
	if s.Mode() != ModeObserve {
		t.Errorf("mode = %q, want observe", s.Mode())
	}
}

func TestCheckSurvivesWithoutAnAuditEmitter(t *testing.T) {
	s := NewServer(Config{Mode: ModeObserve, Engine: &fakeEngine{}})
	if _, err := s.Check(context.Background(),
		checkRequest(spiffeRunner, toolsCallBody, map[string]string{})); err != nil {
		t.Fatalf("Check with no emitter: %v", err)
	}
}

func TestNoOpModeAllowsEvenWhenPolicyDenies(t *testing.T) {
	s, _, _ := newServer(ModeNoOp, policy.Decision{Allowed: false, Reason: "no rule"})
	resp, err := s.Check(context.Background(),
		checkRequest(spiffeRunner, toolsCallBody, map[string]string{}))
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if resp.GetStatus().GetCode() != int32(codes.OK) {
		t.Errorf("status = %d, want OK in no-op mode", resp.GetStatus().GetCode())
	}
}

func TestCounterfactualNamesTheActionThatWouldHaveBeenTaken(t *testing.T) {
	for _, c := range []struct {
		name string
		in   policy.Decision
		want string
	}{
		{"denied", policy.Decision{Allowed: false}, "DENY"},
		{"held", policy.Decision{Allowed: true, Held: true}, "HOLD"},
		{"scoped", policy.Decision{Allowed: true, Scoped: true}, "SCOPE"},
		{"allowed", policy.Decision{Allowed: true}, "ALLOW"},
		// A decision that both holds and scopes has not happened yet, so the
		// action a reviewer needs to see is the one that blocks.
		{"held and scoped", policy.Decision{Allowed: true, Held: true, Scoped: true}, "HOLD"},
	} {
		if got := Counterfactual(c.in); got != c.want {
			t.Errorf("%s: Counterfactual = %q, want %q", c.name, got, c.want)
		}
	}
}
