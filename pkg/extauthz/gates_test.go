package extauthz

import (
	"context"
	"testing"

	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"google.golang.org/grpc/codes"

	v1alpha1 "github.com/babywyrm/nullfield/api/v1alpha1"
	"github.com/babywyrm/nullfield/pkg/anomaly"
	"github.com/babywyrm/nullfield/pkg/audit"
	"github.com/babywyrm/nullfield/pkg/budget"
	"github.com/babywyrm/nullfield/pkg/gates"
	"github.com/babywyrm/nullfield/pkg/policy"
	"github.com/babywyrm/nullfield/pkg/registry"
)

func budgetedEngine(perHour int) policy.Engine {
	return policy.NewRuleEngine([]v1alpha1.Rule{{
		Action:    v1alpha1.ActionAllow,
		ToolNames: []string{"secrets.leak_config"},
		Budget: &v1alpha1.BudgetConfig{
			PerIdentity: &v1alpha1.BudgetLimits{MaxCallsPerHour: perHour},
		},
	}})
}

func status(t *testing.T, s *Server, req *authv3.CheckRequest) codes.Code {
	t.Helper()
	resp, err := s.Check(context.Background(), req)
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	return codes.Code(resp.GetStatus().GetCode())
}

func TestABudgetedRuleRefusesTheCallPastItsLimit(t *testing.T) {
	// The proxy has always enforced this. The mesh path evaluated policy alone,
	// so the same policy allowed every call that arrived through a waypoint.
	rec := &recorder{}
	s := NewServer(Config{
		Mode: ModeEnforce, Engine: budgetedEngine(2), Audit: rec,
		Gates: gates.Gates{Budgets: budget.New()},
	})
	req := func() *authv3.CheckRequest { return checkRequest(spiffeRunner, toolsCallBody, nil) }

	for i := 1; i <= 2; i++ {
		if got := status(t, s, req()); got != codes.OK {
			t.Fatalf("call %d within budget: status %v, want OK", i, got)
		}
	}
	if got := status(t, s, req()); got != codes.PermissionDenied {
		t.Fatalf("call past budget: status %v, want PermissionDenied", got)
	}
	last := rec.events[len(rec.events)-1]
	if last.Gate != gates.GateBudget || last.ReasonClass != gates.ReasonBudgetExhausted {
		t.Errorf("refusal recorded as gate=%q class=%q, want %q/%q",
			last.Gate, last.ReasonClass, gates.GateBudget, gates.ReasonBudgetExhausted)
	}
}

func TestARulesMaxCallsPerMinuteRefusesTheWorkloadPastIt(t *testing.T) {
	rec := &recorder{}
	s := NewServer(Config{
		Mode: ModeEnforce, Audit: rec,
		Engine: policy.NewRuleEngine([]v1alpha1.Rule{{
			Action: v1alpha1.ActionAllow, ToolNames: []string{"secrets.leak_config"}, MaxCallsPerMin: 1,
		}}),
		Gates: gates.Gates{Rates: gates.NewRates()},
	})
	if got := status(t, s, checkRequest(spiffeRunner, toolsCallBody, nil)); got != codes.OK {
		t.Fatalf("first call: %v, want OK", got)
	}
	if got := status(t, s, checkRequest(spiffeRunner, toolsCallBody, nil)); got != codes.PermissionDenied {
		t.Fatalf("second call in the minute: %v, want PermissionDenied", got)
	}
	if last := rec.events[len(rec.events)-1]; last.Gate != gates.GateRate {
		t.Errorf("refusal recorded as gate=%q, want %q", last.Gate, gates.GateRate)
	}
}

func TestObserveModeChargesBudgetsSoItsCounterfactualIsTrue(t *testing.T) {
	// A shadow deployment that never charged would report every call as
	// allowed, and the rollout it was meant to inform would break on day one.
	rec := &recorder{}
	s := NewServer(Config{
		Mode: ModeObserve, Engine: budgetedEngine(1), Audit: rec,
		Gates: gates.Gates{Budgets: budget.New()},
	})
	req := func() *authv3.CheckRequest { return checkRequest(spiffeRunner, toolsCallBody, nil) }

	status(t, s, req())
	if got := status(t, s, req()); got != codes.OK {
		t.Fatalf("observe mode returned %v, want OK", got)
	}
	if last := rec.events[len(rec.events)-1]; last.Counterfactual != "DENY" || last.Gate != gates.GateBudget {
		t.Errorf("second call recorded counterfactual=%q gate=%q, want DENY from the budget",
			last.Counterfactual, last.Gate)
	}
}

func TestAnUnattestedCallerCannotBeChargedSoABudgetedRuleRefusesIt(t *testing.T) {
	// No attested principal means no subject to charge. Skipping the budget
	// would hand an unlimited allowance to whoever can avoid attestation.
	rec := &recorder{}
	s := NewServer(Config{
		Mode: ModeEnforce, Engine: budgetedEngine(100), Audit: rec,
		Gates: gates.Gates{Budgets: budget.New()},
	})

	if got := status(t, s, checkRequest("", toolsCallBody, nil)); got != codes.PermissionDenied {
		t.Fatalf("unattested caller on a budgeted rule: status %v, want PermissionDenied", got)
	}
	if last := rec.events[len(rec.events)-1]; last.ReasonClass != gates.ReasonBudgetUnattributable {
		t.Errorf("reason class = %q, want %q", last.ReasonClass, gates.ReasonBudgetUnattributable)
	}
}

func TestAVelocityAlertThatOnlyLogsIsAuditedOnTheMeshPath(t *testing.T) {
	// A LOG-action alert exists to be read. Dropping it leaves an operator who
	// configured velocity detection with nothing to look at.
	rec := &recorder{}
	s := NewServer(Config{
		Mode:   ModeEnforce,
		Engine: policy.NewRuleEngine([]v1alpha1.Rule{{Action: v1alpha1.ActionAllow}}),
		Audit:  rec,
		Gates: gates.Gates{Velocity: anomaly.NewVelocityTracker(
			anomaly.VelocityConfig{Threshold: 1})},
	})

	status(t, s, checkRequest(spiffeRunner, toolsCallBody, nil))
	if got := status(t, s, checkRequest(spiffeRunner, toolsCallBody, nil)); got != codes.OK {
		t.Fatalf("log-only alert refused the call: %v", got)
	}
	for _, e := range rec.events {
		if e.Type == audit.EventAnomalyVelocity {
			if e.WorkloadPrincipal != spiffeRunner {
				t.Errorf("alert attributed to %q, want %q", e.WorkloadPrincipal, spiffeRunner)
			}
			return
		}
	}
	t.Fatal("no anomaly.velocity event emitted for the alert")
}

func TestTheMeshPathRefusesAnUnregisteredTool(t *testing.T) {
	reg := registry.New()
	s := NewServer(Config{
		Mode:   ModeEnforce,
		Engine: policy.NewRuleEngine([]v1alpha1.Rule{{Action: v1alpha1.ActionAllow}}),
		Audit:  &recorder{},
		Gates:  gates.Gates{Registry: reg},
	})

	if got := status(t, s, checkRequest(spiffeRunner, toolsCallBody, nil)); got != codes.PermissionDenied {
		t.Fatalf("unregistered tool: status %v, want PermissionDenied", got)
	}
}

func TestTheRegistryDoesNotApplyToTrafficThatNamesNoTool(t *testing.T) {
	// The registry is a list of MCP tools. A REST call names none, and refusing
	// it for being absent from a list it could never appear in would make the
	// mesh path unusable for anything but MCP.
	s := NewServer(Config{
		Mode:   ModeEnforce,
		Engine: policy.NewRuleEngine([]v1alpha1.Rule{{Action: v1alpha1.ActionAllow}}),
		Audit:  &recorder{},
		Gates:  gates.Gates{Registry: registry.New()},
	})
	req := checkRequest(spiffeRunner, "", nil)
	req.Attributes.Request.Http.Method = "DELETE"
	req.Attributes.Request.Http.Path = "/repos/acme/widgets"
	req.Attributes.Request.Http.Host = "api.github.com"

	if got := status(t, s, req); got != codes.OK {
		t.Fatalf("REST call with an allow-all policy: status %v, want OK", got)
	}
}

func TestACELRuleDecidesOnTheWireTargetAndOperation(t *testing.T) {
	s := NewServer(Config{
		Mode: ModeEnforce, Audit: &recorder{},
		Engine: policy.NewRuleEngine([]v1alpha1.Rule{
			{Action: v1alpha1.ActionAllow, CELExpression: `request.transport == "B" && request.target == "api.github.com" && request.operation.startsWith("GET ")`},
			{Action: v1alpha1.ActionDeny},
		}),
	})
	wire := func(method string) *authv3.CheckRequest {
		r := checkRequest(spiffeRunner, "", nil)
		h := r.Attributes.Request.Http
		h.Method, h.Path, h.Host = method, "/repos/acme/widgets", "api.github.com"
		return r
	}
	if got := status(t, s, wire("GET")); got != codes.OK {
		t.Fatalf("GET: %v, want OK", got)
	}
	if got := status(t, s, wire("DELETE")); got != codes.PermissionDenied {
		t.Fatalf("DELETE: %v, want PermissionDenied", got)
	}
}
