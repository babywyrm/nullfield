package gates

import (
	"testing"
	"time"

	v1alpha1 "github.com/babywyrm/nullfield/api/v1alpha1"
	"github.com/babywyrm/nullfield/pkg/anomaly"
	"github.com/babywyrm/nullfield/pkg/budget"
	"github.com/babywyrm/nullfield/pkg/circuit"
	"github.com/babywyrm/nullfield/pkg/policy"
	"github.com/babywyrm/nullfield/pkg/registry"
)

var call = Call{Tool: "deploy", Subject: "alice", Session: "s1"}

func budgeted(perIdentity, perSession int) policy.Decision {
	b := &v1alpha1.BudgetConfig{}
	if perIdentity > 0 {
		b.PerIdentity = &v1alpha1.BudgetLimits{MaxCallsPerHour: perIdentity}
	}
	if perSession > 0 {
		b.PerSession = &v1alpha1.BudgetLimits{MaxCallsPerHour: perSession}
	}
	return allowedBy(0, &v1alpha1.Rule{Action: v1alpha1.ActionAllow, Budget: b})
}

func allowedBy(index int, rule *v1alpha1.Rule) policy.Decision {
	return policy.Decision{Allowed: true, RuleIndex: index, RuleID: rule.ID, MatchedRule: rule}
}

func perMinute(index, max int) policy.Decision {
	return allowedBy(index, &v1alpha1.Rule{Action: v1alpha1.ActionAllow, MaxCallsPerMin: max})
}

func wantRefusal(t *testing.T, r *Refusal, gate, class string) {
	t.Helper()
	if r == nil {
		t.Fatalf("admitted, want refusal by %s/%s", gate, class)
	}
	if r.Gate != gate || r.ReasonClass != class {
		t.Fatalf("refused by %s/%s, want %s/%s", r.Gate, r.ReasonClass, gate, class)
	}
}

func TestNoGatesConfiguredAdmitsAndChargesEverything(t *testing.T) {
	var g Gates
	if r := g.Admit(call); r != nil {
		t.Fatalf("Admit with no gates refused: %+v", r)
	}
	if r, _ := g.Charge(call, budgeted(1, 1)); r != nil {
		t.Fatalf("Charge with no budget tracker refused: %+v", r)
	}
}

func TestAdmitRefusesAToolTheRegistryDoesNotList(t *testing.T) {
	g := Gates{Registry: registry.New()}
	wantRefusal(t, g.Admit(call), GateRegistry, ReasonToolNotRegistered)
}

func TestAdmitAcceptsARegisteredTool(t *testing.T) {
	reg := registry.New()
	reg.Register(v1alpha1.ToolRegistryEntry{Name: "deploy"})
	if r := (Gates{Registry: reg}).Admit(call); r != nil {
		t.Fatalf("registered tool refused: %+v", r)
	}
}

func TestAdmitIgnoresTheRegistryForACallThatNamesNoTool(t *testing.T) {
	g := Gates{Registry: registry.New()}
	if r := g.Admit(Call{Subject: "alice"}); r != nil {
		t.Fatalf("toolless call refused by the registry: %+v", r)
	}
}

func TestChargeCountsTowardTheSessionCircuitSoAdmitLaterRefuses(t *testing.T) {
	g := Gates{Breaker: circuit.New(1, time.Hour)}
	if r := g.Admit(call); r != nil {
		t.Fatalf("first call refused: %+v", r)
	}
	g.Charge(call, policy.Decision{})
	wantRefusal(t, g.Admit(call), GateCircuit, ReasonCircuitOpen)
}

func TestChargeRefusesPastAPerIdentityBudget(t *testing.T) {
	g := Gates{Budgets: budget.New()}
	if r, _ := g.Charge(call, budgeted(1, 0)); r != nil {
		t.Fatalf("first call refused: %+v", r)
	}
	r, _ := g.Charge(call, budgeted(1, 0))
	wantRefusal(t, r, GateBudget, ReasonBudgetExhausted)
}

func TestChargeRefusesAPerIdentityBudgetWithNoSubjectToCharge(t *testing.T) {
	g := Gates{Budgets: budget.New()}
	r, _ := g.Charge(Call{Tool: "deploy", Session: "s1"}, budgeted(100, 0))
	wantRefusal(t, r, GateBudget, ReasonBudgetUnattributable)
}

func TestChargeRefusesAPerSessionBudgetWithNoSessionToCharge(t *testing.T) {
	// The proxy used to skip per-session budgets for a client that omitted
	// Mcp-Session-Id, so leaving the header off bought an unlimited session.
	g := Gates{Budgets: budget.New()}
	r, _ := g.Charge(Call{Tool: "deploy", Subject: "alice"}, budgeted(0, 100))
	wantRefusal(t, r, GateBudget, ReasonBudgetUnattributable)
}

func TestARefusedBudgetDoesNotCountTowardTheCircuit(t *testing.T) {
	// The proxy records breaker usage only for calls it forwards.
	g := Gates{Budgets: budget.New(), Breaker: circuit.New(1, time.Hour)}
	g.Charge(Call{Tool: "deploy", Session: "s1"}, budgeted(1, 0))
	if r := g.Admit(call); r != nil {
		t.Fatalf("a call refused by its budget still consumed the session circuit: %+v", r)
	}
}

func TestChargeRefusesOnAVelocityAlertWhoseActionIsDeny(t *testing.T) {
	g := Gates{Velocity: anomaly.NewVelocityTracker(anomaly.VelocityConfig{
		Threshold: 1, AlertAction: anomaly.AlertActionDeny,
	})}
	g.Charge(call, policy.Decision{})
	r, warning := g.Charge(call, policy.Decision{})
	wantRefusal(t, r, GateAnomaly, ReasonVelocityLimit)
	if warning != nil {
		t.Errorf("a refusing alert was also reported as a warning: %+v", warning)
	}
}

func TestChargeReportsAVelocityAlertThatOnlyLogs(t *testing.T) {
	g := Gates{Velocity: anomaly.NewVelocityTracker(anomaly.VelocityConfig{Threshold: 1})}
	g.Charge(call, policy.Decision{})
	r, warning := g.Charge(call, policy.Decision{})
	if r != nil {
		t.Fatalf("a LOG-action alert refused the call: %+v", r)
	}
	wantRefusal(t, warning, GateAnomaly, ReasonVelocityLimit)
}

// charge makes n calls and returns the refusal of the last one.
func charge(t *testing.T, g Gates, c Call, d policy.Decision, n int) *Refusal {
	t.Helper()
	var r *Refusal
	for i := 0; i < n; i++ {
		if i > 0 && r != nil {
			t.Fatalf("call %d of %d refused early: %+v", i, n, r)
		}
		r, _ = g.Charge(c, d)
	}
	return r
}

func TestARulesMaxCallsPerMinuteRefusesTheCallPastIt(t *testing.T) {
	g := Gates{Rates: NewRates()}
	wantRefusal(t, charge(t, g, call, perMinute(0, 2), 3), GateRate, ReasonRateLimited)
}

func TestARulesRateIsCountedPerSubject(t *testing.T) {
	g := Gates{Rates: NewRates()}
	g.Charge(call, perMinute(0, 1))
	if r, _ := g.Charge(Call{Tool: "deploy", Subject: "bob"}, perMinute(0, 1)); r != nil {
		t.Fatalf("bob was refused for alice's call: %+v", r)
	}
}

func TestARulesRateIsCountedPerRule(t *testing.T) {
	g := Gates{Rates: NewRates()}
	g.Charge(call, perMinute(0, 1))
	if r, _ := g.Charge(call, perMinute(1, 1)); r != nil {
		t.Fatalf("a call allowed by another rule was refused: %+v", r)
	}
}

func TestARegisteredToolsMaxCallsPerMinuteRefusesTheCallPastIt(t *testing.T) {
	reg := registry.New()
	reg.Register(v1alpha1.ToolRegistryEntry{Name: "deploy", MaxCallsPerMin: 1})
	g := Gates{Registry: reg, Rates: NewRates()}
	d := allowedBy(0, &v1alpha1.Rule{Action: v1alpha1.ActionAllow})
	wantRefusal(t, charge(t, g, call, d, 2), GateRate, ReasonRateLimited)
}

func TestACallRefusedByOneRateDoesNotCountTowardTheOther(t *testing.T) {
	reg := registry.New()
	reg.Register(v1alpha1.ToolRegistryEntry{Name: "deploy", MaxCallsPerMin: 1})
	g := Gates{Registry: reg, Rates: NewRates()}
	g.Charge(call, perMinute(0, 2))
	g.Charge(call, perMinute(0, 2)) // refused by the tool's limit
	// The rule allows two; only one was made.
	if r, _ := g.Charge(Call{Tool: "other", Subject: "alice"}, perMinute(0, 2)); r != nil {
		t.Fatalf("a call the tool limit refused was counted against the rule: %+v", r)
	}
}

func TestARateLimitWithNoSubjectToChargeRefuses(t *testing.T) {
	g := Gates{Rates: NewRates()}
	r, _ := g.Charge(Call{Tool: "deploy"}, perMinute(0, 100))
	wantRefusal(t, r, GateRate, ReasonRateUnattributable)
}

func TestARateLimitWithNoCounterRefuses(t *testing.T) {
	// The limit is in the policy. A front door that forgot to build the
	// counter must not turn it back into decoration.
	r, _ := Gates{}.Charge(call, perMinute(0, 100))
	wantRefusal(t, r, GateRate, ReasonRateLimited)
}

func TestARateRefusedCallIsNotChargedToItsBudget(t *testing.T) {
	g := Gates{Rates: NewRates(), Budgets: budget.New()}
	d := budgeted(2, 0)
	d.MatchedRule.MaxCallsPerMin = 1
	g.Charge(call, d)
	g.Charge(call, d) // refused by the rate
	d.MatchedRule.MaxCallsPerMin = 0
	if r, _ := g.Charge(call, d); r != nil {
		t.Fatalf("the rate-refused call consumed the budget: %+v", r)
	}
}
