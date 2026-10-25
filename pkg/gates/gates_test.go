package gates

import (
	"testing"
	"time"

	v1alpha1 "github.com/babywyrm/nullfield/api/v1alpha1"
	"github.com/babywyrm/nullfield/pkg/anomaly"
	"github.com/babywyrm/nullfield/pkg/budget"
	"github.com/babywyrm/nullfield/pkg/circuit"
	"github.com/babywyrm/nullfield/pkg/registry"
)

var call = Call{Tool: "deploy", Subject: "alice", Session: "s1"}

func budgeted(perIdentity, perSession int) *v1alpha1.Rule {
	b := &v1alpha1.BudgetConfig{}
	if perIdentity > 0 {
		b.PerIdentity = &v1alpha1.BudgetLimits{MaxCallsPerHour: perIdentity}
	}
	if perSession > 0 {
		b.PerSession = &v1alpha1.BudgetLimits{MaxCallsPerHour: perSession}
	}
	return &v1alpha1.Rule{Action: v1alpha1.ActionAllow, Budget: b}
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
	g.Charge(call, nil)
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
	g.Charge(call, nil)
	r, warning := g.Charge(call, nil)
	wantRefusal(t, r, GateAnomaly, ReasonVelocityLimit)
	if warning != nil {
		t.Errorf("a refusing alert was also reported as a warning: %+v", warning)
	}
}

func TestChargeReportsAVelocityAlertThatOnlyLogs(t *testing.T) {
	g := Gates{Velocity: anomaly.NewVelocityTracker(anomaly.VelocityConfig{Threshold: 1})}
	g.Charge(call, nil)
	r, warning := g.Charge(call, nil)
	if r != nil {
		t.Fatalf("a LOG-action alert refused the call: %+v", r)
	}
	wantRefusal(t, warning, GateAnomaly, ReasonVelocityLimit)
}
