// Package gates is the sequence of checks every front door runs around a policy
// decision: the tool registry, the session circuit breaker, budgets, and call
// velocity.
//
// It decides and nothing else. Each front door keeps its own presentation —
// JSON-RPC error codes for the proxy and gateway, an Envoy response for
// ext_authz — but none of them may skip a gate the others run, which is what
// happened when each kept its own copy: the mesh path evaluated policy alone.
package gates

import (
	"fmt"

	v1alpha1 "github.com/babywyrm/nullfield/api/v1alpha1"
	"github.com/babywyrm/nullfield/pkg/anomaly"
	"github.com/babywyrm/nullfield/pkg/budget"
	"github.com/babywyrm/nullfield/pkg/circuit"
	"github.com/babywyrm/nullfield/pkg/registry"
)

// Gate names and reason classes, as they appear on audit events.
const (
	GateRegistry = "registry"
	GateCircuit  = "circuit"
	GateBudget   = "budget"
	GateAnomaly  = "anomaly"

	ReasonToolNotRegistered    = "tool_not_registered"
	ReasonCircuitOpen          = "circuit_open"
	ReasonBudgetExhausted      = "budget_exhausted"
	ReasonBudgetUnattributable = "budget_unattributable"
	ReasonVelocityLimit        = "velocity_limit"
)

// Gates holds the checks to run. A nil member skips that check, so the zero
// value admits and charges everything.
type Gates struct {
	Registry *registry.Registry
	Breaker  *circuit.Breaker
	Budgets  *budget.Tracker
	Velocity *anomaly.VelocityTracker
}

// Call is what the gates need to know about a request.
type Call struct {
	// Tool is the MCP tool name, empty for traffic that names none.
	Tool string
	// Subject is who budgets and velocity charge.
	Subject string
	// Session keys the circuit breaker and per-session budgets.
	Session string
}

// Refusal names the gate that stopped a call.
type Refusal struct {
	Gate        string
	ReasonClass string
	Reason      string
}

// Admit runs the checks that precede policy evaluation.
func (g Gates) Admit(c Call) *Refusal {
	// The registry lists MCP tools. A call that names none could never appear
	// in it, so absence there says nothing about the call.
	if g.Registry != nil && c.Tool != "" && !g.Registry.IsRegistered(c.Tool) {
		return &Refusal{Gate: GateRegistry, ReasonClass: ReasonToolNotRegistered,
			Reason: "tool not registered"}
	}
	if g.Breaker != nil && !g.Breaker.Allow(c.Session) {
		return &Refusal{Gate: GateCircuit, ReasonClass: ReasonCircuitOpen,
			Reason: "circuit breaker open — session limit exceeded"}
	}
	return nil
}

// Charge runs after policy has allowed a call, against the rule that allowed
// it, and records the call as made. A velocity alert configured only to log
// comes back as warning, for the caller to audit; it does not stop the call.
func (g Gates) Charge(c Call, rule *v1alpha1.Rule) (refusal, warning *Refusal) {
	if r := g.chargeBudget(c, rule); r != nil {
		return r, nil
	}
	if g.Breaker != nil {
		g.Breaker.Record(c.Session)
	}
	if g.Velocity == nil {
		return nil, nil
	}
	alert := g.Velocity.Record(c.Subject, c.Tool)
	if alert == nil {
		return nil, nil
	}
	r := &Refusal{Gate: GateAnomaly, ReasonClass: ReasonVelocityLimit,
		Reason: fmt.Sprintf("velocity %d/min exceeds threshold %d", alert.CallsPerMin, alert.Threshold)}
	if alert.Action == anomaly.AlertActionDeny {
		return r, nil
	}
	return nil, r
}

func (g Gates) chargeBudget(c Call, rule *v1alpha1.Rule) *Refusal {
	if g.Budgets == nil || rule == nil || rule.Budget == nil {
		return nil
	}
	bc := rule.Budget
	// budget.Tracker skips a limit whose key is empty. Doing the same here would
	// let a caller escape a budget by not presenting what it is keyed on.
	if (bc.PerIdentity != nil && c.Subject == "") || (bc.PerSession != nil && c.Session == "") {
		return &Refusal{Gate: GateBudget, ReasonClass: ReasonBudgetUnattributable,
			Reason: "budget cannot be charged: the call has no identity or session to charge it to"}
	}
	if err := g.Budgets.CheckAndRecord(c.Subject, c.Session, limits(bc.PerIdentity), limits(bc.PerSession)); err != nil {
		return &Refusal{Gate: GateBudget, ReasonClass: ReasonBudgetExhausted,
			Reason: "budget exhausted: " + err.Error()}
	}
	return nil
}

func limits(l *v1alpha1.BudgetLimits) *budget.Limits {
	if l == nil {
		return nil
	}
	return &budget.Limits{
		MaxCallsPerHour: l.MaxCallsPerHour,
		MaxCallsPerDay:  l.MaxCallsPerDay,
		MaxTokensPerDay: l.MaxTokensPerDay,
	}
}
