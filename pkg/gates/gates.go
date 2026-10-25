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
	"sync"
	"time"

	v1alpha1 "github.com/babywyrm/nullfield/api/v1alpha1"
	"github.com/babywyrm/nullfield/pkg/anomaly"
	"github.com/babywyrm/nullfield/pkg/budget"
	"github.com/babywyrm/nullfield/pkg/circuit"
	"github.com/babywyrm/nullfield/pkg/policy"
	"github.com/babywyrm/nullfield/pkg/registry"
)

// Gate names and reason classes, as they appear on audit events.
const (
	GateRegistry = "registry"
	GateCircuit  = "circuit"
	GateBudget   = "budget"
	GateAnomaly  = "anomaly"
	GateRate     = "rate"

	ReasonToolNotRegistered    = "tool_not_registered"
	ReasonCircuitOpen          = "circuit_open"
	ReasonBudgetExhausted      = "budget_exhausted"
	ReasonBudgetUnattributable = "budget_unattributable"
	ReasonVelocityLimit        = "velocity_limit"
	ReasonRateLimited          = "rate_limited"
	ReasonRateUnattributable   = "rate_unattributable"
)

// Gates holds the checks to run. A nil member skips that check, except Rates:
// a rate limit is written in the policy, so with no counter a call it applies
// to is refused rather than let through uncounted.
type Gates struct {
	Registry *registry.Registry
	Breaker  *circuit.Breaker
	Budgets  *budget.Tracker
	Velocity *anomaly.VelocityTracker
	Rates    *Rates
}

// Rates counts calls over a sliding minute, for maxCallsPerMinute.
//
// ponytail: windows are never swept, so memory grows with distinct
// subject-and-limit pairs. Bounded for workload identities; add a sweep like
// circuit.Breaker's if subjects become per-request.
type Rates struct {
	mu    sync.Mutex
	calls map[string][]time.Time
}

func NewRates() *Rates { return &Rates{calls: map[string][]time.Time{}} }

type rateLimit struct {
	scope string
	max   int
}

// take records a call against every limit, or against none if any is full,
// so a refused call never uses up another limit's allowance.
func (r *Rates) take(subject string, limits []rateLimit) (rateLimit, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := time.Now()
	cutoff := now.Add(-time.Minute)
	for _, l := range limits {
		key := l.scope + "\x00" + subject
		live := r.calls[key][:0]
		for _, t := range r.calls[key] {
			if t.After(cutoff) {
				live = append(live, t)
			}
		}
		r.calls[key] = live
		if len(live) >= l.max {
			return l, false
		}
	}
	for _, l := range limits {
		key := l.scope + "\x00" + subject
		r.calls[key] = append(r.calls[key], now)
	}
	return rateLimit{}, true
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

// Charge runs after policy has allowed a call, against the decision that
// allowed it, and records the call as made. A velocity alert configured only
// to log comes back as warning, for the caller to audit; it does not stop the
// call.
func (g Gates) Charge(c Call, d policy.Decision) (refusal, warning *Refusal) {
	if r := g.chargeRates(c, d); r != nil {
		return r, nil
	}
	if r := g.chargeBudget(c, d.MatchedRule); r != nil {
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

// chargeRates applies maxCallsPerMinute from the rule that allowed the call
// and from the tool's registry entry, counted per subject.
func (g Gates) chargeRates(c Call, d policy.Decision) *Refusal {
	var limits []rateLimit
	if rule := d.MatchedRule; rule != nil && rule.MaxCallsPerMin > 0 {
		key := rule.ID
		if key == "" {
			// ponytail: an index key shifts when a reload inserts a rule above
			// it, resetting that rule's window. Give rules an id to avoid it.
			key = fmt.Sprintf("#%d", d.RuleIndex)
		}
		limits = append(limits, rateLimit{"rule " + key, rule.MaxCallsPerMin})
	}
	if g.Registry != nil && c.Tool != "" {
		if entry, ok := g.Registry.Get(c.Tool); ok && entry.MaxCallsPerMin > 0 {
			limits = append(limits, rateLimit{"tool " + c.Tool, entry.MaxCallsPerMin})
		}
	}
	if len(limits) == 0 {
		return nil
	}
	if c.Subject == "" {
		return &Refusal{Gate: GateRate, ReasonClass: ReasonRateUnattributable,
			Reason: "rate limit cannot be charged: the call has no identity to charge it to"}
	}
	if g.Rates == nil {
		return &Refusal{Gate: GateRate, ReasonClass: ReasonRateLimited,
			Reason: "rate limit configured but not counted"}
	}
	if l, ok := g.Rates.take(c.Subject, limits); !ok {
		return &Refusal{Gate: GateRate, ReasonClass: ReasonRateLimited,
			Reason: fmt.Sprintf("rate limit exceeded: %s allows %d calls/min", l.scope, l.max)}
	}
	return nil
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
