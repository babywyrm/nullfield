package policy

import (
	"context"
	"strings"

	v1alpha1 "github.com/babywyrm/nullfield/api/v1alpha1"
)

// RuleEngine evaluates a list of NullfieldPolicy rules in order (first match wins).
type RuleEngine struct {
	rules []v1alpha1.Rule
}

func NewRuleEngine(rules []v1alpha1.Rule) *RuleEngine {
	return &RuleEngine{rules: rules}
}

func (e *RuleEngine) Evaluate(_ context.Context, req Request) Decision {
	for _, rule := range e.rules {
		if !matchesMethod(rule, req) {
			continue
		}
		if !matchesToolName(rule, req) {
			continue
		}
		if rule.RequireIdentity && req.Identity == nil {
			return Decision{Allowed: false, Reason: "identity required but not present"}
		}

		switch rule.Action {
		case v1alpha1.ActionAllow:
			return Decision{Allowed: true}
		case v1alpha1.ActionDeny:
			return Decision{Allowed: false, Reason: "denied by rule for tool: " + req.ToolName}
		}
	}

	// Default deny — if no rule matched, reject.
	return Decision{Allowed: false, Reason: "no matching rule (default deny)"}
}

func matchesMethod(rule v1alpha1.Rule, req Request) bool {
	if rule.MCPMethod == "" {
		return true
	}
	return rule.MCPMethod == req.Method
}

func matchesToolName(rule v1alpha1.Rule, req Request) bool {
	if len(rule.ToolNames) == 0 {
		return true
	}
	for _, name := range rule.ToolNames {
		if name == "*" || strings.EqualFold(name, req.ToolName) {
			return true
		}
	}
	return false
}
