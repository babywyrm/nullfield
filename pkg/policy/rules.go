package policy

import (
	"context"
	"fmt"
	"strings"

	v1alpha1 "github.com/babywyrm/nullfield/api/v1alpha1"
	"github.com/babywyrm/nullfield/pkg/identity"
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
		if !matchesWhen(rule, req) {
			continue
		}
		if rule.RequireIdentity && req.Identity == nil {
			return Decision{Allowed: false, Reason: "identity required but not present"}
		}

		reason := rule.Reason
		matched := rule
		switch rule.Action {
		case v1alpha1.ActionAllow:
			return Decision{Allowed: true, MatchedRule: &matched}
		case v1alpha1.ActionDeny:
			if reason == "" {
				reason = "denied by rule for tool: " + req.ToolName
			}
			return Decision{Allowed: false, Reason: reason, MatchedRule: &matched}
		case v1alpha1.ActionHold:
			if reason == "" {
				reason = "held for approval: " + req.ToolName
			}
			return Decision{Allowed: false, Held: true, Reason: reason, MatchedRule: &matched}
		case v1alpha1.ActionScope:
			return Decision{Allowed: true, Scoped: true, MatchedRule: &matched}
		}
	}

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

// matchesWhen evaluates the optional when-condition on a rule.
// If the rule has no When block, it matches unconditionally (backward compatible).
// If it has a When block, all specified fields must match (AND logic).
func matchesWhen(rule v1alpha1.Rule, req Request) bool {
	w := rule.When
	if w == nil {
		return true
	}

	if w.IdentityType != "" && w.IdentityType != "any" {
		if req.Identity == nil {
			return false
		}
		if string(req.Identity.Type) != w.IdentityType {
			return false
		}
	}

	if w.Provider != "" {
		if req.Identity == nil {
			return false
		}
		if w.Provider == "unknown" {
			if req.Identity.Provider != "" {
				return false
			}
		} else if !strings.EqualFold(req.Identity.Provider, w.Provider) {
			return false
		}
	}

	if len(w.Claims) > 0 {
		if req.Identity == nil || req.Identity.Claims == nil {
			return false
		}
		if !matchesClaims(w.Claims, req.Identity) {
			return false
		}
	}

	return true
}

func matchesClaims(expected map[string]any, id *identity.Identity) bool {
	for key, condition := range expected {
		switch cond := condition.(type) {
		case map[string]any:
			if containsVal, ok := cond["contains"]; ok {
				if !claimContains(id, key, fmt.Sprint(containsVal)) {
					return false
				}
			}
		case string:
			actual, _ := id.Claims[key].(string)
			if actual != cond {
				return false
			}
		}
	}
	return true
}

func claimContains(id *identity.Identity, key, value string) bool {
	switch v := id.Claims[key].(type) {
	case []any:
		for _, item := range v {
			if fmt.Sprint(item) == value {
				return true
			}
		}
	case []string:
		for _, item := range v {
			if item == value {
				return true
			}
		}
	case string:
		return strings.Contains(v, value)
	}
	return false
}
