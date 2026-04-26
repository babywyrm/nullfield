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
		// Per-rule identity + delegation guards (2026-04-26 spec).
		// Guards are AND-composed after the match predicates; a failing
		// guard continues the loop so a later, looser rule can still fire.
		if ok, _ := evaluateIdentityGuards(rule, req); !ok {
			continue
		}
		if ok, _ := evaluateDelegationGuards(rule, req); !ok {
			continue
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

// -- Per-rule identity / delegation guards (2026-04-26 spec) -----------------
//
// actChainDepth counts the depth of the RFC 8693 `act` claim chain on an
// identity's claims. No `act` claim → 0. One `act` object → 1. Nested
// `act.act` → 2. And so on.
func actChainDepth(claims map[string]any) int {
	depth := 0
	current := claims
	for {
		act, ok := current["act"].(map[string]any)
		if !ok {
			return depth
		}
		depth++
		current = act
	}
}

// claimAudiences normalizes a claims map's `aud` value into a []string.
// `aud` may be a single string or an array of strings (RFC 7519).
func claimAudiences(claims map[string]any) []string {
	switch v := claims["aud"].(type) {
	case string:
		if v == "" {
			return nil
		}
		return []string{v}
	case []any:
		out := make([]string, 0, len(v))
		for _, item := range v {
			if s, ok := item.(string); ok && s != "" {
				out = append(out, s)
			}
		}
		return out
	case []string:
		return append([]string(nil), v...)
	}
	return nil
}

// audienceIsSubset returns true if every element of child is present in parent.
// Empty child is considered a subset (no audiences to widen).
func audienceIsSubset(child, parent []string) bool {
	parentSet := make(map[string]struct{}, len(parent))
	for _, a := range parent {
		parentSet[a] = struct{}{}
	}
	for _, a := range child {
		if _, ok := parentSet[a]; !ok {
			return false
		}
	}
	return true
}

// evaluateIdentityGuards enforces RuleIdentityGuard on the caller's identity.
// Returns (true, "") when all declared guards pass, or (false, reason) on the
// first failing guard. Absent guard block (nil) always passes.
func evaluateIdentityGuards(rule v1alpha1.Rule, req Request) (bool, string) {
	g := rule.Identity
	if g == nil {
		return true, ""
	}
	if req.Identity == nil || req.Identity.Claims == nil {
		// Guards only make sense against an authenticated identity. If
		// the rule declares guards but the request has no identity,
		// this is a fail-closed fit — the rule does not match, let
		// another rule (probably a default DENY) fire.
		return false, "rule identity guards declared but request has no identity"
	}
	claims := req.Identity.Claims

	if g.RequireActChain {
		if actChainDepth(claims) == 0 {
			return false, "act chain required (RFC 8693) but missing on token"
		}
	}

	if g.AudienceMustNarrow {
		parentAct, ok := claims["act"].(map[string]any)
		if !ok {
			// No parent in the chain — narrowing is vacuously satisfied.
			return true, ""
		}
		childAud := claimAudiences(claims)
		parentAud := claimAudiences(parentAct)
		// If neither token declares audience, treat as pass (operator's
		// identity pipeline should enforce `requireAudience` separately).
		if len(childAud) == 0 && len(parentAud) == 0 {
			return true, ""
		}
		if !audienceIsSubset(childAud, parentAud) {
			return false, "audience widened across delegation (RFC 8707 violation)"
		}
	}

	return true, ""
}

// evaluateDelegationGuards enforces RuleDelegationGuard on the caller's
// act-chain depth. MaxDepth=0 means "no limit" (backward compatible).
func evaluateDelegationGuards(rule v1alpha1.Rule, req Request) (bool, string) {
	g := rule.Delegation
	if g == nil {
		return true, ""
	}
	if g.MaxDepth <= 0 {
		return true, ""
	}
	// Interpret claims-free callers as depth 0 (direct call).
	depth := 0
	if req.Identity != nil && req.Identity.Claims != nil {
		depth = actChainDepth(req.Identity.Claims)
	}
	if depth > g.MaxDepth {
		return false, fmt.Sprintf("act chain depth %d exceeds maxDepth %d", depth, g.MaxDepth)
	}
	return true, ""
}
