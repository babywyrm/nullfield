package policy

import (
	"context"
	"testing"

	v1alpha1 "github.com/babywyrm/nullfield/api/v1alpha1"
	"github.com/babywyrm/nullfield/pkg/identity"
)

func TestRuleEngine_BackwardCompatible(t *testing.T) {
	engine := NewRuleEngine([]v1alpha1.Rule{
		{Action: v1alpha1.ActionAllow, MCPMethod: "tools/call", ToolNames: []string{"safe_tool"}},
		{Action: v1alpha1.ActionDeny, MCPMethod: "tools/call", ToolNames: []string{"*"}},
	})

	d := engine.Evaluate(context.Background(), Request{Method: "tools/call", ToolName: "safe_tool"})
	if !d.Allowed {
		t.Errorf("expected safe_tool allowed, got denied: %s", d.Reason)
	}

	d = engine.Evaluate(context.Background(), Request{Method: "tools/call", ToolName: "bad_tool"})
	if d.Allowed {
		t.Error("expected bad_tool denied, got allowed")
	}
}

func TestRuleEngine_DecisionContextIdentifiesMatchedRule(t *testing.T) {
	engine := NewRuleEngine([]v1alpha1.Rule{
		{ID: "read-jira", Action: v1alpha1.ActionAllow, MCPMethod: "tools/call", ToolNames: []string{"jira.read_issue"}},
		{ID: "default-deny", Action: v1alpha1.ActionDeny, MCPMethod: "tools/call", ToolNames: []string{"*"}},
	})

	d := engine.Evaluate(context.Background(), Request{Method: "tools/call", ToolName: "jira.read_issue"})
	if !d.Allowed {
		t.Fatalf("expected jira.read_issue allowed, got denied: %s", d.Reason)
	}
	if d.RuleIndex != 0 {
		t.Fatalf("RuleIndex = %d, want 0", d.RuleIndex)
	}
	if d.RuleID != "read-jira" {
		t.Fatalf("RuleID = %q, want read-jira", d.RuleID)
	}
	if d.Gate != "policy" {
		t.Fatalf("Gate = %q, want policy", d.Gate)
	}
	if d.ReasonClass != "allowed" {
		t.Fatalf("ReasonClass = %q, want allowed", d.ReasonClass)
	}

	d = engine.Evaluate(context.Background(), Request{Method: "tools/call", ToolName: "jira.delete_issue"})
	if d.Allowed {
		t.Fatal("expected jira.delete_issue denied")
	}
	if d.RuleIndex != 1 {
		t.Fatalf("RuleIndex = %d, want 1", d.RuleIndex)
	}
	if d.RuleID != "default-deny" {
		t.Fatalf("RuleID = %q, want default-deny", d.RuleID)
	}
	if d.ReasonClass != "policy_denied" {
		t.Fatalf("ReasonClass = %q, want policy_denied", d.ReasonClass)
	}
}

func TestRuleEngine_DecisionContextMarksDefaultDeny(t *testing.T) {
	engine := NewRuleEngine([]v1alpha1.Rule{
		{ID: "read-jira", Action: v1alpha1.ActionAllow, MCPMethod: "tools/call", ToolNames: []string{"jira.read_issue"}},
	})

	d := engine.Evaluate(context.Background(), Request{Method: "tools/call", ToolName: "jira.delete_issue"})
	if d.Allowed {
		t.Fatal("expected unmatched tool denied")
	}
	if d.RuleIndex != -1 {
		t.Fatalf("RuleIndex = %d, want -1", d.RuleIndex)
	}
	if d.RuleID != "" {
		t.Fatalf("RuleID = %q, want empty", d.RuleID)
	}
	if d.Gate != "policy" {
		t.Fatalf("Gate = %q, want policy", d.Gate)
	}
	if d.ReasonClass != "default_deny" {
		t.Fatalf("ReasonClass = %q, want default_deny", d.ReasonClass)
	}
}

func TestRuleEngine_WhenIdentityType(t *testing.T) {
	engine := NewRuleEngine([]v1alpha1.Rule{
		{
			Action:    v1alpha1.ActionAllow,
			MCPMethod: "tools/call",
			ToolNames: []string{"write_tool"},
			When:      &v1alpha1.WhenCondition{IdentityType: "human"},
		},
		{
			Action:    v1alpha1.ActionDeny,
			MCPMethod: "tools/call",
			ToolNames: []string{"*"},
			Reason:    "not allowed for this identity type",
		},
	})

	human := &identity.Identity{Subject: "alice", Type: identity.IdentityHuman}
	agent := &identity.Identity{Subject: "bot", Type: identity.IdentityAgent}

	d := engine.Evaluate(context.Background(), Request{Method: "tools/call", ToolName: "write_tool", Identity: human})
	if !d.Allowed {
		t.Errorf("expected human allowed, got: %s", d.Reason)
	}

	d = engine.Evaluate(context.Background(), Request{Method: "tools/call", ToolName: "write_tool", Identity: agent})
	if d.Allowed {
		t.Error("expected agent denied for write_tool")
	}
	if d.Reason != "not allowed for this identity type" {
		t.Errorf("expected custom reason, got: %s", d.Reason)
	}
}

func TestRuleEngine_WhenProvider(t *testing.T) {
	engine := NewRuleEngine([]v1alpha1.Rule{
		{
			Action:    v1alpha1.ActionAllow,
			MCPMethod: "tools/call",
			ToolNames: []string{"internal_tool"},
			When:      &v1alpha1.WhenCondition{Provider: "zitadel"},
		},
		{Action: v1alpha1.ActionDeny, MCPMethod: "tools/call", ToolNames: []string{"*"}},
	})

	zitadelUser := &identity.Identity{Subject: "svc", Provider: "zitadel"}
	oktaUser := &identity.Identity{Subject: "alice", Provider: "okta"}

	d := engine.Evaluate(context.Background(), Request{Method: "tools/call", ToolName: "internal_tool", Identity: zitadelUser})
	if !d.Allowed {
		t.Errorf("expected zitadel user allowed, got: %s", d.Reason)
	}

	d = engine.Evaluate(context.Background(), Request{Method: "tools/call", ToolName: "internal_tool", Identity: oktaUser})
	if d.Allowed {
		t.Error("expected okta user denied for internal_tool with zitadel-only rule")
	}
}

func TestRuleEngine_WhenClaims(t *testing.T) {
	engine := NewRuleEngine([]v1alpha1.Rule{
		{
			Action:    v1alpha1.ActionAllow,
			MCPMethod: "tools/call",
			ToolNames: []string{"admin_tool"},
			When: &v1alpha1.WhenCondition{
				Claims: map[string]any{
					"groups": map[string]any{"contains": "admins"},
				},
			},
		},
		{Action: v1alpha1.ActionDeny, MCPMethod: "tools/call", ToolNames: []string{"*"}},
	})

	admin := &identity.Identity{
		Subject: "alice",
		Claims:  map[string]any{"groups": []any{"admins", "users"}},
	}
	regular := &identity.Identity{
		Subject: "bob",
		Claims:  map[string]any{"groups": []any{"users"}},
	}

	d := engine.Evaluate(context.Background(), Request{Method: "tools/call", ToolName: "admin_tool", Identity: admin})
	if !d.Allowed {
		t.Errorf("expected admin allowed, got: %s", d.Reason)
	}

	d = engine.Evaluate(context.Background(), Request{Method: "tools/call", ToolName: "admin_tool", Identity: regular})
	if d.Allowed {
		t.Error("expected regular user denied for admin_tool")
	}
}

func TestRuleEngine_NoWhenBlockBackwardCompat(t *testing.T) {
	engine := NewRuleEngine([]v1alpha1.Rule{
		{Action: v1alpha1.ActionAllow, MCPMethod: "tools/call", ToolNames: []string{"any_tool"}},
	})

	d := engine.Evaluate(context.Background(), Request{Method: "tools/call", ToolName: "any_tool", Identity: nil})
	if !d.Allowed {
		t.Errorf("expected nil identity to match rule without when block, got: %s", d.Reason)
	}
}

// --- Per-rule identity / delegation guards (2026-04-26 spec) ----------------

func TestActChainDepth(t *testing.T) {
	cases := []struct {
		name   string
		claims map[string]any
		want   int
	}{
		{"no act claim", map[string]any{"sub": "alice"}, 0},
		{"one act", map[string]any{"sub": "agent-a", "act": map[string]any{"sub": "alice"}}, 1},
		{"two acts", map[string]any{
			"sub": "agent-b",
			"act": map[string]any{
				"sub": "agent-a",
				"act": map[string]any{"sub": "alice"},
			},
		}, 2},
		{"act not an object is ignored", map[string]any{"act": "not-an-object"}, 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := actChainDepth(c.claims); got != c.want {
				t.Errorf("depth = %d, want %d", got, c.want)
			}
		})
	}
}

func TestRequireActChain_BlocksMissingAct(t *testing.T) {
	engine := NewRuleEngine([]v1alpha1.Rule{
		{
			Action:    v1alpha1.ActionAllow,
			MCPMethod: "tools/call",
			ToolNames: []string{"t"},
			Identity:  &v1alpha1.RuleIdentityGuard{RequireActChain: true},
		},
		{Action: v1alpha1.ActionDeny, MCPMethod: "tools/call", ToolNames: []string{"*"}},
	})

	// Direct user — no act claim. Guard fails, falls through to DENY.
	direct := &identity.Identity{Subject: "alice", Claims: map[string]any{"sub": "alice"}}
	d := engine.Evaluate(context.Background(), Request{Method: "tools/call", ToolName: "t", Identity: direct})
	if d.Allowed {
		t.Errorf("expected DENY for token without act chain, got ALLOW")
	}

	// Delegated call with one `act` hop — guard passes.
	delegated := &identity.Identity{
		Subject: "agent-a",
		Claims: map[string]any{
			"sub": "agent-a",
			"act": map[string]any{"sub": "alice"},
		},
	}
	d = engine.Evaluate(context.Background(), Request{Method: "tools/call", ToolName: "t", Identity: delegated})
	if !d.Allowed {
		t.Errorf("expected ALLOW for token with act chain, got DENY: %s", d.Reason)
	}
}

func TestAudienceMustNarrow_RejectsWidening(t *testing.T) {
	engine := NewRuleEngine([]v1alpha1.Rule{
		{
			Action:    v1alpha1.ActionAllow,
			MCPMethod: "tools/call",
			ToolNames: []string{"t"},
			Identity:  &v1alpha1.RuleIdentityGuard{AudienceMustNarrow: true},
		},
		{Action: v1alpha1.ActionDeny, MCPMethod: "tools/call", ToolNames: []string{"*"}},
	})

	// Narrowing: parent has {a, b}, child has {a}. Guard passes.
	narrow := &identity.Identity{
		Subject: "agent-a",
		Claims: map[string]any{
			"sub": "agent-a",
			"aud": []any{"a"},
			"act": map[string]any{"sub": "alice", "aud": []any{"a", "b"}},
		},
	}
	d := engine.Evaluate(context.Background(), Request{Method: "tools/call", ToolName: "t", Identity: narrow})
	if !d.Allowed {
		t.Errorf("expected narrowing aud to pass, got DENY: %s", d.Reason)
	}

	// Widening: parent has {a}, child has {a, c}. Guard fails, default DENY fires.
	wide := &identity.Identity{
		Subject: "agent-a",
		Claims: map[string]any{
			"sub": "agent-a",
			"aud": []any{"a", "c"},
			"act": map[string]any{"sub": "alice", "aud": []any{"a"}},
		},
	}
	d = engine.Evaluate(context.Background(), Request{Method: "tools/call", ToolName: "t", Identity: wide})
	if d.Allowed {
		t.Errorf("expected widening aud to be DENIED, got ALLOW")
	}

	// No act chain — narrow-ness is vacuously true, guard passes.
	noAct := &identity.Identity{
		Subject: "alice",
		Claims:  map[string]any{"sub": "alice", "aud": []any{"whatever"}},
	}
	d = engine.Evaluate(context.Background(), Request{Method: "tools/call", ToolName: "t", Identity: noAct})
	if !d.Allowed {
		t.Errorf("expected direct caller (no act) to pass AudienceMustNarrow, got DENY")
	}
}

func TestDelegationMaxDepth_RejectsDeepChains(t *testing.T) {
	engine := NewRuleEngine([]v1alpha1.Rule{
		{
			Action:     v1alpha1.ActionAllow,
			MCPMethod:  "tools/call",
			ToolNames:  []string{"t"},
			Delegation: &v1alpha1.RuleDelegationGuard{MaxDepth: 2},
		},
		{Action: v1alpha1.ActionDeny, MCPMethod: "tools/call", ToolNames: []string{"*"}},
	})

	// Depth 1 — passes.
	d1 := &identity.Identity{Subject: "a", Claims: map[string]any{
		"sub": "a",
		"act": map[string]any{"sub": "alice"},
	}}
	if !engine.Evaluate(context.Background(), Request{Method: "tools/call", ToolName: "t", Identity: d1}).Allowed {
		t.Errorf("depth 1 should pass maxDepth=2")
	}

	// Depth 2 — passes (boundary).
	d2 := &identity.Identity{Subject: "b", Claims: map[string]any{
		"sub": "b",
		"act": map[string]any{"sub": "a", "act": map[string]any{"sub": "alice"}},
	}}
	if !engine.Evaluate(context.Background(), Request{Method: "tools/call", ToolName: "t", Identity: d2}).Allowed {
		t.Errorf("depth 2 should pass maxDepth=2 (<=)")
	}

	// Depth 3 — blocked, default DENY fires.
	d3 := &identity.Identity{Subject: "c", Claims: map[string]any{
		"sub": "c",
		"act": map[string]any{
			"sub": "b",
			"act": map[string]any{"sub": "a", "act": map[string]any{"sub": "alice"}},
		},
	}}
	if engine.Evaluate(context.Background(), Request{Method: "tools/call", ToolName: "t", Identity: d3}).Allowed {
		t.Errorf("depth 3 should be denied by maxDepth=2")
	}
}

func TestGuards_NoGuardsIsPass(t *testing.T) {
	// Back-compat: a rule with no Identity/Delegation guard block behaves
	// exactly as before.
	engine := NewRuleEngine([]v1alpha1.Rule{
		{Action: v1alpha1.ActionAllow, MCPMethod: "tools/call", ToolNames: []string{"t"}},
	})
	d := engine.Evaluate(context.Background(), Request{Method: "tools/call", ToolName: "t"})
	if !d.Allowed {
		t.Errorf("rule with no guards should allow the call, got DENY: %s", d.Reason)
	}
}

func TestGuards_RequireIdentityFiresBeforeGuards(t *testing.T) {
	// If requireIdentity is set and identity is missing, the existing fast
	// path returns DENY — we must not regress that behavior.
	engine := NewRuleEngine([]v1alpha1.Rule{
		{
			Action:          v1alpha1.ActionAllow,
			MCPMethod:       "tools/call",
			ToolNames:       []string{"t"},
			RequireIdentity: true,
			Identity:        &v1alpha1.RuleIdentityGuard{RequireActChain: true},
		},
	})
	d := engine.Evaluate(context.Background(), Request{Method: "tools/call", ToolName: "t", Identity: nil})
	if d.Allowed {
		t.Error("expected DENY when requireIdentity true and identity nil")
	}
}
