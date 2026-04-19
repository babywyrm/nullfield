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
