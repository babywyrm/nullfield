package policy

import (
	"context"
	"strings"
	"testing"

	v1alpha1 "github.com/babywyrm/nullfield/api/v1alpha1"
	"github.com/babywyrm/nullfield/pkg/identity"
)

func celRules(expr string) *RuleEngine {
	return NewRuleEngine([]v1alpha1.Rule{
		{Action: v1alpha1.ActionAllow, CELExpression: expr},
		{Action: v1alpha1.ActionDeny},
	})
}

func TestACELRuleMatchesOnTargetAndOperation(t *testing.T) {
	e := celRules(`request.target == "api.github.com" && request.operation.startsWith("GET ")`)
	read := Request{Transport: TransportWireAPI, Target: "api.github.com", Operation: "GET /repos/acme/widgets"}
	del := Request{Transport: TransportWireAPI, Target: "api.github.com", Operation: "DELETE /repos/acme/widgets"}

	if d := e.Evaluate(context.Background(), read); !d.Allowed {
		t.Fatalf("read refused: %s", d.Reason)
	}
	if d := e.Evaluate(context.Background(), del); d.Allowed || d.RuleIndex != 1 {
		t.Fatalf("delete should fall through to the deny rule, got %+v", d)
	}
}

func TestACELRuleSeesArgumentsAndIdentity(t *testing.T) {
	e := celRules(`has(request.identity) && "sre" in request.identity.groups && request.arguments.repo.startsWith("acme/")`)
	sre := &identity.Identity{Subject: "run-42", Groups: []string{"sre"}}

	ok := Request{Method: "tools/call", ToolName: "gh.delete", Arguments: map[string]any{"repo": "acme/widgets"}, Identity: sre}
	if d := e.Evaluate(context.Background(), ok); !d.Allowed {
		t.Fatalf("refused: %s", d.Reason)
	}
	other := ok
	other.Arguments = map[string]any{"repo": "evil/widgets"}
	if d := e.Evaluate(context.Background(), other); d.Allowed {
		t.Fatal("a repo outside acme/ was allowed")
	}
	anon := ok
	anon.Identity = nil
	if d := e.Evaluate(context.Background(), anon); d.Allowed {
		t.Fatal("an unauthenticated call was allowed")
	}
}

func TestACELExpressionThatCannotBeEvaluatedRefusesTheCall(t *testing.T) {
	e := NewRuleEngine([]v1alpha1.Rule{
		{Action: v1alpha1.ActionDeny, CELExpression: `request.arguments.repo.startsWith("prod/")`},
		{Action: v1alpha1.ActionAllow},
	})
	d := e.Evaluate(context.Background(), Request{Method: "tools/call", Arguments: map[string]any{}})
	if d.Allowed {
		t.Fatal("an expression error skipped a deny rule and reached the allow")
	}
	if d.ReasonClass != ReasonClassExpressionError || d.RuleIndex != 0 {
		t.Fatalf("got %+v", d)
	}
}

func TestACELExpressionPastItsCostLimitRefusesTheCall(t *testing.T) {
	e := celRules(`request.arguments.xs.all(a, request.arguments.xs.all(b, request.arguments.xs.all(c, a + b + c >= 0)))`)
	xs := make([]any, 500)
	for i := range xs {
		xs[i] = 1
	}
	d := e.Evaluate(context.Background(), Request{Arguments: map[string]any{"xs": xs}})
	if d.Allowed || d.ReasonClass != ReasonClassExpressionError {
		t.Fatalf("got %+v", d)
	}
}

func TestACELExpressionThatDoesNotCompileIsRefusedAtLoad(t *testing.T) {
	for name, expr := range map[string]string{
		"syntax":       `request.target ==`,
		"unknown root": `req.target == "x"`,
		"not a bool":   `request.target`,
	} {
		t.Run(name, func(t *testing.T) {
			err := parse(`  rules:
    - action: ALLOW
      celExpression: '` + expr + `'
`)
			if err == nil || !strings.Contains(err.Error(), "celExpression") {
				t.Fatalf("want a celExpression error, got %v", err)
			}
		})
	}
}

func TestAValidCELExpressionLoads(t *testing.T) {
	if err := parse(`  rules:
    - action: ALLOW
      celExpression: "request.target == 'api.github.com'"
`); err != nil {
		t.Fatal(err)
	}
}
