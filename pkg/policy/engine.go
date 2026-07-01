package policy

import (
	"context"

	v1alpha1 "github.com/babywyrm/nullfield/api/v1alpha1"
	"github.com/babywyrm/nullfield/pkg/identity"
)

// Request is the input to a policy evaluation.
type Request struct {
	Method    string
	ToolName  string
	Arguments map[string]any
	Identity  *identity.Identity
}

// Decision is the output of a policy evaluation.
type Decision struct {
	Allowed     bool
	Held        bool
	Scoped      bool
	Reason      string
	Gate        string
	ReasonClass string
	RuleIndex   int
	RuleID      string
	MatchedRule *v1alpha1.Rule
}

// Engine evaluates policy rules against an incoming request.
type Engine interface {
	Evaluate(ctx context.Context, req Request) Decision
}
