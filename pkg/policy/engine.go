package policy

import (
	"context"

	v1alpha1 "github.com/babywyrm/nullfield/api/v1alpha1"
	"github.com/babywyrm/nullfield/pkg/identity"
)

// Transport classes. These previously existed only as a label stamped onto
// generated policy, which meant no rule could distinguish an MCP call from a
// wire API call reaching the same target.
const (
	TransportMCP            = "A"
	TransportWireAPI        = "B"
	TransportInProcessSDK   = "C"
	TransportSubprocess     = "D"
	TransportModelFunctions = "E"
)

// Request is the input to a policy evaluation.
//
// Transport, Target and Operation are additive. Every existing construction site
// sets none of them, so no rule may read an empty value as meaningful — doing so
// would change the behaviour of code nobody edited.
type Request struct {
	Method    string
	ToolName  string
	Arguments map[string]any
	Identity  *identity.Identity

	// Transport is the class from the taxonomy above.
	Transport string
	// Target is the thing being acted upon: a service host, an API endpoint, a
	// cluster. This is what makes non-MCP traffic expressible at all.
	Target string
	// Operation is the verb in the target's own vocabulary, such as
	// "DELETE /repos/acme/widgets".
	Operation string
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
	Labels      map[string]string
	MatchedRule *v1alpha1.Rule

	// Counterfactual records the action that would have been taken, for observe
	// mode. Empty when the decision was applied rather than shadowed.
	Counterfactual string
}

// Engine evaluates policy rules against an incoming request.
type Engine interface {
	Evaluate(ctx context.Context, req Request) Decision
}
