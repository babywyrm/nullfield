package extauthz

import (
	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	typev3 "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	rpcstatus "google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/grpc/codes"

	"github.com/babywyrm/nullfield/pkg/policy"
)

// Mode governs whether a decision is applied or merely recorded.
type Mode string

const (
	// ModeNoOp allows everything and records nothing beyond the request itself.
	ModeNoOp Mode = "no-op"
	// ModeObserve allows everything and records the action it would have taken.
	ModeObserve Mode = "observe"
	// ModeEnforce applies the decision.
	ModeEnforce Mode = "enforce"
)

// Valid reports whether a mode is one this server understands. An unrecognised
// mode must not silently degrade into enforcement.
func (m Mode) Valid() bool {
	switch m {
	case ModeNoOp, ModeObserve, ModeEnforce:
		return true
	default:
		return false
	}
}

// CounterfactualFor names the action enforcement would have taken, but only
// when this mode did not take it.
//
// Enforce applies the decision, so there is nothing counter to fact and the
// field is empty. Reporting one anyway is not merely redundant: an operator
// sizing up a rollout filters on this field to ask which calls a shadow
// deployment *would* have blocked, and enforce-mode events answering that
// query inflate the count with denials that already happened.
func CounterfactualFor(mode Mode, d policy.Decision) string {
	if mode == ModeEnforce {
		return ""
	}
	return Counterfactual(d)
}

// Counterfactual names the action a decision would produce.
//
// HOLD outranks SCOPE because a held call has not happened yet, so the blocking
// action is the one a reviewer needs to see first.
func Counterfactual(d policy.Decision) string {
	switch {
	case !d.Allowed:
		return "DENY"
	case d.Held:
		return "HOLD"
	case d.Scoped:
		return "SCOPE"
	default:
		return "ALLOW"
	}
}

// Respond builds the Envoy response for a decision under a given mode.
//
// Only ModeEnforce can deny. Observe and no-op return OK unconditionally: a
// rollout declared read-only that starts refusing production traffic is the
// worst failure available to us, and it would poison adoption of every later
// phase.
func Respond(mode Mode, d policy.Decision) *authv3.CheckResponse {
	if mode != ModeEnforce || d.Allowed {
		return ok()
	}
	return denied(d.Reason)
}

func ok() *authv3.CheckResponse {
	return &authv3.CheckResponse{
		Status:       &rpcstatus.Status{Code: int32(codes.OK)},
		HttpResponse: &authv3.CheckResponse_OkResponse{OkResponse: &authv3.OkHttpResponse{}},
	}
}

func denied(reason string) *authv3.CheckResponse {
	return &authv3.CheckResponse{
		Status: &rpcstatus.Status{Code: int32(codes.PermissionDenied)},
		HttpResponse: &authv3.CheckResponse_DeniedResponse{
			DeniedResponse: &authv3.DeniedHttpResponse{
				Status: &typev3.HttpStatus{Code: typev3.StatusCode_Forbidden},
				Body:   reason,
			},
		},
	}
}
