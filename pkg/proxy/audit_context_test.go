package proxy

import (
	"testing"

	"github.com/babywyrm/nullfield/pkg/audit"
	"github.com/babywyrm/nullfield/pkg/policy"
)

func TestHoldReasonClassDistinguishesTimeout(t *testing.T) {
	if got := holdReasonClass("timeout"); got != "hold_timeout" {
		t.Fatalf("holdReasonClass(timeout) = %q, want hold_timeout", got)
	}
	if got := holdReasonClass("ops-alice"); got != "hold_denied" {
		t.Fatalf("holdReasonClass(ops-alice) = %q, want hold_denied", got)
	}
}

func TestEventWithDecisionAddsAuditLabels(t *testing.T) {
	event := eventWithDecision(audit.Event{
		Type:   audit.EventToolAllowed,
		Labels: map[string]string{"callsite": "wins"},
	}, policy.Decision{
		Gate:        "policy",
		ReasonClass: "allowed",
		Labels: map[string]string{
			"system":   "jira",
			"callsite": "rule-value",
		},
	}, nil)

	if event.Labels["system"] != "jira" {
		t.Fatalf("system label = %q, want jira", event.Labels["system"])
	}
	if event.Labels["callsite"] != "wins" {
		t.Fatalf("callsite label = %q, want existing value to win", event.Labels["callsite"])
	}
}
