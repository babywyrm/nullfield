package proxy

import (
	"github.com/babywyrm/nullfield/pkg/audit"
	"github.com/babywyrm/nullfield/pkg/identity"
	"github.com/babywyrm/nullfield/pkg/policy"
)

func eventWithIdentity(event audit.Event, id *identity.Identity) audit.Event {
	if id == nil {
		return event
	}
	if event.Identity == "" {
		event.Identity = id.Subject
	}
	if event.SessionID == "" {
		event.SessionID = id.SessionID
	}
	return event
}

func eventWithDecision(event audit.Event, decision policy.Decision, id *identity.Identity) audit.Event {
	event = eventWithIdentity(event, id)
	if event.Gate == "" {
		event.Gate = decision.Gate
	}
	if event.ReasonClass == "" {
		event.ReasonClass = decision.ReasonClass
	}
	if event.RuleID == "" {
		event.RuleID = decision.RuleID
	}
	if decision.RuleIndex >= 0 && event.RuleIndex == nil {
		ruleIndex := decision.RuleIndex
		event.RuleIndex = &ruleIndex
	}
	if len(decision.Labels) > 0 {
		if event.Labels == nil {
			event.Labels = make(map[string]string, len(decision.Labels))
		}
		for key, value := range decision.Labels {
			if _, exists := event.Labels[key]; !exists {
				event.Labels[key] = value
			}
		}
	}
	return event
}

func holdReasonClass(resolvedBy string) string {
	if resolvedBy == "timeout" {
		return "hold_timeout"
	}
	return "hold_denied"
}
