package controller

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"testing"
	"time"

	pb "github.com/babywyrm/nullfield/api/v1alpha1/controllerpb"
)

func TestEventBuffer_AddAndList(t *testing.T) {
	buf := NewEventBuffer(100)

	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	for i := 0; i < 5; i++ {
		buf.Add(AuditEvent{
			EventType: "call",
			Tool:      fmt.Sprintf("tool-%d", i),
			Timestamp: base.Add(time.Duration(i) * time.Second),
		})
	}

	events := buf.List("", 0)
	if len(events) != 5 {
		t.Fatalf("expected 5 events, got %d", len(events))
	}

	if events[0].Tool != "tool-4" {
		t.Fatalf("expected newest first (tool-4), got %s", events[0].Tool)
	}
	if events[4].Tool != "tool-0" {
		t.Fatalf("expected oldest last (tool-0), got %s", events[4].Tool)
	}
}

func TestEventBuffer_RingBufferOverflow(t *testing.T) {
	buf := NewEventBuffer(3)

	for i := 0; i < 5; i++ {
		buf.Add(AuditEvent{
			EventType: "call",
			Tool:      fmt.Sprintf("tool-%d", i),
			Timestamp: time.Now().Add(time.Duration(i) * time.Millisecond),
		})
	}

	if buf.Count() != 3 {
		t.Fatalf("expected count=3 (capped at buffer size), got %d", buf.Count())
	}

	events := buf.List("", 0)
	if len(events) != 3 {
		t.Fatalf("expected 3 events, got %d", len(events))
	}

	if events[0].Tool != "tool-4" {
		t.Fatalf("expected newest tool-4, got %s", events[0].Tool)
	}
	if events[2].Tool != "tool-2" {
		t.Fatalf("expected oldest retained tool-2, got %s", events[2].Tool)
	}
}

func TestEventBuffer_FilterByType(t *testing.T) {
	buf := NewEventBuffer(100)

	buf.Add(AuditEvent{EventType: "call", Tool: "a", Timestamp: time.Now()})
	buf.Add(AuditEvent{EventType: "hold", Tool: "b", Timestamp: time.Now()})
	buf.Add(AuditEvent{EventType: "call", Tool: "c", Timestamp: time.Now()})
	buf.Add(AuditEvent{EventType: "deny", Tool: "d", Timestamp: time.Now()})

	calls := buf.List("call", 0)
	if len(calls) != 2 {
		t.Fatalf("expected 2 'call' events, got %d", len(calls))
	}
	for _, e := range calls {
		if e.EventType != "call" {
			t.Fatalf("expected eventType=call, got %s", e.EventType)
		}
	}

	holds := buf.List("hold", 0)
	if len(holds) != 1 {
		t.Fatalf("expected 1 'hold' event, got %d", len(holds))
	}
}

func TestEventBuffer_Count(t *testing.T) {
	buf := NewEventBuffer(100)

	if buf.Count() != 0 {
		t.Fatalf("expected count=0 initially, got %d", buf.Count())
	}

	for i := 0; i < 7; i++ {
		buf.Add(AuditEvent{EventType: "test", Timestamp: time.Now()})
	}

	if buf.Count() != 7 {
		t.Fatalf("expected count=7, got %d", buf.Count())
	}
}

func TestServerReportEventStoresDecisionContext(t *testing.T) {
	ruleIndex := int32(2)
	server := &Server{
		Events:  NewEventBuffer(10),
		Alerter: NewAlerter("", slog.New(slog.NewTextHandler(io.Discard, nil))),
	}

	_, err := server.ReportEvent(context.Background(), &pb.ReportEventRequest{
		EventType:   "tool.denied",
		Method:      "tools/call",
		Tool:        "jira.delete_issue",
		Identity:    "astra",
		SessionId:   "session-123",
		Reason:      "not an approved path",
		Target:      "prod/astra",
		Gate:        "policy",
		ReasonClass: "policy_denied",
		RuleIndex:   &ruleIndex,
		RuleId:      "deny-delete",
		PolicyRef:   "astra-jira",
		RegistryRef: "jira-tools",
		Route:       "atlassian",
		Labels:      map[string]string{"lane": "delegated", "resource": "jira"},
	})
	if err != nil {
		t.Fatalf("ReportEvent returned error: %v", err)
	}

	events := server.Events.List("", 0)
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	event := events[0]
	if event.Gate != "policy" {
		t.Fatalf("Gate = %q, want policy", event.Gate)
	}
	if event.ReasonClass != "policy_denied" {
		t.Fatalf("ReasonClass = %q, want policy_denied", event.ReasonClass)
	}
	if event.RuleIndex == nil || *event.RuleIndex != 2 {
		t.Fatalf("RuleIndex = %v, want 2", event.RuleIndex)
	}
	if event.RuleID != "deny-delete" {
		t.Fatalf("RuleID = %q, want deny-delete", event.RuleID)
	}
	if event.Labels["lane"] != "delegated" {
		t.Fatalf("Labels[lane] = %q, want delegated", event.Labels["lane"])
	}
}
