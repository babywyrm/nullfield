package controller

import (
	"fmt"
	"testing"
	"time"
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
