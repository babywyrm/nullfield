package audit

import (
	"context"
	"testing"
)

func TestMetricsEmitter_DoesNotPanic(t *testing.T) {
	m := NewMetricsEmitter()
	ctx := context.Background()

	events := []Event{
		{Type: EventToolAllowed, Method: "tools/call", ToolName: "test_tool"},
		{Type: EventToolDenied, Method: "tools/call", ToolName: "bad_tool", Reason: "denied"},
		{Type: EventMCPRequest, Method: "initialize"},
		{Type: EventIdentityFailed, Method: "tools/call"},
		{Type: EventCircuitTripped, Method: "tools/call"},
		{Type: EventAnomalyVelocity, Method: "tools/call", ToolName: "fast_tool"},
	}

	for _, e := range events {
		m.Emit(ctx, e)
	}
}

func TestMultiEmitter_FansOut(t *testing.T) {
	var count int
	fake := &countingEmitter{count: &count}
	multi := NewMultiEmitter(fake, fake)

	multi.Emit(context.Background(), Event{Type: EventToolAllowed})
	if count != 2 {
		t.Errorf("expected 2 emissions, got %d", count)
	}
}

type countingEmitter struct {
	count *int
}

func (c *countingEmitter) Emit(_ context.Context, _ Event) {
	*c.count++
}
