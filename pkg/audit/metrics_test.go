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

func TestToolCallMetricLabelsUseStableDecisionContext(t *testing.T) {
	labels := toolCallMetricLabels(Event{
		Type:        EventToolDenied,
		ToolName:    "jira.delete_issue",
		Gate:        "policy",
		Reason:      "mcp-atlassian.delete_page denied for AIFE",
		ReasonClass: "policy_denied",
	})

	if labels.tool != "jira.delete_issue" {
		t.Fatalf("tool label = %q, want jira.delete_issue", labels.tool)
	}
	if labels.action != "denied" {
		t.Fatalf("action label = %q, want denied", labels.action)
	}
	if labels.gate != "policy" {
		t.Fatalf("gate label = %q, want policy", labels.gate)
	}
	if labels.reasonClass != "policy_denied" {
		t.Fatalf("reasonClass label = %q, want policy_denied", labels.reasonClass)
	}
}

func TestToolCallMetricLabelsClassifyKnownReasons(t *testing.T) {
	cases := []struct {
		name string
		in   Event
		want string
	}{
		{
			name: "registry",
			in:   Event{Type: EventToolDenied, ToolName: "unknown", Gate: "registry", Reason: "tool not registered"},
			want: "tool_not_registered",
		},
		{
			name: "budget",
			in:   Event{Type: EventToolDenied, ToolName: "llm.invoke", Gate: "budget", Reason: "budget exhausted: call limit reached"},
			want: "budget_exhausted",
		},
		{
			name: "hold timeout",
			in:   Event{Type: EventToolDenied, ToolName: "deploy.prod", Gate: "hold", Reason: "hold timed out without approval"},
			want: "hold_timeout",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			labels := toolCallMetricLabels(c.in)
			if labels.reasonClass != c.want {
				t.Fatalf("reasonClass = %q, want %q", labels.reasonClass, c.want)
			}
		})
	}
}

func TestToolCallMetricLabelsBoundUnknownToolCardinality(t *testing.T) {
	cases := []struct {
		name string
		in   Event
		want string
	}{
		{
			name: "unregistered tool",
			in:   Event{Type: EventToolDenied, ToolName: "attacker.generated.tool.123", Gate: "registry"},
			want: "unregistered",
		},
		{
			name: "unrouted tool",
			in:   Event{Type: EventToolDenied, ToolName: "attacker.generated.tool.456", Gate: "route"},
			want: "unrouted",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			labels := toolCallMetricLabels(c.in)
			if labels.tool != c.want {
				t.Fatalf("tool label = %q, want %q", labels.tool, c.want)
			}
		})
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

func TestMultiEmitterSetsTimestampBeforeFanout(t *testing.T) {
	recorder := &recordingEmitter{}
	multi := NewMultiEmitter(recorder)

	multi.Emit(context.Background(), Event{Type: EventToolAllowed})

	if recorder.event.Time.IsZero() {
		t.Fatal("expected MultiEmitter to set event timestamp before fanout")
	}
}

type countingEmitter struct {
	count *int
}

func (c *countingEmitter) Emit(_ context.Context, _ Event) {
	*c.count++
}

type recordingEmitter struct {
	event Event
}

func (r *recordingEmitter) Emit(_ context.Context, event Event) {
	r.event = event
}
