package anomaly

import (
	"testing"
)

func TestSequenceTracker_NoPatterns(t *testing.T) {
	st := NewSequenceTracker(SequenceConfig{})
	alert := st.Record("s1", "tool_a", "alice")
	if alert != nil {
		t.Fatal("no patterns should produce no alerts")
	}
}

func TestSequenceTracker_SinglePatternMatch(t *testing.T) {
	st := NewSequenceTracker(SequenceConfig{
		Patterns: []SequencePattern{
			{Name: "exfil", Tools: []string{"cred_broker.read_credential", "egress.fetch_url"}},
		},
	})

	alert := st.Record("s1", "cred_broker.read_credential", "alice")
	if alert != nil {
		t.Fatal("partial sequence should not alert")
	}

	alert = st.Record("s1", "egress.fetch_url", "alice")
	if alert == nil {
		t.Fatal("complete sequence should alert")
	}
	if alert.Pattern != "exfil" {
		t.Errorf("expected pattern 'exfil', got %q", alert.Pattern)
	}
}

func TestSequenceTracker_NonContiguousMatch(t *testing.T) {
	st := NewSequenceTracker(SequenceConfig{
		Patterns: []SequencePattern{
			{Name: "exfil", Tools: []string{"read_credential", "fetch_url"}},
		},
	})

	st.Record("s1", "read_credential", "alice")
	st.Record("s1", "some_other_tool", "alice")
	st.Record("s1", "another_tool", "alice")
	alert := st.Record("s1", "fetch_url", "alice")

	if alert == nil {
		t.Fatal("non-contiguous but ordered sequence should match")
	}
}

func TestSequenceTracker_WrongOrder(t *testing.T) {
	st := NewSequenceTracker(SequenceConfig{
		Patterns: []SequencePattern{
			{Name: "exfil", Tools: []string{"read_credential", "fetch_url"}},
		},
	})

	st.Record("s1", "fetch_url", "alice")
	alert := st.Record("s1", "read_credential", "alice")

	if alert != nil {
		t.Fatal("wrong order should not match")
	}
}

func TestSequenceTracker_PerSessionIsolation(t *testing.T) {
	st := NewSequenceTracker(SequenceConfig{
		Patterns: []SequencePattern{
			{Name: "exfil", Tools: []string{"read_cred", "fetch_url"}},
		},
	})

	st.Record("s1", "read_cred", "alice")
	alert := st.Record("s2", "fetch_url", "bob")

	if alert != nil {
		t.Fatal("different sessions should not cross-match")
	}
}

func TestSequenceTracker_DenyAction(t *testing.T) {
	st := NewSequenceTracker(SequenceConfig{
		Patterns: []SequencePattern{
			{Name: "exfil", Tools: []string{"a", "b"}, AlertAction: "DENY"},
		},
	})

	st.Record("s1", "a", "alice")
	alert := st.Record("s1", "b", "alice")

	if alert == nil {
		t.Fatal("expected alert")
	}
	if alert.Action != AlertActionDeny {
		t.Errorf("expected DENY, got %s", alert.Action)
	}
}

func TestSequenceTracker_EmptySession(t *testing.T) {
	st := NewSequenceTracker(SequenceConfig{
		Patterns: []SequencePattern{
			{Name: "test", Tools: []string{"a", "b"}},
		},
	})

	alert := st.Record("", "a", "alice")
	if alert != nil {
		t.Fatal("empty session should skip tracking")
	}
}

func TestSequenceTracker_ThreeToolPattern(t *testing.T) {
	st := NewSequenceTracker(SequenceConfig{
		Patterns: []SequencePattern{
			{Name: "chain", Tools: []string{"auth", "read_cred", "exfil"}},
		},
	})

	st.Record("s1", "auth", "alice")
	st.Record("s1", "read_cred", "alice")
	alert := st.Record("s1", "exfil", "alice")

	if alert == nil {
		t.Fatal("three-tool pattern should match")
	}
}
