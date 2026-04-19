package budget

import (
	"testing"
	"time"
)

func TestTracker_WithinLimits(t *testing.T) {
	tr := New()
	limits := &Limits{MaxCallsPerHour: 10}

	for i := 0; i < 10; i++ {
		if err := tr.CheckAndRecord("alice", "s1", limits, nil); err != nil {
			t.Fatalf("call %d should be within limits: %v", i+1, err)
		}
	}
}

func TestTracker_HourlyLimitExceeded(t *testing.T) {
	tr := New()
	limits := &Limits{MaxCallsPerHour: 3}

	for i := 0; i < 3; i++ {
		tr.CheckAndRecord("alice", "", limits, nil)
	}

	err := tr.CheckAndRecord("alice", "", limits, nil)
	if err == nil {
		t.Fatal("expected hourly limit error")
	}
}

func TestTracker_DailyLimitExceeded(t *testing.T) {
	tr := New()
	limits := &Limits{MaxCallsPerDay: 2}

	tr.CheckAndRecord("bob", "", limits, nil)
	tr.CheckAndRecord("bob", "", limits, nil)

	err := tr.CheckAndRecord("bob", "", limits, nil)
	if err == nil {
		t.Fatal("expected daily limit error")
	}
}

func TestTracker_TokenLimit(t *testing.T) {
	tr := New()
	limits := &Limits{MaxTokensPerDay: 100}

	tr.CheckAndRecord("alice", "", limits, nil)
	tr.RecordTokens("alice", "", 80)

	if err := tr.CheckAndRecord("alice", "", limits, nil); err != nil {
		t.Fatalf("should still be within token limit: %v", err)
	}

	tr.RecordTokens("alice", "", 25)

	err := tr.CheckAndRecord("alice", "", limits, nil)
	if err == nil {
		t.Fatal("expected token limit error after 105 tokens")
	}
}

func TestTracker_PerSessionIsolation(t *testing.T) {
	tr := New()
	idLimits := &Limits{MaxCallsPerHour: 100}
	sessLimits := &Limits{MaxCallsPerHour: 2}

	tr.CheckAndRecord("alice", "s1", idLimits, sessLimits)
	tr.CheckAndRecord("alice", "s1", idLimits, sessLimits)

	err := tr.CheckAndRecord("alice", "s1", idLimits, sessLimits)
	if err == nil {
		t.Fatal("expected session limit error")
	}

	if err := tr.CheckAndRecord("alice", "s2", idLimits, sessLimits); err != nil {
		t.Fatalf("different session should be OK: %v", err)
	}
}

func TestTracker_PerIdentityIsolation(t *testing.T) {
	tr := New()
	limits := &Limits{MaxCallsPerHour: 2}

	tr.CheckAndRecord("alice", "", limits, nil)
	tr.CheckAndRecord("alice", "", limits, nil)

	if err := tr.CheckAndRecord("bob", "", limits, nil); err != nil {
		t.Fatalf("bob should not be affected by alice: %v", err)
	}
}

func TestTracker_GetUsage(t *testing.T) {
	tr := New()
	limits := &Limits{MaxCallsPerHour: 100, MaxTokensPerDay: 10000}

	tr.CheckAndRecord("alice", "", limits, nil)
	tr.CheckAndRecord("alice", "", limits, nil)
	tr.RecordTokens("alice", "", 42)

	h, d, tok := tr.GetUsage("alice")
	if h != 2 || d != 2 || tok != 42 {
		t.Errorf("expected 2/2/42, got %d/%d/%d", h, d, tok)
	}
}

func TestTracker_Sweep(t *testing.T) {
	tr := New()
	limits := &Limits{MaxCallsPerHour: 100}
	tr.CheckAndRecord("alice", "", limits, nil)

	_ = time.Now()
	tr.Sweep()

	h, _, _ := tr.GetUsage("alice")
	if h != 1 {
		t.Errorf("recent record should not be swept, got %d hourly calls", h)
	}
}

func TestTracker_NilLimits(t *testing.T) {
	tr := New()
	if err := tr.CheckAndRecord("alice", "s1", nil, nil); err != nil {
		t.Fatalf("nil limits should pass: %v", err)
	}
}
