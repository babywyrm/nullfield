package anomaly

import (
	"testing"
	"time"
)

func TestVelocityTracker_UnderThreshold(t *testing.T) {
	vt := NewVelocityTracker(VelocityConfig{Threshold: 5})
	for i := 0; i < 5; i++ {
		if alert := vt.Record("alice", "tool_a"); alert != nil {
			t.Fatalf("expected no alert at call %d, got: %+v", i+1, alert)
		}
	}
}

func TestVelocityTracker_OverThreshold(t *testing.T) {
	vt := NewVelocityTracker(VelocityConfig{Threshold: 3})
	for i := 0; i < 3; i++ {
		vt.Record("alice", "tool_a")
	}
	alert := vt.Record("alice", "tool_a")
	if alert == nil {
		t.Fatal("expected alert after exceeding threshold")
	}
	if alert.CallsPerMin != 4 {
		t.Errorf("expected 4 calls, got %d", alert.CallsPerMin)
	}
	if alert.Threshold != 3 {
		t.Errorf("expected threshold 3, got %d", alert.Threshold)
	}
}

func TestVelocityTracker_PerIdentityIsolation(t *testing.T) {
	vt := NewVelocityTracker(VelocityConfig{Threshold: 2})
	vt.Record("alice", "tool_a")
	vt.Record("alice", "tool_a")

	if alert := vt.Record("bob", "tool_a"); alert != nil {
		t.Fatal("bob should not be affected by alice's calls")
	}

	if alert := vt.Record("alice", "tool_a"); alert == nil {
		t.Fatal("alice should trigger alert at 3 calls with threshold 2")
	}
}

func TestVelocityTracker_AlertAction(t *testing.T) {
	vt := NewVelocityTracker(VelocityConfig{Threshold: 1, AlertAction: AlertActionDeny})
	vt.Record("alice", "tool_a")
	alert := vt.Record("alice", "tool_a")
	if alert == nil {
		t.Fatal("expected alert")
	}
	if alert.Action != AlertActionDeny {
		t.Errorf("expected DENY action, got %s", alert.Action)
	}
}

func TestVelocityTracker_Sweep(t *testing.T) {
	vt := NewVelocityTracker(VelocityConfig{Threshold: 100})
	vt.Record("alice", "tool_a")

	// Manually set the window to something very short for testing
	vt.window = 1 * time.Millisecond
	time.Sleep(5 * time.Millisecond)
	vt.Sweep()

	vt.mu.Lock()
	_, exists := vt.windows["alice"]
	vt.mu.Unlock()
	if exists {
		t.Fatal("expected alice's window to be swept")
	}
}
