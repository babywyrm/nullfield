package identity

import (
	"testing"
	"time"
)

func TestSessionBinder_FirstCallBinds(t *testing.T) {
	b := NewSessionBinder()
	if err := b.Bind("sess1", "alice"); err != nil {
		t.Fatalf("first bind should succeed: %v", err)
	}
}

func TestSessionBinder_SameIdentityAllowed(t *testing.T) {
	b := NewSessionBinder()
	b.Bind("sess1", "alice")
	if err := b.Bind("sess1", "alice"); err != nil {
		t.Fatalf("same identity should be allowed: %v", err)
	}
}

func TestSessionBinder_DifferentIdentityRejected(t *testing.T) {
	b := NewSessionBinder()
	b.Bind("sess1", "alice")
	err := b.Bind("sess1", "bob")
	if err == nil {
		t.Fatal("expected error for identity change, got nil")
	}
}

func TestSessionBinder_EmptySessionAllowed(t *testing.T) {
	b := NewSessionBinder()
	if err := b.Bind("", "alice"); err != nil {
		t.Fatalf("empty session should be allowed: %v", err)
	}
}

func TestReplayDetector_FirstUseAllowed(t *testing.T) {
	d := NewReplayDetector(time.Minute)
	if err := d.Check("jti-1"); err != nil {
		t.Fatalf("first use should be allowed: %v", err)
	}
}

func TestReplayDetector_ReplayRejected(t *testing.T) {
	d := NewReplayDetector(time.Minute)
	d.Check("jti-1")
	err := d.Check("jti-1")
	if err == nil {
		t.Fatal("expected replay error, got nil")
	}
}

func TestReplayDetector_EmptyJTIAllowed(t *testing.T) {
	d := NewReplayDetector(time.Minute)
	if err := d.Check(""); err != nil {
		t.Fatalf("empty JTI should be allowed: %v", err)
	}
	if err := d.Check(""); err != nil {
		t.Fatalf("empty JTI should always be allowed: %v", err)
	}
}

func TestReplayDetector_SweepExpired(t *testing.T) {
	d := NewReplayDetector(1 * time.Millisecond)
	d.Check("jti-1")
	time.Sleep(5 * time.Millisecond)
	d.Sweep()
	if err := d.Check("jti-1"); err != nil {
		t.Fatalf("expired JTI should be allowed after sweep: %v", err)
	}
}

func TestIntegrityChecker_NilSafe(t *testing.T) {
	var ic *IntegrityChecker
	if err := ic.Check(&Identity{Subject: "test"}); err != nil {
		t.Fatalf("nil checker should be no-op: %v", err)
	}
}

func TestIntegrityChecker_BothEnabled(t *testing.T) {
	ic := NewIntegrityChecker(IntegrityConfig{
		BindToSession: true,
		DetectReplay:  true,
		ReplayMaxAge:  time.Minute,
	})

	id := &Identity{Subject: "alice", SessionID: "s1", JTI: "j1"}
	if err := ic.Check(id); err != nil {
		t.Fatalf("first check should pass: %v", err)
	}

	id2 := &Identity{Subject: "bob", SessionID: "s1", JTI: "j2"}
	if err := ic.Check(id2); err == nil {
		t.Fatal("expected session binding error for identity change")
	}
}
