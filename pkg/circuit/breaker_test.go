package circuit

import (
	"testing"
	"time"
)

func TestBreaker_AllowWithinLimits(t *testing.T) {
	b := New(5, time.Minute)
	for i := 0; i < 5; i++ {
		if !b.Allow("s1") {
			t.Fatalf("call %d should be allowed", i+1)
		}
		b.Record("s1")
	}
}

func TestBreaker_DenyOverCallLimit(t *testing.T) {
	b := New(3, time.Minute)
	for i := 0; i < 3; i++ {
		b.Record("s1")
	}
	if b.Allow("s1") {
		t.Fatal("should be denied after 3 calls with limit 3")
	}
}

func TestBreaker_DenyOverDuration(t *testing.T) {
	b := New(100, 50*time.Millisecond)
	b.Record("s1")
	time.Sleep(60 * time.Millisecond)
	if b.Allow("s1") {
		t.Fatal("should be denied after duration exceeded")
	}
}

func TestBreaker_PerSessionIsolation(t *testing.T) {
	b := New(2, time.Minute)
	b.Record("s1")
	b.Record("s1")

	if b.Allow("s1") {
		t.Fatal("s1 should be denied")
	}
	if !b.Allow("s2") {
		t.Fatal("s2 should be allowed — different session")
	}
}

func TestBreaker_EmptySessionAllowed(t *testing.T) {
	b := New(1, time.Minute)
	if !b.Allow("") {
		t.Fatal("empty session should always be allowed")
	}
}

func TestBreaker_Reset(t *testing.T) {
	b := New(2, time.Minute)
	b.Record("s1")
	b.Record("s1")
	b.Reset("s1")

	if !b.Allow("s1") {
		t.Fatal("should be allowed after reset")
	}
}

func TestBreaker_Sweep(t *testing.T) {
	b := New(100, 1*time.Millisecond)
	b.Record("s1")
	time.Sleep(5 * time.Millisecond)
	b.Sweep()

	b.mu.Lock()
	_, exists := b.sessions["s1"]
	b.mu.Unlock()
	if exists {
		t.Fatal("s1 should be swept after expiry")
	}
}

func TestBreaker_ZeroLimitsAlwaysAllow(t *testing.T) {
	b := New(0, 0)
	b.Record("s1")
	b.Record("s1")
	b.Record("s1")
	if !b.Allow("s1") {
		t.Fatal("zero limits should always allow")
	}
}
