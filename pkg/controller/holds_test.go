package controller

import (
	"testing"
	"time"
)

func TestHoldStore_CreateAndApprove(t *testing.T) {
	s := NewHoldStore()
	id, ch := s.Create("exec", "alice", "s1", "risky call", "DENY", nil, 5*time.Second)

	if err := s.Approve(id, "admin"); err != nil {
		t.Fatalf("Approve returned error: %v", err)
	}

	state := <-ch
	if state != HoldApproved {
		t.Fatalf("expected %s, got %s", HoldApproved, state)
	}

	h, ok := s.Get(id)
	if !ok {
		t.Fatal("hold not found after approval")
	}
	if h.State != HoldApproved {
		t.Fatalf("stored state: expected %s, got %s", HoldApproved, h.State)
	}
	if h.ResolvedBy != "admin" {
		t.Fatalf("expected resolvedBy=admin, got %s", h.ResolvedBy)
	}
}

func TestHoldStore_CreateAndDeny(t *testing.T) {
	s := NewHoldStore()
	id, ch := s.Create("exec", "bob", "s2", "blocked", "DENY", nil, 5*time.Second)

	if err := s.Deny(id, "policy"); err != nil {
		t.Fatalf("Deny returned error: %v", err)
	}

	state := <-ch
	if state != HoldDenied {
		t.Fatalf("expected %s, got %s", HoldDenied, state)
	}

	h, ok := s.Get(id)
	if !ok {
		t.Fatal("hold not found after denial")
	}
	if h.State != HoldDenied {
		t.Fatalf("stored state: expected %s, got %s", HoldDenied, h.State)
	}
}

func TestHoldStore_Timeout(t *testing.T) {
	s := NewHoldStore()
	_, ch := s.Create("exec", "carol", "s3", "will timeout", "DENY", nil, 20*time.Millisecond)

	state := <-ch
	if state != HoldDenied {
		t.Fatalf("expected %s on timeout with onTimeout=DENY, got %s", HoldDenied, state)
	}
}

func TestHoldStore_TimeoutAllows(t *testing.T) {
	s := NewHoldStore()
	id, ch := s.Create("read", "dave", "s4", "auto-approve", "ALLOW", nil, 20*time.Millisecond)

	state := <-ch
	if state != HoldApproved {
		t.Fatalf("expected %s on timeout with onTimeout=ALLOW, got %s", HoldApproved, state)
	}

	h, ok := s.Get(id)
	if !ok {
		t.Fatal("hold not found after timeout")
	}
	if h.State != HoldTimeout {
		t.Fatalf("stored state should be %s, got %s", HoldTimeout, h.State)
	}
	if h.ResolvedBy != "timeout" {
		t.Fatalf("expected resolvedBy=timeout, got %s", h.ResolvedBy)
	}
}

func TestHoldStore_List(t *testing.T) {
	s := NewHoldStore()

	s.Create("a", "u1", "s1", "", "DENY", nil, 5*time.Second)
	s.Create("b", "u2", "s2", "", "DENY", nil, 5*time.Second)
	s.Create("c", "u3", "s3", "", "DENY", nil, 5*time.Second)

	holds := s.List()
	if len(holds) != 3 {
		t.Fatalf("expected 3 holds, got %d", len(holds))
	}
}

func TestHoldStore_Get(t *testing.T) {
	s := NewHoldStore()
	id, _ := s.Create("tool1", "eve", "s5", "test", "DENY", nil, 5*time.Second)

	h, ok := s.Get(id)
	if !ok {
		t.Fatal("Get returned not-found for existing hold")
	}
	if h.ID != id {
		t.Fatalf("expected ID %s, got %s", id, h.ID)
	}
	if h.Tool != "tool1" {
		t.Fatalf("expected Tool=tool1, got %s", h.Tool)
	}
}

func TestHoldStore_DoubleApprove(t *testing.T) {
	s := NewHoldStore()
	id, ch := s.Create("exec", "frank", "s6", "", "DENY", nil, 5*time.Second)

	if err := s.Approve(id, "admin"); err != nil {
		t.Fatalf("first Approve failed: %v", err)
	}
	<-ch

	err := s.Approve(id, "admin")
	if err == nil {
		t.Fatal("expected error on double Approve, got nil")
	}
}

func TestHoldStore_ApproveUnknown(t *testing.T) {
	s := NewHoldStore()

	err := s.Approve("hold-nonexistent", "admin")
	if err == nil {
		t.Fatal("expected error approving unknown ID, got nil")
	}
}
