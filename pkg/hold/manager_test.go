package hold

import (
	"testing"
	"time"
)

func TestHold_ApproveResolvesChannel(t *testing.T) {
	mgr := NewManager()
	id, ch := mgr.Hold("test_tool", nil, "alice", "s1", "needs approval", 5*time.Minute)

	go func() {
		time.Sleep(10 * time.Millisecond)
		mgr.Approve(id, "bob")
	}()

	res := <-ch
	if !res.Approved {
		t.Fatal("expected approved")
	}
	if res.By != "bob" {
		t.Errorf("expected approver 'bob', got %q", res.By)
	}
}

func TestHold_DenyResolvesChannel(t *testing.T) {
	mgr := NewManager()
	id, ch := mgr.Hold("test_tool", nil, "alice", "s1", "needs approval", 5*time.Minute)

	go func() {
		time.Sleep(10 * time.Millisecond)
		mgr.Deny(id, "security-team")
	}()

	res := <-ch
	if res.Approved {
		t.Fatal("expected denied")
	}
	if res.By != "security-team" {
		t.Errorf("expected denier 'security-team', got %q", res.By)
	}
}

func TestHold_TimeoutResolvesChannel(t *testing.T) {
	mgr := NewManager()
	_, ch := mgr.Hold("test_tool", nil, "alice", "s1", "needs approval", 50*time.Millisecond)

	res := <-ch
	if res.Approved {
		t.Fatal("expected denied on timeout")
	}
	if res.By != "timeout" {
		t.Errorf("expected 'timeout', got %q", res.By)
	}
}

func TestHold_ListPending(t *testing.T) {
	mgr := NewManager()
	mgr.Hold("tool_a", nil, "alice", "s1", "reason a", 5*time.Minute)
	mgr.Hold("tool_b", nil, "bob", "s2", "reason b", 5*time.Minute)

	pending := mgr.List()
	if len(pending) != 2 {
		t.Errorf("expected 2 pending, got %d", len(pending))
	}
}

func TestHold_ListEmptyAfterResolve(t *testing.T) {
	mgr := NewManager()
	id, _ := mgr.Hold("tool_a", nil, "alice", "s1", "reason", 5*time.Minute)
	mgr.Approve(id, "admin")

	pending := mgr.List()
	if len(pending) != 0 {
		t.Errorf("expected 0 pending after approval, got %d", len(pending))
	}
}

func TestHold_HistoryPopulatedAfterResolve(t *testing.T) {
	mgr := NewManager()
	id, _ := mgr.Hold("tool_a", nil, "alice", "s1", "reason", 5*time.Minute)
	mgr.Approve(id, "admin")

	hist := mgr.History()
	if len(hist) != 1 {
		t.Fatalf("expected 1 history entry, got %d", len(hist))
	}
	if hist[0].Status != StatusApproved {
		t.Errorf("expected status approved, got %s", hist[0].Status)
	}
}

func TestHold_GetByID(t *testing.T) {
	mgr := NewManager()
	id, _ := mgr.Hold("tool_a", nil, "alice", "s1", "reason", 5*time.Minute)

	req, ok := mgr.Get(id)
	if !ok {
		t.Fatal("expected to find hold by ID")
	}
	if req.Tool != "tool_a" {
		t.Errorf("expected tool_a, got %s", req.Tool)
	}
}

func TestHold_DoubleApproveReturnsError(t *testing.T) {
	mgr := NewManager()
	id, _ := mgr.Hold("tool_a", nil, "alice", "s1", "reason", 5*time.Minute)
	mgr.Approve(id, "admin")

	err := mgr.Approve(id, "admin")
	if err == nil {
		t.Fatal("expected error on double approve")
	}
}

func TestHold_ApproveUnknownReturnsError(t *testing.T) {
	mgr := NewManager()
	err := mgr.Approve("nonexistent", "admin")
	if err == nil {
		t.Fatal("expected error for unknown hold ID")
	}
}
