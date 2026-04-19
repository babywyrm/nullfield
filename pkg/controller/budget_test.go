package controller

import (
	"testing"
)

func TestBudgetStore_WithinLimits(t *testing.T) {
	bs := NewBudgetStore(BudgetLimits{MaxCallsPerHour: 10, MaxCallsPerDay: 100, MaxTokensPerDay: 50000})

	allowed, reason, remainCalls, remainTokens := bs.Check("alice", "s1", 100)
	if !allowed {
		t.Fatalf("expected allowed, got denied: %s", reason)
	}
	if remainCalls != 9 {
		t.Fatalf("expected 9 remaining calls, got %d", remainCalls)
	}
	if remainTokens != 49900 {
		t.Fatalf("expected 49900 remaining tokens, got %d", remainTokens)
	}
}

func TestBudgetStore_CallLimitExceeded(t *testing.T) {
	bs := NewBudgetStore(BudgetLimits{MaxCallsPerHour: 3, MaxCallsPerDay: 1000, MaxTokensPerDay: 500000})

	for i := 0; i < 3; i++ {
		allowed, reason, _, _ := bs.Check("alice", "", 0)
		if !allowed {
			t.Fatalf("call %d should be allowed: %s", i+1, reason)
		}
	}

	allowed, reason, _, _ := bs.Check("alice", "", 0)
	if allowed {
		t.Fatal("expected denied after exceeding hourly call limit")
	}
	if reason == "" {
		t.Fatal("expected non-empty reason")
	}
}

func TestBudgetStore_TokenLimit(t *testing.T) {
	bs := NewBudgetStore(BudgetLimits{MaxCallsPerHour: 100, MaxCallsPerDay: 1000, MaxTokensPerDay: 500})

	allowed, _, _, _ := bs.Check("alice", "", 500)
	if !allowed {
		t.Fatal("first call at exact token limit should be allowed")
	}

	allowed, reason, _, _ := bs.Check("alice", "", 1)
	if allowed {
		t.Fatal("expected denied after exceeding token limit")
	}
	if reason == "" {
		t.Fatal("expected non-empty reason")
	}
}

func TestBudgetStore_PerSessionIsolation(t *testing.T) {
	bs := NewBudgetStore(BudgetLimits{MaxCallsPerHour: 2, MaxCallsPerDay: 1000, MaxTokensPerDay: 500000})

	for i := 0; i < 2; i++ {
		allowed, reason, _, _ := bs.Check("", "session-A", 0)
		if !allowed {
			t.Fatalf("session-A call %d should be allowed: %s", i+1, reason)
		}
	}

	allowed, _, _, _ := bs.Check("", "session-A", 0)
	if allowed {
		t.Fatal("session-A should be over limit")
	}

	allowed, reason, _, _ := bs.Check("", "session-B", 0)
	if !allowed {
		t.Fatalf("session-B should still be allowed: %s", reason)
	}
}

func TestBudgetStore_PerIdentityIsolation(t *testing.T) {
	bs := NewBudgetStore(BudgetLimits{MaxCallsPerHour: 2, MaxCallsPerDay: 1000, MaxTokensPerDay: 500000})

	for i := 0; i < 2; i++ {
		bs.Check("user-X", "", 0)
	}

	allowed, _, _, _ := bs.Check("user-X", "", 0)
	if allowed {
		t.Fatal("user-X should be over limit")
	}

	allowed, reason, _, _ := bs.Check("user-Y", "", 0)
	if !allowed {
		t.Fatalf("user-Y should still be allowed: %s", reason)
	}
}

func TestBudgetStore_GetUsage(t *testing.T) {
	bs := NewBudgetStore(BudgetLimits{MaxCallsPerHour: 100, MaxCallsPerDay: 1000, MaxTokensPerDay: 500000})

	bs.Check("alice", "s1", 200)
	bs.Check("alice", "s1", 300)
	bs.Check("bob", "s2", 150)

	usage := bs.GetUsage()
	if len(usage) != 2 {
		t.Fatalf("expected 2 identity records, got %d", len(usage))
	}

	byID := make(map[string]BudgetUsage)
	for _, u := range usage {
		byID[u.Identity] = u
	}

	if a, ok := byID["alice"]; !ok {
		t.Fatal("missing alice in usage")
	} else {
		if a.HourlyCalls != 2 {
			t.Fatalf("expected alice hourlyCalls=2, got %d", a.HourlyCalls)
		}
		if a.DailyTokens != 500 {
			t.Fatalf("expected alice dailyTokens=500, got %d", a.DailyTokens)
		}
	}
}

func TestBudgetStore_DefaultLimits(t *testing.T) {
	bs := NewBudgetStore(BudgetLimits{})

	allowed, _, _, _ := bs.Check("alice", "s1", 0)
	if !allowed {
		t.Fatal("should be allowed with default limits")
	}

	usage := bs.GetUsage()
	if len(usage) != 1 {
		t.Fatalf("expected 1 usage record, got %d", len(usage))
	}

	u := usage[0]
	if u.MaxCallsPerHour != DefaultMaxCallsPerHour {
		t.Fatalf("expected default MaxCallsPerHour=%d, got %d", DefaultMaxCallsPerHour, u.MaxCallsPerHour)
	}
	if u.MaxCallsPerDay != DefaultMaxCallsPerDay {
		t.Fatalf("expected default MaxCallsPerDay=%d, got %d", DefaultMaxCallsPerDay, u.MaxCallsPerDay)
	}
	if u.MaxTokensPerDay != DefaultMaxTokensPerDay {
		t.Fatalf("expected default MaxTokensPerDay=%d, got %d", DefaultMaxTokensPerDay, u.MaxTokensPerDay)
	}
}
