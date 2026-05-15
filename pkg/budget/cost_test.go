package budget

import (
	"math"
	"testing"
)

func almostEqual(a, b float64) bool {
	return math.Abs(a-b) < 0.0001
}

func TestCostConfig_RateFor_Default(t *testing.T) {
	cfg := CostConfig{
		DefaultRate: CostRate{CostPerCall: 0.01, CostPerToken: 0.001},
	}
	rate := cfg.RateFor("unknown_tool")
	if rate.CostPerCall != 0.01 {
		t.Errorf("expected default cost per call, got %f", rate.CostPerCall)
	}
}

func TestCostConfig_RateFor_ToolSpecific(t *testing.T) {
	cfg := CostConfig{
		DefaultRate: CostRate{CostPerCall: 0.01},
		ToolRates: map[string]CostRate{
			"expensive_tool": {CostPerCall: 1.00, CostPerToken: 0.05},
		},
	}
	rate := cfg.RateFor("expensive_tool")
	if rate.CostPerCall != 1.00 {
		t.Errorf("expected tool-specific rate, got %f", rate.CostPerCall)
	}
}

func TestGetToolCost(t *testing.T) {
	cfg := CostConfig{
		DefaultRate: CostRate{CostPerCall: 0.01, CostPerToken: 0.001},
		ToolRates: map[string]CostRate{
			"llm_tool": {CostPerCall: 0.05, CostPerToken: 0.01},
		},
	}

	cost := GetToolCost(cfg, "basic_tool", 100)
	expected := 0.01 + 100*0.001
	if !almostEqual(cost, expected) {
		t.Errorf("expected %f, got %f", expected, cost)
	}

	cost = GetToolCost(cfg, "llm_tool", 500)
	expected = 0.05 + 500*0.01
	if !almostEqual(cost, expected) {
		t.Errorf("expected %f, got %f", expected, cost)
	}
}

func TestGetUsageReport_Empty(t *testing.T) {
	tracker := New()
	cfg := CostConfig{DefaultRate: CostRate{CostPerCall: 0.01}}

	report := tracker.GetUsageReport(cfg)
	if len(report.Identities) != 0 {
		t.Errorf("expected empty identities, got %d", len(report.Identities))
	}
	if report.TotalCost != 0 {
		t.Errorf("expected zero cost, got %f", report.TotalCost)
	}
}

func TestGetUsageReport_WithUsage(t *testing.T) {
	tracker := New()
	cfg := CostConfig{
		DefaultRate: CostRate{CostPerCall: 0.10, CostPerToken: 0.001},
	}

	idLimits := &Limits{MaxCallsPerHour: 100, MaxCallsPerDay: 1000}
	sessLimits := &Limits{MaxCallsPerHour: 100, MaxCallsPerDay: 1000}
	for i := 0; i < 5; i++ {
		tracker.CheckAndRecord("user-a", "sess-1", idLimits, sessLimits)
	}
	tracker.RecordTokens("user-a", "sess-1", 200)

	for i := 0; i < 3; i++ {
		tracker.CheckAndRecord("user-b", "sess-2", idLimits, sessLimits)
	}
	tracker.RecordTokens("user-b", "sess-2", 50)

	report := tracker.GetUsageReport(cfg)

	if len(report.Identities) != 2 {
		t.Fatalf("expected 2 identities, got %d", len(report.Identities))
	}
	if len(report.Sessions) != 2 {
		t.Fatalf("expected 2 sessions, got %d", len(report.Sessions))
	}

	if report.Identities[0].Subject != "user-a" {
		t.Errorf("expected user-a first (highest cost), got %s", report.Identities[0].Subject)
	}

	expectedCostA := 5*0.10 + 200*0.001
	if !almostEqual(report.Identities[0].EstCostUSD, expectedCostA) {
		t.Errorf("expected cost %f for user-a, got %f", expectedCostA, report.Identities[0].EstCostUSD)
	}

	expectedCostB := 3*0.10 + 50*0.001
	expectedTotal := expectedCostA + expectedCostB
	if !almostEqual(report.TotalCost, expectedTotal) {
		t.Errorf("expected total cost %f, got %f", expectedTotal, report.TotalCost)
	}
}

func TestGetUsageReport_SortedByHighestCost(t *testing.T) {
	tracker := New()
	cfg := CostConfig{DefaultRate: CostRate{CostPerCall: 1.0}}

	limits := &Limits{MaxCallsPerHour: 1000, MaxCallsPerDay: 10000}
	for i := 0; i < 2; i++ {
		tracker.CheckAndRecord("low-user", "s1", limits, nil)
	}
	for i := 0; i < 10; i++ {
		tracker.CheckAndRecord("high-user", "s2", limits, nil)
	}

	report := tracker.GetUsageReport(cfg)
	if report.Identities[0].Subject != "high-user" {
		t.Errorf("expected highest-cost user first, got %s", report.Identities[0].Subject)
	}
}
