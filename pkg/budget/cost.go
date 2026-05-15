package budget

import (
	"sort"
	"time"
)

// CostRate defines the per-call and per-token cost multipliers for a tool.
type CostRate struct {
	CostPerCall  float64 `json:"costPerCall" yaml:"costPerCall"`
	CostPerToken float64 `json:"costPerToken" yaml:"costPerToken"`
}

// CostConfig holds tool-specific cost rates and a default fallback.
type CostConfig struct {
	DefaultRate CostRate            `json:"defaultRate" yaml:"defaultRate"`
	ToolRates   map[string]CostRate `json:"toolRates,omitempty" yaml:"toolRates,omitempty"`
}

// RateFor returns the cost rate for a given tool, falling back to the default.
func (c CostConfig) RateFor(tool string) CostRate {
	if r, ok := c.ToolRates[tool]; ok {
		return r
	}
	return c.DefaultRate
}

// UsageEntry summarizes usage and cost for a single identity or session.
type UsageEntry struct {
	Subject     string  `json:"subject"`
	HourlyCalls int     `json:"hourlyCalls"`
	DailyCalls  int     `json:"dailyCalls"`
	DailyTokens int     `json:"dailyTokens"`
	EstCostUSD  float64 `json:"estCostUsd"`
}

// UsageReport is a point-in-time summary of all tracked identities.
type UsageReport struct {
	Timestamp  time.Time    `json:"timestamp"`
	Identities []UsageEntry `json:"identities"`
	Sessions   []UsageEntry `json:"sessions"`
	TotalCost  float64      `json:"totalCostUsd"`
}

// GetUsageReport builds a full usage report across all tracked identities
// and sessions. Requires a CostConfig to compute estimated costs.
func (t *Tracker) GetUsageReport(cfg CostConfig) UsageReport {
	t.mu.Lock()
	defer t.mu.Unlock()

	now := time.Now()
	report := UsageReport{Timestamp: now.UTC()}

	for subj, rec := range t.identity {
		trimTimestamps(rec, now)
		entry := UsageEntry{
			Subject:     subj,
			HourlyCalls: len(rec.hourlyCalls),
			DailyCalls:  len(rec.dailyCalls),
			DailyTokens: rec.dailyTokens,
		}
		rate := cfg.DefaultRate
		entry.EstCostUSD = float64(entry.DailyCalls)*rate.CostPerCall + float64(entry.DailyTokens)*rate.CostPerToken
		report.TotalCost += entry.EstCostUSD
		report.Identities = append(report.Identities, entry)
	}

	for sess, rec := range t.sessions {
		trimTimestamps(rec, now)
		entry := UsageEntry{
			Subject:     sess,
			HourlyCalls: len(rec.hourlyCalls),
			DailyCalls:  len(rec.dailyCalls),
			DailyTokens: rec.dailyTokens,
		}
		rate := cfg.DefaultRate
		entry.EstCostUSD = float64(entry.DailyCalls)*rate.CostPerCall + float64(entry.DailyTokens)*rate.CostPerToken
		report.Sessions = append(report.Sessions, entry)
	}

	sort.Slice(report.Identities, func(i, j int) bool {
		return report.Identities[i].EstCostUSD > report.Identities[j].EstCostUSD
	})
	sort.Slice(report.Sessions, func(i, j int) bool {
		return report.Sessions[i].EstCostUSD > report.Sessions[j].EstCostUSD
	})

	return report
}

// GetToolCost computes the estimated cost for a single tool call.
func GetToolCost(cfg CostConfig, tool string, tokens int) float64 {
	rate := cfg.RateFor(tool)
	return rate.CostPerCall + float64(tokens)*rate.CostPerToken
}
