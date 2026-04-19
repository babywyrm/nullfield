package budget

import (
	"fmt"
	"sync"
	"time"
)

type usageRecord struct {
	hourlyCalls  []time.Time
	dailyCalls   []time.Time
	dailyTokens  int
	lastResetDay int // day of year
}

// Tracker enforces per-identity and per-session call/token budgets.
type Tracker struct {
	mu       sync.Mutex
	identity map[string]*usageRecord
	sessions map[string]*usageRecord
}

func New() *Tracker {
	return &Tracker{
		identity: make(map[string]*usageRecord),
		sessions: make(map[string]*usageRecord),
	}
}

// CheckAndRecord verifies the identity and session are within budget,
// then records the call. Returns an error describing which limit was hit.
func (t *Tracker) CheckAndRecord(identitySubject, sessionID string, perIdentity, perSession *Limits) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	now := time.Now()

	if perIdentity != nil && identitySubject != "" {
		rec := t.getOrCreate(t.identity, identitySubject, now)
		if err := checkLimits(rec, perIdentity, now); err != nil {
			return fmt.Errorf("identity budget: %w", err)
		}
	}

	if perSession != nil && sessionID != "" {
		rec := t.getOrCreate(t.sessions, sessionID, now)
		if err := checkLimits(rec, perSession, now); err != nil {
			return fmt.Errorf("session budget: %w", err)
		}
	}

	// All checks passed — record the call.
	if perIdentity != nil && identitySubject != "" {
		rec := t.identity[identitySubject]
		rec.hourlyCalls = append(rec.hourlyCalls, now)
		rec.dailyCalls = append(rec.dailyCalls, now)
	}
	if perSession != nil && sessionID != "" {
		rec := t.sessions[sessionID]
		rec.hourlyCalls = append(rec.hourlyCalls, now)
		rec.dailyCalls = append(rec.dailyCalls, now)
	}

	return nil
}

// RecordTokens adds token usage after a successful upstream call.
func (t *Tracker) RecordTokens(identitySubject, sessionID string, tokens int) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if rec, ok := t.identity[identitySubject]; ok {
		rec.dailyTokens += tokens
	}
	if rec, ok := t.sessions[sessionID]; ok {
		rec.dailyTokens += tokens
	}
}

// GetUsage returns current usage for an identity (for observability).
func (t *Tracker) GetUsage(identitySubject string) (hourlyCalls, dailyCalls, dailyTokens int) {
	t.mu.Lock()
	defer t.mu.Unlock()

	now := time.Now()
	rec, ok := t.identity[identitySubject]
	if !ok {
		return 0, 0, 0
	}
	trimTimestamps(rec, now)
	return len(rec.hourlyCalls), len(rec.dailyCalls), rec.dailyTokens
}

// Sweep removes stale records older than 24h.
func (t *Tracker) Sweep() {
	t.mu.Lock()
	defer t.mu.Unlock()

	cutoff := time.Now().Add(-24 * time.Hour)
	for id, rec := range t.identity {
		if len(rec.dailyCalls) == 0 || rec.dailyCalls[len(rec.dailyCalls)-1].Before(cutoff) {
			delete(t.identity, id)
		}
	}
	for id, rec := range t.sessions {
		if len(rec.dailyCalls) == 0 || rec.dailyCalls[len(rec.dailyCalls)-1].Before(cutoff) {
			delete(t.sessions, id)
		}
	}
}

// Limits mirrors the BudgetLimits from the API types (avoids import cycle).
type Limits struct {
	MaxCallsPerHour int
	MaxCallsPerDay  int
	MaxTokensPerDay int
}

func (t *Tracker) getOrCreate(m map[string]*usageRecord, key string, now time.Time) *usageRecord {
	rec, ok := m[key]
	if !ok {
		rec = &usageRecord{lastResetDay: now.YearDay()}
		m[key] = rec
		return rec
	}
	trimTimestamps(rec, now)
	if now.YearDay() != rec.lastResetDay {
		rec.dailyTokens = 0
		rec.lastResetDay = now.YearDay()
	}
	return rec
}

func trimTimestamps(rec *usageRecord, now time.Time) {
	hourAgo := now.Add(-time.Hour)
	dayAgo := now.Add(-24 * time.Hour)

	trimmed := rec.hourlyCalls[:0]
	for _, t := range rec.hourlyCalls {
		if t.After(hourAgo) {
			trimmed = append(trimmed, t)
		}
	}
	rec.hourlyCalls = trimmed

	trimmed = rec.dailyCalls[:0]
	for _, t := range rec.dailyCalls {
		if t.After(dayAgo) {
			trimmed = append(trimmed, t)
		}
	}
	rec.dailyCalls = trimmed
}

func checkLimits(rec *usageRecord, limits *Limits, now time.Time) error {
	trimTimestamps(rec, now)

	if limits.MaxCallsPerHour > 0 && len(rec.hourlyCalls) >= limits.MaxCallsPerHour {
		return fmt.Errorf("hourly call limit reached (%d/%d)", len(rec.hourlyCalls), limits.MaxCallsPerHour)
	}
	if limits.MaxCallsPerDay > 0 && len(rec.dailyCalls) >= limits.MaxCallsPerDay {
		return fmt.Errorf("daily call limit reached (%d/%d)", len(rec.dailyCalls), limits.MaxCallsPerDay)
	}
	if limits.MaxTokensPerDay > 0 && rec.dailyTokens >= limits.MaxTokensPerDay {
		return fmt.Errorf("daily token limit reached (%d/%d)", rec.dailyTokens, limits.MaxTokensPerDay)
	}
	return nil
}
