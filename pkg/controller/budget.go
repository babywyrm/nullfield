package controller

import (
	"fmt"
	"sync"
	"time"
)

const (
	DefaultMaxCallsPerHour = 100
	DefaultMaxCallsPerDay  = 1000
	DefaultMaxTokensPerDay = 500000
)

type BudgetLimits struct {
	MaxCallsPerHour int
	MaxCallsPerDay  int
	MaxTokensPerDay int
}

type budgetRecord struct {
	hourlyCalls  []time.Time
	dailyCalls   []time.Time
	dailyTokens  int64
	lastResetDay int
}

type BudgetUsage struct {
	Identity        string `json:"identity"`
	HourlyCalls     int    `json:"hourlyCalls"`
	DailyCalls      int    `json:"dailyCalls"`
	DailyTokens     int64  `json:"dailyTokens"`
	MaxCallsPerHour int    `json:"maxCallsPerHour"`
	MaxCallsPerDay  int    `json:"maxCallsPerDay"`
	MaxTokensPerDay int    `json:"maxTokensPerDay"`
}

type BudgetStore struct {
	mu       sync.Mutex
	identity map[string]*budgetRecord
	sessions map[string]*budgetRecord
	limits   BudgetLimits
}

func NewBudgetStore(limits BudgetLimits) *BudgetStore {
	if limits.MaxCallsPerHour <= 0 {
		limits.MaxCallsPerHour = DefaultMaxCallsPerHour
	}
	if limits.MaxCallsPerDay <= 0 {
		limits.MaxCallsPerDay = DefaultMaxCallsPerDay
	}
	if limits.MaxTokensPerDay <= 0 {
		limits.MaxTokensPerDay = DefaultMaxTokensPerDay
	}
	return &BudgetStore{
		identity: make(map[string]*budgetRecord),
		sessions: make(map[string]*budgetRecord),
		limits:   limits,
	}
}

// Check returns whether the identity/session has remaining budget, and how much is left.
// It also records the call if allowed.
func (s *BudgetStore) Check(identity, sessionID string, tokens int64) (allowed bool, reason string, remainCalls int64, remainTokens int64) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()

	if identity != "" {
		rec := s.getOrCreate(s.identity, identity, now)
		if err := s.checkLimits(rec, now); err != nil {
			return false, fmt.Sprintf("identity budget: %s", err), 0, 0
		}
	}

	if sessionID != "" {
		rec := s.getOrCreate(s.sessions, sessionID, now)
		if err := s.checkLimits(rec, now); err != nil {
			return false, fmt.Sprintf("session budget: %s", err), 0, 0
		}
	}

	// Record the call
	if identity != "" {
		rec := s.identity[identity]
		rec.hourlyCalls = append(rec.hourlyCalls, now)
		rec.dailyCalls = append(rec.dailyCalls, now)
		rec.dailyTokens += tokens
	}
	if sessionID != "" {
		rec := s.sessions[sessionID]
		rec.hourlyCalls = append(rec.hourlyCalls, now)
		rec.dailyCalls = append(rec.dailyCalls, now)
		rec.dailyTokens += tokens
	}

	remainCalls = int64(s.limits.MaxCallsPerHour)
	remainTokens = int64(s.limits.MaxTokensPerDay)
	if identity != "" {
		rec := s.identity[identity]
		remainCalls = int64(s.limits.MaxCallsPerHour - len(rec.hourlyCalls))
		remainTokens = int64(s.limits.MaxTokensPerDay) - rec.dailyTokens
	}

	return true, "", remainCalls, remainTokens
}

func (s *BudgetStore) GetUsage() []BudgetUsage {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	out := make([]BudgetUsage, 0, len(s.identity))
	for id, rec := range s.identity {
		trimBudgetTimestamps(rec, now)
		out = append(out, BudgetUsage{
			Identity:        id,
			HourlyCalls:     len(rec.hourlyCalls),
			DailyCalls:      len(rec.dailyCalls),
			DailyTokens:     rec.dailyTokens,
			MaxCallsPerHour: s.limits.MaxCallsPerHour,
			MaxCallsPerDay:  s.limits.MaxCallsPerDay,
			MaxTokensPerDay: s.limits.MaxTokensPerDay,
		})
	}
	return out
}

// Sweep removes records with no activity in the last 24h.
func (s *BudgetStore) Sweep() {
	s.mu.Lock()
	defer s.mu.Unlock()

	cutoff := time.Now().Add(-24 * time.Hour)
	for id, rec := range s.identity {
		if len(rec.dailyCalls) == 0 || rec.dailyCalls[len(rec.dailyCalls)-1].Before(cutoff) {
			delete(s.identity, id)
		}
	}
	for id, rec := range s.sessions {
		if len(rec.dailyCalls) == 0 || rec.dailyCalls[len(rec.dailyCalls)-1].Before(cutoff) {
			delete(s.sessions, id)
		}
	}
}

func (s *BudgetStore) checkLimits(rec *budgetRecord, now time.Time) error {
	trimBudgetTimestamps(rec, now)

	if len(rec.hourlyCalls) >= s.limits.MaxCallsPerHour {
		return fmt.Errorf("hourly call limit reached (%d/%d)", len(rec.hourlyCalls), s.limits.MaxCallsPerHour)
	}
	if len(rec.dailyCalls) >= s.limits.MaxCallsPerDay {
		return fmt.Errorf("daily call limit reached (%d/%d)", len(rec.dailyCalls), s.limits.MaxCallsPerDay)
	}
	if int64(s.limits.MaxTokensPerDay) > 0 && rec.dailyTokens >= int64(s.limits.MaxTokensPerDay) {
		return fmt.Errorf("daily token limit reached (%d/%d)", rec.dailyTokens, s.limits.MaxTokensPerDay)
	}
	return nil
}

func (s *BudgetStore) getOrCreate(m map[string]*budgetRecord, key string, now time.Time) *budgetRecord {
	rec, ok := m[key]
	if !ok {
		rec = &budgetRecord{lastResetDay: now.YearDay()}
		m[key] = rec
		return rec
	}
	trimBudgetTimestamps(rec, now)
	if now.YearDay() != rec.lastResetDay {
		rec.dailyTokens = 0
		rec.lastResetDay = now.YearDay()
	}
	return rec
}

func trimBudgetTimestamps(rec *budgetRecord, now time.Time) {
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
