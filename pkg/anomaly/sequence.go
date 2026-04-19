package anomaly

import (
	"sync"
)

// SequencePattern defines a suspicious tool call sequence.
type SequencePattern struct {
	Name        string   `json:"name" yaml:"name"`
	Tools       []string `json:"tools" yaml:"tools"`
	AlertAction string   `json:"alertAction,omitempty" yaml:"alertAction,omitempty"`
}

// SequenceAlert is emitted when a suspicious sequence is detected.
type SequenceAlert struct {
	Pattern    string
	Tools      []string
	Identity   string
	SessionID  string
	Action     AlertAction
}

// SequenceTracker watches for suspicious tool call orderings per session.
type SequenceTracker struct {
	mu       sync.Mutex
	patterns []SequencePattern
	sessions map[string][]string // sessionID -> recent tool names
	maxHist  int
}

type SequenceConfig struct {
	Patterns []SequencePattern
	MaxHistory int
}

func NewSequenceTracker(cfg SequenceConfig) *SequenceTracker {
	maxHist := cfg.MaxHistory
	if maxHist <= 0 {
		maxHist = 20
	}
	return &SequenceTracker{
		patterns: cfg.Patterns,
		sessions: make(map[string][]string),
		maxHist:  maxHist,
	}
}

// Record adds a tool call to the session history and checks for pattern matches.
// Returns an alert if a suspicious sequence is detected, nil otherwise.
func (t *SequenceTracker) Record(sessionID, tool, identity string) *SequenceAlert {
	if sessionID == "" || len(t.patterns) == 0 {
		return nil
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	hist := t.sessions[sessionID]
	hist = append(hist, tool)
	if len(hist) > t.maxHist {
		hist = hist[len(hist)-t.maxHist:]
	}
	t.sessions[sessionID] = hist

	for _, p := range t.patterns {
		if matchesSequence(hist, p.Tools) {
			action := AlertActionLog
			if p.AlertAction == "DENY" {
				action = AlertActionDeny
			}
			return &SequenceAlert{
				Pattern:   p.Name,
				Tools:     p.Tools,
				Identity:  identity,
				SessionID: sessionID,
				Action:    action,
			}
		}
	}

	return nil
}

// Sweep removes stale sessions.
func (t *SequenceTracker) Sweep() {
	t.mu.Lock()
	defer t.mu.Unlock()
	for id, hist := range t.sessions {
		if len(hist) == 0 {
			delete(t.sessions, id)
		}
	}
}

// matchesSequence checks if the pattern tools appear in order within the history.
func matchesSequence(history []string, pattern []string) bool {
	if len(pattern) == 0 || len(history) < len(pattern) {
		return false
	}

	pi := 0
	for _, tool := range history {
		if tool == pattern[pi] {
			pi++
			if pi == len(pattern) {
				return true
			}
		}
	}
	return false
}
