package anomaly

import (
	"sync"
	"time"
)

// AlertAction determines what happens when a velocity threshold is exceeded.
type AlertAction string

const (
	AlertActionLog  AlertAction = "LOG"
	AlertActionDeny AlertAction = "DENY"
)

// Alert is emitted when an anomaly is detected.
type Alert struct {
	Identity    string
	Tool        string
	CallsPerMin int
	Threshold   int
	Action      AlertAction
}

type callRecord struct {
	timestamp time.Time
}

type identityWindow struct {
	calls []callRecord
}

// VelocityTracker tracks per-identity tool call rates using a sliding window.
type VelocityTracker struct {
	mu        sync.Mutex
	windows   map[string]*identityWindow
	threshold int
	window    time.Duration
	action    AlertAction
}

type VelocityConfig struct {
	Threshold   int
	AlertAction AlertAction
}

func NewVelocityTracker(cfg VelocityConfig) *VelocityTracker {
	if cfg.Threshold <= 0 {
		cfg.Threshold = 30
	}
	if cfg.AlertAction == "" {
		cfg.AlertAction = AlertActionLog
	}
	return &VelocityTracker{
		windows:   make(map[string]*identityWindow),
		threshold: cfg.Threshold,
		window:    time.Minute,
		action:    cfg.AlertAction,
	}
}

// Record adds a tool call to the identity's sliding window and returns
// an alert if the velocity exceeds the threshold. Returns nil if OK.
func (v *VelocityTracker) Record(identitySubject, tool string) *Alert {
	v.mu.Lock()
	defer v.mu.Unlock()

	now := time.Now()
	cutoff := now.Add(-v.window)

	w, ok := v.windows[identitySubject]
	if !ok {
		w = &identityWindow{}
		v.windows[identitySubject] = w
	}

	// Trim expired entries.
	trimmed := w.calls[:0]
	for _, c := range w.calls {
		if c.timestamp.After(cutoff) {
			trimmed = append(trimmed, c)
		}
	}
	w.calls = append(trimmed, callRecord{timestamp: now})

	if len(w.calls) > v.threshold {
		return &Alert{
			Identity:    identitySubject,
			Tool:        tool,
			CallsPerMin: len(w.calls),
			Threshold:   v.threshold,
			Action:      v.action,
		}
	}
	return nil
}

// Sweep removes stale identity windows with no recent calls.
func (v *VelocityTracker) Sweep() {
	v.mu.Lock()
	defer v.mu.Unlock()

	cutoff := time.Now().Add(-v.window * 2)
	for id, w := range v.windows {
		if len(w.calls) == 0 || w.calls[len(w.calls)-1].timestamp.Before(cutoff) {
			delete(v.windows, id)
		}
	}
}
