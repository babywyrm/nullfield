package identity

import (
	"fmt"
	"sync"
	"time"
)

// SessionBinder tracks the identity associated with each MCP session.
// If a different identity appears on the same session, it rejects the request.
// This detects mid-session identity swaps (e.g. by an LLM or intermediate agent).
type SessionBinder struct {
	mu       sync.RWMutex
	sessions map[string]string // sessionID -> subject
}

func NewSessionBinder() *SessionBinder {
	return &SessionBinder{sessions: make(map[string]string)}
}

// Bind checks that the identity is consistent for this session.
// First call for a session establishes the binding; subsequent calls must match.
func (b *SessionBinder) Bind(sessionID, subject string) error {
	if sessionID == "" {
		return nil
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	existing, ok := b.sessions[sessionID]
	if !ok {
		b.sessions[sessionID] = subject
		return nil
	}
	if existing != subject {
		return fmt.Errorf("identity changed mid-session: was %q, now %q", existing, subject)
	}
	return nil
}

func (b *SessionBinder) Clear(sessionID string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	delete(b.sessions, sessionID)
}

// ReplayDetector tracks seen JWT IDs (jti claims) to prevent token replay.
// Entries expire after maxAge to bound memory usage.
type ReplayDetector struct {
	mu     sync.Mutex
	seen   map[string]time.Time
	maxAge time.Duration
}

func NewReplayDetector(maxAge time.Duration) *ReplayDetector {
	if maxAge == 0 {
		maxAge = 10 * time.Minute
	}
	return &ReplayDetector{
		seen:   make(map[string]time.Time),
		maxAge: maxAge,
	}
}

// Check returns an error if the JTI has been seen before.
// Empty JTIs are allowed (not all tokens have them).
func (d *ReplayDetector) Check(jti string) error {
	if jti == "" {
		return nil
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	if _, exists := d.seen[jti]; exists {
		return fmt.Errorf("token replay detected: jti %q already used", jti)
	}
	d.seen[jti] = time.Now()
	return nil
}

// Sweep removes expired entries. Call periodically from a goroutine.
func (d *ReplayDetector) Sweep() {
	d.mu.Lock()
	defer d.mu.Unlock()

	cutoff := time.Now().Add(-d.maxAge)
	for jti, t := range d.seen {
		if t.Before(cutoff) {
			delete(d.seen, jti)
		}
	}
}

// IntegrityChecker combines session binding and replay detection.
// Both are independently opt-in based on the policy config.
type IntegrityChecker struct {
	binder   *SessionBinder
	detector *ReplayDetector
	bindEnabled   bool
	replayEnabled bool
}

type IntegrityConfig struct {
	BindToSession bool
	DetectReplay  bool
	ReplayMaxAge  time.Duration
}

func NewIntegrityChecker(cfg IntegrityConfig) *IntegrityChecker {
	var binder *SessionBinder
	var detector *ReplayDetector

	if cfg.BindToSession {
		binder = NewSessionBinder()
	}
	if cfg.DetectReplay {
		detector = NewReplayDetector(cfg.ReplayMaxAge)
	}

	return &IntegrityChecker{
		binder:        binder,
		detector:      detector,
		bindEnabled:   cfg.BindToSession,
		replayEnabled: cfg.DetectReplay,
	}
}

// Check runs all enabled integrity checks on the identity.
func (ic *IntegrityChecker) Check(id *Identity) error {
	if ic == nil {
		return nil
	}

	if ic.bindEnabled && ic.binder != nil {
		if err := ic.binder.Bind(id.SessionID, id.Subject); err != nil {
			return err
		}
	}

	if ic.replayEnabled && ic.detector != nil {
		if err := ic.detector.Check(id.JTI); err != nil {
			return err
		}
	}

	return nil
}

// Sweep cleans up expired replay entries.
func (ic *IntegrityChecker) Sweep() {
	if ic != nil && ic.detector != nil {
		ic.detector.Sweep()
	}
}
