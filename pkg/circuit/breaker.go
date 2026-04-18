package circuit

import (
	"sync"
	"time"
)

type sessionState struct {
	calls   int
	started time.Time
}

// Breaker tracks per-session tool call counts and enforces limits.
type Breaker struct {
	mu          sync.Mutex
	sessions    map[string]*sessionState
	maxCalls    int
	maxDuration time.Duration
}

func New(maxCalls int, maxDuration time.Duration) *Breaker {
	return &Breaker{
		sessions:    make(map[string]*sessionState),
		maxCalls:    maxCalls,
		maxDuration: maxDuration,
	}
}

// Allow checks whether the session is still within limits.
func (b *Breaker) Allow(sessionID string) bool {
	if sessionID == "" {
		return true
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	s, ok := b.sessions[sessionID]
	if !ok {
		return true
	}

	if b.maxCalls > 0 && s.calls >= b.maxCalls {
		return false
	}
	if b.maxDuration > 0 && time.Since(s.started) > b.maxDuration {
		return false
	}
	return true
}

// Record increments the call counter for a session.
func (b *Breaker) Record(sessionID string) {
	if sessionID == "" {
		return
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	s, ok := b.sessions[sessionID]
	if !ok {
		b.sessions[sessionID] = &sessionState{
			calls:   1,
			started: time.Now(),
		}
		return
	}
	s.calls++
}

// Reset clears state for a session.
func (b *Breaker) Reset(sessionID string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	delete(b.sessions, sessionID)
}

// Sweep removes expired sessions. Call periodically from a goroutine.
func (b *Breaker) Sweep() {
	b.mu.Lock()
	defer b.mu.Unlock()

	now := time.Now()
	for id, s := range b.sessions {
		if b.maxDuration > 0 && now.Sub(s.started) > b.maxDuration*2 {
			delete(b.sessions, id)
		}
	}
}
