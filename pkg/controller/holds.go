package controller

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sync"
	"time"
)

type HoldState string

const (
	HoldPending  HoldState = "pending"
	HoldApproved HoldState = "approved"
	HoldDenied   HoldState = "denied"
	HoldTimeout  HoldState = "timeout"
)

type Hold struct {
	ID         string    `json:"id"`
	Tool       string    `json:"tool"`
	Identity   string    `json:"identity"`
	SessionID  string    `json:"sessionId"`
	Reason     string    `json:"reason"`
	State      HoldState `json:"state"`
	OnTimeout  string    `json:"onTimeout"`
	Payload    []byte    `json:"-"`
	CreatedAt  time.Time `json:"createdAt"`
	ResolvedAt time.Time `json:"resolvedAt,omitempty"`
	ResolvedBy string    `json:"resolvedBy,omitempty"`
}

type holdEntry struct {
	hold    *Hold
	done    chan HoldState
	timeout time.Duration
}

type HoldStore struct {
	mu      sync.RWMutex
	pending map[string]*holdEntry
	history []*Hold
	maxHist int
}

func NewHoldStore() *HoldStore {
	return &HoldStore{
		pending: make(map[string]*holdEntry),
		maxHist: 500,
	}
}

// Create registers a hold and returns a channel that fires when the hold is resolved.
// The caller blocks on the returned channel. The timeout goroutine auto-resolves
// based on onTimeout ("ALLOW" → approved, anything else → denied).
func (s *HoldStore) Create(tool, identity, sessionID, reason, onTimeout string, payload []byte, timeout time.Duration) (string, <-chan HoldState) {
	id := generateHoldID()
	ch := make(chan HoldState, 1)

	h := &Hold{
		ID:        id,
		Tool:      tool,
		Identity:  identity,
		SessionID: sessionID,
		Reason:    reason,
		State:     HoldPending,
		OnTimeout: onTimeout,
		Payload:   payload,
		CreatedAt: time.Now(),
	}

	s.mu.Lock()
	s.pending[id] = &holdEntry{hold: h, done: ch, timeout: timeout}
	s.mu.Unlock()

	go s.runTimeout(id, timeout, onTimeout)

	return id, ch
}

func (s *HoldStore) Approve(id, by string) error {
	return s.resolve(id, HoldApproved, by)
}

func (s *HoldStore) Deny(id, by string) error {
	return s.resolve(id, HoldDenied, by)
}

func (s *HoldStore) Get(id string) (*Hold, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if e, ok := s.pending[id]; ok {
		return e.hold, true
	}
	for _, h := range s.history {
		if h.ID == id {
			return h, true
		}
	}
	return nil, false
}

func (s *HoldStore) List() []*Hold {
	s.mu.RLock()
	defer s.mu.RUnlock()

	out := make([]*Hold, 0, len(s.pending)+len(s.history))
	for _, e := range s.pending {
		out = append(out, e.hold)
	}
	out = append(out, s.history...)
	return out
}

func (s *HoldStore) resolve(id string, state HoldState, by string) error {
	s.mu.Lock()
	e, ok := s.pending[id]
	if !ok {
		s.mu.Unlock()
		return fmt.Errorf("hold %s not found or already resolved", id)
	}
	delete(s.pending, id)

	e.hold.State = state
	e.hold.ResolvedAt = time.Now()
	e.hold.ResolvedBy = by
	s.archive(e.hold)
	s.mu.Unlock()

	e.done <- state
	close(e.done)
	return nil
}

func (s *HoldStore) runTimeout(id string, timeout time.Duration, onTimeout string) {
	time.Sleep(timeout)

	s.mu.Lock()
	e, ok := s.pending[id]
	if !ok {
		s.mu.Unlock()
		return
	}
	delete(s.pending, id)

	state := HoldTimeout
	e.hold.State = state
	e.hold.ResolvedAt = time.Now()
	e.hold.ResolvedBy = "timeout"
	s.archive(e.hold)
	s.mu.Unlock()

	// When onTimeout is ALLOW, the sidecar should treat timeout as approved
	if onTimeout == "ALLOW" {
		e.done <- HoldApproved
	} else {
		e.done <- HoldDenied
	}
	close(e.done)
}

// archive appends to history and trims to maxHist (caller must hold mu).
func (s *HoldStore) archive(h *Hold) {
	s.history = append(s.history, h)
	if len(s.history) > s.maxHist {
		s.history = s.history[len(s.history)-s.maxHist:]
	}
}

func generateHoldID() string {
	b := make([]byte, 8)
	rand.Read(b)
	return "hold-" + hex.EncodeToString(b)
}
