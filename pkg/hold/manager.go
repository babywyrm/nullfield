package hold

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sync"
	"time"
)

// Status represents the state of a held request.
type Status string

const (
	StatusPending  Status = "pending"
	StatusApproved Status = "approved"
	StatusDenied   Status = "denied"
	StatusTimeout  Status = "timeout"
)

// HeldRequest represents a tool call that is waiting for human approval.
type HeldRequest struct {
	ID         string         `json:"id"`
	Tool       string         `json:"tool"`
	Arguments  map[string]any `json:"arguments,omitempty"`
	Identity   string         `json:"identity"`
	SessionID  string         `json:"sessionId,omitempty"`
	Reason     string         `json:"reason"`
	Status     Status         `json:"status"`
	CreatedAt  time.Time      `json:"createdAt"`
	ResolvedAt *time.Time     `json:"resolvedAt,omitempty"`
	ResolvedBy string         `json:"resolvedBy,omitempty"`
}

// Resolution is sent back to the waiting goroutine.
type Resolution struct {
	Approved bool
	By       string
}

type pendingHold struct {
	request    *HeldRequest
	resolution chan Resolution
	timeout    time.Duration
}

// Manager tracks held requests and routes approvals/denials.
type Manager struct {
	mu      sync.Mutex
	pending map[string]*pendingHold
	history []*HeldRequest
	maxHist int
}

func NewManager() *Manager {
	return &Manager{
		pending: make(map[string]*pendingHold),
		maxHist: 100,
	}
}

// Hold parks a request and returns a channel that will receive the resolution.
// The caller should block on the channel (with their own timeout or the one returned).
func (m *Manager) Hold(tool string, args map[string]any, identitySubject, sessionID, reason string, timeout time.Duration) (string, <-chan Resolution) {
	id := generateID()
	ch := make(chan Resolution, 1)

	req := &HeldRequest{
		ID:        id,
		Tool:      tool,
		Arguments: args,
		Identity:  identitySubject,
		SessionID: sessionID,
		Reason:    reason,
		Status:    StatusPending,
		CreatedAt: time.Now(),
	}

	m.mu.Lock()
	m.pending[id] = &pendingHold{
		request:    req,
		resolution: ch,
		timeout:    timeout,
	}
	m.mu.Unlock()

	go m.startTimeout(id, timeout)

	return id, ch
}

// Approve resolves a held request as approved.
func (m *Manager) Approve(id, approvedBy string) error {
	return m.resolve(id, true, approvedBy)
}

// Deny resolves a held request as denied.
func (m *Manager) Deny(id, deniedBy string) error {
	return m.resolve(id, false, deniedBy)
}

// List returns all pending held requests.
func (m *Manager) List() []*HeldRequest {
	m.mu.Lock()
	defer m.mu.Unlock()

	out := make([]*HeldRequest, 0, len(m.pending))
	for _, p := range m.pending {
		out = append(out, p.request)
	}
	return out
}

// History returns recently resolved holds.
func (m *Manager) History() []*HeldRequest {
	m.mu.Lock()
	defer m.mu.Unlock()

	out := make([]*HeldRequest, len(m.history))
	copy(out, m.history)
	return out
}

// Get returns a specific held request by ID (pending or history).
func (m *Manager) Get(id string) (*HeldRequest, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if p, ok := m.pending[id]; ok {
		return p.request, true
	}
	for _, h := range m.history {
		if h.ID == id {
			return h, true
		}
	}
	return nil, false
}

func (m *Manager) resolve(id string, approved bool, by string) error {
	m.mu.Lock()
	p, ok := m.pending[id]
	if !ok {
		m.mu.Unlock()
		return fmt.Errorf("hold %s not found or already resolved", id)
	}
	delete(m.pending, id)

	now := time.Now()
	p.request.ResolvedAt = &now
	p.request.ResolvedBy = by
	if approved {
		p.request.Status = StatusApproved
	} else {
		p.request.Status = StatusDenied
	}

	m.history = append(m.history, p.request)
	if len(m.history) > m.maxHist {
		m.history = m.history[len(m.history)-m.maxHist:]
	}
	m.mu.Unlock()

	p.resolution <- Resolution{Approved: approved, By: by}
	close(p.resolution)
	return nil
}

func (m *Manager) startTimeout(id string, timeout time.Duration) {
	time.Sleep(timeout)

	m.mu.Lock()
	p, ok := m.pending[id]
	if !ok {
		m.mu.Unlock()
		return
	}
	delete(m.pending, id)

	now := time.Now()
	p.request.ResolvedAt = &now
	p.request.Status = StatusTimeout

	m.history = append(m.history, p.request)
	if len(m.history) > m.maxHist {
		m.history = m.history[len(m.history)-m.maxHist:]
	}
	m.mu.Unlock()

	p.resolution <- Resolution{Approved: false, By: "timeout"}
	close(p.resolution)
}

func generateID() string {
	b := make([]byte, 8)
	rand.Read(b)
	return "hold-" + hex.EncodeToString(b)
}
