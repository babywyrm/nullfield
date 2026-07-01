package controller

import (
	"sync"
	"time"
)

const DefaultEventBufferSize = 1000

type AuditEvent struct {
	EventType   string            `json:"eventType"`
	Method      string            `json:"method,omitempty"`
	Tool        string            `json:"tool,omitempty"`
	Identity    string            `json:"identity,omitempty"`
	SessionID   string            `json:"sessionId,omitempty"`
	Gate        string            `json:"gate,omitempty"`
	ReasonClass string            `json:"reasonClass,omitempty"`
	RuleIndex   *int              `json:"ruleIndex,omitempty"`
	RuleID      string            `json:"ruleId,omitempty"`
	PolicyRef   string            `json:"policyRef,omitempty"`
	RegistryRef string            `json:"registryRef,omitempty"`
	Route       string            `json:"route,omitempty"`
	Labels      map[string]string `json:"labels,omitempty"`
	Reason      string            `json:"reason,omitempty"`
	Target      string            `json:"target,omitempty"`
	Timestamp   time.Time         `json:"timestamp"`
}

// EventBuffer is a thread-safe ring buffer of recent audit events.
type EventBuffer struct {
	mu    sync.RWMutex
	buf   []AuditEvent
	size  int
	pos   int
	count int
}

func NewEventBuffer(size int) *EventBuffer {
	if size <= 0 {
		size = DefaultEventBufferSize
	}
	return &EventBuffer{
		buf:  make([]AuditEvent, size),
		size: size,
	}
}

func (b *EventBuffer) Add(e AuditEvent) {
	if e.Timestamp.IsZero() {
		e.Timestamp = time.Now()
	}
	b.mu.Lock()
	b.buf[b.pos] = e
	b.pos = (b.pos + 1) % b.size
	if b.count < b.size {
		b.count++
	}
	b.mu.Unlock()
}

// List returns events in reverse-chronological order.
// If eventType is non-empty, only matching events are returned.
func (b *EventBuffer) List(eventType string, limit int) []AuditEvent {
	b.mu.RLock()
	defer b.mu.RUnlock()

	if limit <= 0 || limit > b.count {
		limit = b.count
	}

	out := make([]AuditEvent, 0, limit)
	for i := 0; i < b.count && len(out) < limit; i++ {
		idx := (b.pos - 1 - i + b.size) % b.size
		e := b.buf[idx]
		if eventType != "" && e.EventType != eventType {
			continue
		}
		out = append(out, e)
	}
	return out
}

func (b *EventBuffer) Count() int {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.count
}
