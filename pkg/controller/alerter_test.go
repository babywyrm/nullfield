package controller

import (
	"log/slog"
	"os"
	"testing"
	"time"
)

func TestAlerter_NoWebhook(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	a := NewAlerter("", logger)

	a.Alert(AuditEvent{
		EventType: "blocked",
		Tool:      "exec",
		Identity:  "alice",
		Timestamp: time.Now(),
	})
	// No webhook configured — should silently return without panic or error.
}

func TestAlerter_Deduplication(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	a := NewAlerter("http://127.0.0.1:1/noop", logger)

	evt := AuditEvent{
		EventType: "blocked",
		Tool:      "exec",
		Identity:  "alice",
		Timestamp: time.Now(),
	}

	a.Alert(evt)

	a.mu.Lock()
	countAfterFirst := len(a.recentAlerts)
	a.mu.Unlock()

	if countAfterFirst != 1 {
		t.Fatalf("expected 1 alert tracked after first send, got %d", countAfterFirst)
	}

	a.Alert(evt)

	a.mu.Lock()
	countAfterSecond := len(a.recentAlerts)
	a.mu.Unlock()

	if countAfterSecond != 1 {
		t.Fatalf("expected still 1 alert (deduped), got %d", countAfterSecond)
	}
}
