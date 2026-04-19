package controller

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"sync"
	"time"
)

const (
	DefaultDedupeWindow    = 60 * time.Second
	DefaultMaxAlertsPerMin = 10
)

type Alerter struct {
	mu             sync.Mutex
	webhookURL     string
	client         *http.Client
	logger         *slog.Logger
	dedupeWindow   time.Duration
	maxPerMin      int
	seen           map[string]time.Time // dedup key → last sent
	recentAlerts   []time.Time
}

func NewAlerter(webhookURL string, logger *slog.Logger) *Alerter {
	return &Alerter{
		webhookURL:   webhookURL,
		client:       &http.Client{Timeout: 10 * time.Second},
		logger:       logger,
		dedupeWindow: DefaultDedupeWindow,
		maxPerMin:    DefaultMaxAlertsPerMin,
		seen:         make(map[string]time.Time),
	}
}

func (a *Alerter) SetWebhook(url string) {
	a.mu.Lock()
	a.webhookURL = url
	a.mu.Unlock()
}

func (a *Alerter) Alert(event AuditEvent) {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.webhookURL == "" {
		return
	}

	key := event.EventType + "|" + event.Tool + "|" + event.Identity
	if last, ok := a.seen[key]; ok && time.Since(last) < a.dedupeWindow {
		return
	}

	now := time.Now()
	cutoff := now.Add(-time.Minute)
	trimmed := a.recentAlerts[:0]
	for _, t := range a.recentAlerts {
		if t.After(cutoff) {
			trimmed = append(trimmed, t)
		}
	}
	a.recentAlerts = trimmed

	if len(a.recentAlerts) >= a.maxPerMin {
		a.logger.Warn("alert rate limit exceeded, dropping alert",
			"eventType", event.EventType, "tool", event.Tool)
		return
	}

	body, err := json.Marshal(event)
	if err != nil {
		a.logger.Error("failed to marshal alert", "error", err)
		return
	}

	a.seen[key] = now
	a.recentAlerts = append(a.recentAlerts, now)

	// Fire webhook asynchronously so we don't hold the lock during HTTP.
	url := a.webhookURL
	go func() {
		resp, err := a.client.Post(url, "application/json", bytes.NewReader(body))
		if err != nil {
			a.logger.Warn("alert webhook failed", "url", url, "error", err)
			return
		}
		resp.Body.Close()
		if resp.StatusCode >= 300 {
			a.logger.Warn("alert webhook non-2xx", "url", url, "status", resp.StatusCode)
		}
	}()
}
