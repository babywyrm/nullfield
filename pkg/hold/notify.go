package hold

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"time"
)

// Notifier sends notifications when holds are created.
type Notifier interface {
	Notify(req *HeldRequest) error
}

// WebhookNotifier sends a POST to a configured URL with hold details.
type WebhookNotifier struct {
	URL    string
	Client *http.Client
	Logger *slog.Logger
}

func NewWebhookNotifier(url string, logger *slog.Logger) *WebhookNotifier {
	return &WebhookNotifier{
		URL: url,
		Client: &http.Client{
			Timeout: 10 * time.Second,
		},
		Logger: logger,
	}
}

type webhookPayload struct {
	Event    string         `json:"event"`
	HoldID   string         `json:"hold_id"`
	Tool     string         `json:"tool"`
	Identity string         `json:"identity"`
	Reason   string         `json:"reason"`
	ApproveURL string       `json:"approve_url"`
	DenyURL    string       `json:"deny_url"`
	ExpiresAt  time.Time    `json:"expires_at"`
	Arguments  map[string]any `json:"arguments,omitempty"`
}

func (n *WebhookNotifier) Notify(req *HeldRequest) error {
	payload := webhookPayload{
		Event:    "hold.created",
		HoldID:   req.ID,
		Tool:     req.Tool,
		Identity: req.Identity,
		Reason:   req.Reason,
		ApproveURL: fmt.Sprintf("/admin/holds/%s/approve", req.ID),
		DenyURL:    fmt.Sprintf("/admin/holds/%s/deny", req.ID),
		ExpiresAt:  req.CreatedAt.Add(5 * time.Minute),
		Arguments:  req.Arguments,
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal webhook payload: %w", err)
	}

	resp, err := n.Client.Post(n.URL, "application/json", bytes.NewReader(body))
	if err != nil {
		n.Logger.Warn("webhook notification failed", "url", n.URL, "error", err)
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		n.Logger.Warn("webhook returned non-2xx", "url", n.URL, "status", resp.StatusCode)
	}
	return nil
}

// NoopNotifier does nothing (used when no webhook is configured).
type NoopNotifier struct{}

func (n *NoopNotifier) Notify(_ *HeldRequest) error { return nil }
