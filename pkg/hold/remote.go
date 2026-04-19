package hold

import (
	"context"
	"log/slog"

	v1alpha1 "github.com/babywyrm/nullfield/api/v1alpha1"
	"github.com/babywyrm/nullfield/pkg/controller"
)

type RemoteHoldManager struct {
	client *controller.Client
	logger *slog.Logger
}

func NewRemoteHoldManager(client *controller.Client, logger *slog.Logger) *RemoteHoldManager {
	return &RemoteHoldManager{
		client: client,
		logger: logger,
	}
}

func (r *RemoteHoldManager) Create(tool, identity, sessionID, reason string, cfg *v1alpha1.HoldConfig) (string, error) {
	timeout := "5m"
	onTimeout := "DENY"
	if cfg != nil {
		if cfg.Timeout != "" {
			timeout = cfg.Timeout
		}
		if cfg.OnTimeout != "" {
			onTimeout = cfg.OnTimeout
		}
	}

	decision, err := r.client.CreateHold(context.Background(), tool, identity, sessionID, reason, timeout, onTimeout, nil)
	if err != nil {
		r.logger.Error("remote hold creation failed", "tool", tool, "identity", identity, "error", err)
		return "", err
	}
	return decision, nil
}
