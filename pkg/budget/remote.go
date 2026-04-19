package budget

import (
	"context"
	"log/slog"

	"github.com/babywyrm/nullfield/pkg/controller"
)

type RemoteTracker struct {
	client *controller.Client
	logger *slog.Logger
}

func NewRemoteTracker(client *controller.Client, logger *slog.Logger) *RemoteTracker {
	return &RemoteTracker{
		client: client,
		logger: logger,
	}
}

func (r *RemoteTracker) Check(identity, sessionID, tool string) (bool, error) {
	allowed, _, err := r.client.CheckBudget(context.Background(), identity, sessionID, tool, 0)
	if err != nil {
		return false, err
	}
	return allowed, nil
}

func (r *RemoteTracker) Record(identity, sessionID, tool string, tokens int64) {
	_, _, err := r.client.CheckBudget(context.Background(), identity, sessionID, tool, tokens)
	if err != nil {
		r.logger.Warn("remote budget record failed", "identity", identity, "tool", tool, "error", err)
	}
}
