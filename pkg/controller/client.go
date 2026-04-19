package controller

import (
	"context"
	"log/slog"

	pb "github.com/babywyrm/nullfield/api/v1alpha1/controllerpb"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

type (
	ReportEventRequest     = pb.ReportEventRequest
	RegisterSidecarRequest = pb.RegisterSidecarRequest
)

type Client struct {
	conn   *grpc.ClientConn
	rpc    pb.NullfieldControllerClient
	logger *slog.Logger
}

func NewClient(addr string, logger *slog.Logger) (*Client, error) {
	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, err
	}
	return &Client{
		conn:   conn,
		rpc:    pb.NewNullfieldControllerClient(conn),
		logger: logger,
	}, nil
}

func (c *Client) CheckBudget(ctx context.Context, identity, sessionID, tool string, tokens int64) (allowed bool, remaining int64, err error) {
	resp, err := c.rpc.CheckBudget(ctx, &pb.CheckBudgetRequest{
		Identity:  identity,
		SessionId: sessionID,
		Tool:      tool,
		Tokens:    tokens,
	})
	if err != nil {
		return false, 0, err
	}
	return resp.Allowed, resp.RemainingCalls, nil
}

func (c *Client) CreateHold(ctx context.Context, tool, identity, sessionID, reason, timeout, onTimeout string, payload []byte) (string, error) {
	resp, err := c.rpc.CreateHold(ctx, &pb.CreateHoldRequest{
		Tool:      tool,
		Identity:  identity,
		SessionId: sessionID,
		Reason:    reason,
		Timeout:   timeout,
		OnTimeout: onTimeout,
		Payload:   payload,
	})
	if err != nil {
		return "", err
	}
	return resp.Decision, nil
}

func (c *Client) ReportEvent(ctx context.Context, event *ReportEventRequest) error {
	_, err := c.rpc.ReportEvent(ctx, event)
	return err
}

func (c *Client) RegisterSidecar(ctx context.Context, req *RegisterSidecarRequest) error {
	_, err := c.rpc.RegisterSidecar(ctx, req)
	return err
}

func (c *Client) Close() error {
	return c.conn.Close()
}
