package controller

import (
	"context"
	"log/slog"
	"time"

	pb "github.com/babywyrm/nullfield/api/v1alpha1/controllerpb"
)

type Server struct {
	pb.UnimplementedNullfieldControllerServer

	Holds    *HoldStore
	Budgets  *BudgetStore
	Events   *EventBuffer
	Sidecars *SidecarRegistry
	Alerter  *Alerter
	Logger   *slog.Logger
}

func (s *Server) CheckBudget(_ context.Context, req *pb.CheckBudgetRequest) (*pb.CheckBudgetResponse, error) {
	allowed, reason, remainCalls, remainTokens := s.Budgets.Check(req.Identity, req.SessionId, req.Tokens)

	s.Events.Add(AuditEvent{
		EventType: "budget.check",
		Tool:      req.Tool,
		Identity:  req.Identity,
		SessionID: req.SessionId,
		Reason:    reason,
	})

	if !allowed {
		s.Logger.Info("budget denied",
			"identity", req.Identity, "session", req.SessionId,
			"tool", req.Tool, "reason", reason)
		s.Alerter.Alert(AuditEvent{
			EventType: "budget.denied",
			Tool:      req.Tool,
			Identity:  req.Identity,
			Reason:    reason,
		})
	}

	return &pb.CheckBudgetResponse{
		Allowed:         allowed,
		Reason:          reason,
		RemainingCalls:  remainCalls,
		RemainingTokens: remainTokens,
	}, nil
}

func (s *Server) CreateHold(ctx context.Context, req *pb.CreateHoldRequest) (*pb.CreateHoldResponse, error) {
	timeout := 5 * time.Minute
	if req.Timeout != "" {
		if d, err := time.ParseDuration(req.Timeout); err == nil {
			timeout = d
		}
	}
	onTimeout := "DENY"
	if req.OnTimeout != "" {
		onTimeout = req.OnTimeout
	}

	id, ch := s.Holds.Create(req.Tool, req.Identity, req.SessionId, req.Reason, onTimeout, req.Payload, timeout)

	s.Logger.Info("hold created",
		"holdId", id, "tool", req.Tool,
		"identity", req.Identity, "timeout", timeout)

	s.Events.Add(AuditEvent{
		EventType: "hold.created",
		Tool:      req.Tool,
		Identity:  req.Identity,
		SessionID: req.SessionId,
		Reason:    req.Reason,
	})

	s.Alerter.Alert(AuditEvent{
		EventType: "hold.created",
		Tool:      req.Tool,
		Identity:  req.Identity,
		Reason:    req.Reason,
	})

	// Block until resolved or context cancelled.
	select {
	case state := <-ch:
		decision := string(state)
		s.Logger.Info("hold resolved", "holdId", id, "decision", decision)
		return &pb.CreateHoldResponse{
			HoldId:   id,
			Decision: decision,
		}, nil
	case <-ctx.Done():
		return &pb.CreateHoldResponse{
			HoldId:   id,
			Decision: "denied",
			Reason:   "context cancelled",
		}, nil
	}
}

func (s *Server) ReportEvent(_ context.Context, req *pb.ReportEventRequest) (*pb.ReportEventResponse, error) {
	ts := time.Now()
	if req.Timestamp != nil {
		ts = req.Timestamp.AsTime()
	}

	event := AuditEvent{
		EventType:   req.EventType,
		Method:      req.Method,
		Tool:        req.Tool,
		Identity:    req.Identity,
		SessionID:   req.SessionId,
		Gate:        req.Gate,
		ReasonClass: req.ReasonClass,
		RuleIndex:   optionalRuleIndex(req.RuleIndex),
		RuleID:      req.RuleId,
		PolicyRef:   req.PolicyRef,
		RegistryRef: req.RegistryRef,
		Route:       req.Route,
		Labels:      req.Labels,
		Reason:      req.Reason,
		Target:      req.Target,
		Timestamp:   ts,
	}

	s.Events.Add(event)
	s.Alerter.Alert(event)

	return &pb.ReportEventResponse{}, nil
}

func optionalRuleIndex(ruleIndex *int32) *int {
	if ruleIndex == nil {
		return nil
	}
	i := int(*ruleIndex)
	return &i
}

func (s *Server) RegisterSidecar(_ context.Context, req *pb.RegisterSidecarRequest) (*pb.RegisterSidecarResponse, error) {
	s.Sidecars.Register(SidecarInfo{
		TargetName:      req.TargetName,
		TargetNamespace: req.TargetNamespace,
		PodName:         req.PodName,
		Version:         req.Version,
		ToolCount:       req.ToolCount,
		RuleCount:       req.RuleCount,
	})

	s.Logger.Info("sidecar registered",
		"target", req.TargetName, "namespace", req.TargetNamespace,
		"pod", req.PodName, "version", req.Version)

	s.Events.Add(AuditEvent{
		EventType: "sidecar.registered",
		Target:    req.TargetNamespace + "/" + req.TargetName,
		Reason:    "pod=" + req.PodName,
	})

	return &pb.RegisterSidecarResponse{
		Accepted: true,
		Message:  "registered",
	}, nil
}
