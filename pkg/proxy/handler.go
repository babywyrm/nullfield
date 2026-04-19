package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"
	"time"

	v1alpha1 "github.com/babywyrm/nullfield/api/v1alpha1"
	"github.com/babywyrm/nullfield/pkg/anomaly"
	"github.com/babywyrm/nullfield/pkg/audit"
	"github.com/babywyrm/nullfield/pkg/budget"
	"github.com/babywyrm/nullfield/pkg/circuit"
	"github.com/babywyrm/nullfield/pkg/hold"
	"github.com/babywyrm/nullfield/pkg/identity"
	"github.com/babywyrm/nullfield/pkg/policy"
	"github.com/babywyrm/nullfield/pkg/registry"
	"github.com/babywyrm/nullfield/pkg/scope"
)

// Handler is the main reverse proxy handler that intercepts MCP traffic.
type Handler struct {
	upstream     *httputil.ReverseProxy
	upstreamAddr string
	engine       policy.Engine
	auditor   audit.Emitter
	verifier  identity.Verifier
	integrity *identity.IntegrityChecker
	velocity  *anomaly.VelocityTracker
	budgets   *budget.Tracker
	holds     *hold.Manager
	registry  *registry.Registry
	breaker   *circuit.Breaker
	logger    *slog.Logger
}

type HandlerOpts struct {
	UpstreamURL *url.URL
	Engine      policy.Engine
	Auditor     audit.Emitter
	Verifier    identity.Verifier
	Integrity   *identity.IntegrityChecker
	Velocity    *anomaly.VelocityTracker
	Budgets     *budget.Tracker
	Holds       *hold.Manager
	Registry    *registry.Registry
	Breaker     *circuit.Breaker
	Logger      *slog.Logger
}

func NewHandler(opts HandlerOpts) *Handler {
	proxy := httputil.NewSingleHostReverseProxy(opts.UpstreamURL)
	return &Handler{
		upstream:     proxy,
		upstreamAddr: opts.UpstreamURL.Host,
		engine:       opts.Engine,
		auditor:   opts.Auditor,
		verifier:  opts.Verifier,
		integrity: opts.Integrity,
		velocity:  opts.Velocity,
		budgets:   opts.Budgets,
		holds:     opts.Holds,
		registry:  opts.Registry,
		breaker:   opts.Breaker,
		logger:    opts.Logger,
	}
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20)) // 1 MiB cap
	if err != nil {
		h.writeJSONRPCError(w, nil, ErrCodeParse, "failed to read request body")
		return
	}
	r.Body = io.NopCloser(bytes.NewReader(body))

	var req JSONRPCRequest
	if err := json.Unmarshal(body, &req); err != nil {
		// Not JSON-RPC — pass through as non-MCP traffic.
		r.Body = io.NopCloser(bytes.NewReader(body))
		h.upstream.ServeHTTP(w, r)
		return
	}

	ctx := r.Context()

	id, err := h.verifier.Verify(r)
	if err != nil {
		h.logger.WarnContext(ctx, "identity verification failed", "error", err, "method", req.Method)
		h.auditor.Emit(ctx, audit.Event{
			Type:   audit.EventIdentityFailed,
			Method: req.Method,
			Error:  err.Error(),
		})
		h.writeJSONRPCError(w, req.ID, ErrCodeIdentityFailed, "identity verification failed")
		return
	}
	if h.integrity != nil {
		if err := h.integrity.Check(id); err != nil {
			h.logger.WarnContext(ctx, "integrity check failed", "error", err, "method", req.Method)
			h.auditor.Emit(ctx, audit.Event{
				Type:   audit.EventIdentityFailed,
				Method: req.Method,
				Error:  err.Error(),
			})
			h.writeJSONRPCError(w, req.ID, ErrCodeIdentityFailed, "integrity check failed: "+err.Error())
			return
		}
	}

	ctx = identity.WithIdentity(ctx, id)

	if req.Method == MethodToolsCall {
		h.handleToolsCall(ctx, w, r, &req, body, id)
		return
	}

	// Non-tools/call MCP methods — audit and forward.
	h.auditor.Emit(ctx, audit.Event{
		Type:     audit.EventMCPRequest,
		Method:   req.Method,
		Identity: id.Subject,
	})
	r.Body = io.NopCloser(bytes.NewReader(body))
	h.upstream.ServeHTTP(w, r)
}

func (h *Handler) handleToolsCall(ctx context.Context, w http.ResponseWriter, r *http.Request, req *JSONRPCRequest, body []byte, id *identity.Identity) {
	tc, err := ParseToolsCall(req)
	if err != nil {
		h.writeJSONRPCError(w, req.ID, ErrCodeInvalidPar, err.Error())
		return
	}

	if !h.registry.IsRegistered(tc.Name) {
		h.auditor.Emit(ctx, audit.Event{
			Type:     audit.EventToolDenied,
			Method:   req.Method,
			ToolName: tc.Name,
			Identity: id.Subject,
			Reason:   "tool not registered",
		})
		h.writeJSONRPCError(w, req.ID, ErrCodeToolUnknown, "tool not registered: "+tc.Name)
		return
	}

	if !h.breaker.Allow(id.SessionID) {
		h.auditor.Emit(ctx, audit.Event{
			Type:     audit.EventCircuitTripped,
			Method:   req.Method,
			ToolName: tc.Name,
			Identity: id.Subject,
		})
		h.writeJSONRPCError(w, req.ID, ErrCodeCircuitOpen, "circuit breaker open — session limit exceeded")
		return
	}

	decision := h.engine.Evaluate(ctx, policy.Request{
		Method:    req.Method,
		ToolName:  tc.Name,
		Arguments: tc.Arguments,
		Identity:  id,
	})

	if decision.Held && h.holds != nil && decision.MatchedRule != nil && decision.MatchedRule.Hold != nil {
		holdCfg := decision.MatchedRule.Hold
		timeout := 5 * time.Minute
		if holdCfg.Timeout != "" {
			if parsed, err := time.ParseDuration(holdCfg.Timeout); err == nil {
				timeout = parsed
			}
		}

		holdID, ch := h.holds.Hold(tc.Name, tc.Arguments, id.Subject, id.SessionID, decision.Reason, timeout)

		h.logger.InfoContext(ctx, "request held for approval",
			"holdId", holdID, "tool", tc.Name, "identity", id.Subject, "timeout", timeout)

		h.auditor.Emit(ctx, audit.Event{
			Type:     audit.EventHoldCreated,
			Method:   req.Method,
			ToolName: tc.Name,
			Identity: id.Subject,
			Reason:   fmt.Sprintf("held: %s (id=%s, timeout=%s)", decision.Reason, holdID, timeout),
		})

		resolution := <-ch

		if !resolution.Approved {
			h.auditor.Emit(ctx, audit.Event{
				Type:     audit.EventToolDenied,
				Method:   req.Method,
				ToolName: tc.Name,
				Identity: id.Subject,
				Reason:   fmt.Sprintf("hold %s: denied by %s", holdID, resolution.By),
			})
			if resolution.By == "timeout" {
				h.writeJSONRPCError(w, req.ID, ErrCodeHoldTimeout, "hold timed out without approval")
			} else {
				h.writeJSONRPCError(w, req.ID, ErrCodePolicyDenied, "hold denied by "+resolution.By)
			}
			return
		}

		h.logger.InfoContext(ctx, "hold approved", "holdId", holdID, "approvedBy", resolution.By)
		h.auditor.Emit(ctx, audit.Event{
			Type:     audit.EventHoldApproved,
			Method:   req.Method,
			ToolName: tc.Name,
			Identity: id.Subject,
			Reason:   fmt.Sprintf("hold %s: approved by %s", holdID, resolution.By),
		})
		// Fall through to budget check and forwarding.
	} else if !decision.Allowed {
		h.auditor.Emit(ctx, audit.Event{
			Type:     audit.EventToolDenied,
			Method:   req.Method,
			ToolName: tc.Name,
			Identity: id.Subject,
			Reason:   decision.Reason,
		})
		h.writeJSONRPCError(w, req.ID, ErrCodePolicyDenied, "denied by policy: "+decision.Reason)
		return
	}

	// SCOPE — modify request arguments if the matched rule has scope config.
	var scopeResponseCfg *v1alpha1.ScopeResponseConfig
	if decision.Scoped && decision.MatchedRule != nil && decision.MatchedRule.Scope != nil {
		scopeCfg := decision.MatchedRule.Scope
		var mods scope.Modifications

		if scopeCfg.Request != nil {
			var modifiedArgs map[string]any
			modifiedArgs, mods = scope.ModifyRequest(tc.Arguments, scopeCfg.Request)
			tc.Arguments = modifiedArgs

			newBody, err := scope.RebuildRequestBody(body, modifiedArgs)
			if err != nil {
				h.writeJSONRPCError(w, req.ID, ErrCodeScopeViolation, "scope: failed to rebuild request")
				return
			}
			body = newBody
		}

		if scopeCfg.Response != nil {
			scopeResponseCfg = scopeCfg.Response
		}

		h.auditor.Emit(ctx, audit.Event{
			Type:     audit.EventScopeModified,
			Method:   req.Method,
			ToolName: tc.Name,
			Identity: id.Subject,
			Reason:   fmt.Sprintf("stripped=%v injected=%v", mods.StrippedArgs, mods.InjectedArgs),
		})
	}

	// Budget check — if the matched rule has a budget config, enforce it.
	if h.budgets != nil && decision.MatchedRule != nil && decision.MatchedRule.Budget != nil {
		bc := decision.MatchedRule.Budget
		var perID, perSess *budget.Limits
		if bc.PerIdentity != nil {
			perID = &budget.Limits{
				MaxCallsPerHour: bc.PerIdentity.MaxCallsPerHour,
				MaxCallsPerDay:  bc.PerIdentity.MaxCallsPerDay,
				MaxTokensPerDay: bc.PerIdentity.MaxTokensPerDay,
			}
		}
		if bc.PerSession != nil {
			perSess = &budget.Limits{
				MaxCallsPerHour: bc.PerSession.MaxCallsPerHour,
				MaxCallsPerDay:  bc.PerSession.MaxCallsPerDay,
				MaxTokensPerDay: bc.PerSession.MaxTokensPerDay,
			}
		}
		if err := h.budgets.CheckAndRecord(id.Subject, id.SessionID, perID, perSess); err != nil {
			h.auditor.Emit(ctx, audit.Event{
				Type:     audit.EventToolDenied,
				Method:   req.Method,
				ToolName: tc.Name,
				Identity: id.Subject,
				Reason:   "budget exhausted: " + err.Error(),
			})
			h.writeJSONRPCError(w, req.ID, ErrCodeRateLimited, "budget exhausted: "+err.Error())
			return
		}
	}

	h.breaker.Record(id.SessionID)

	if h.velocity != nil {
		if alert := h.velocity.Record(id.Subject, tc.Name); alert != nil {
			h.auditor.Emit(ctx, audit.Event{
				Type:     audit.EventAnomalyVelocity,
				Method:   req.Method,
				ToolName: tc.Name,
				Identity: id.Subject,
				Reason:   fmt.Sprintf("velocity %d/min exceeds threshold %d", alert.CallsPerMin, alert.Threshold),
			})
			if alert.Action == anomaly.AlertActionDeny {
				h.writeJSONRPCError(w, req.ID, ErrCodeRateLimited, fmt.Sprintf("velocity limit exceeded: %d calls/min", alert.CallsPerMin))
				return
			}
		}
	}

	h.auditor.Emit(ctx, audit.Event{
		Type:     audit.EventToolAllowed,
		Method:   req.Method,
		ToolName: tc.Name,
		Identity: id.Subject,
		Args:     tc.Arguments,
	})

	r.Body = io.NopCloser(bytes.NewReader(body))

	if scopeResponseCfg != nil && len(scopeResponseCfg.RedactPatterns) > 0 {
		resp, err := http.Post("http://"+h.upstreamAddr+r.URL.Path, "application/json", io.NopCloser(bytes.NewReader(body)))
		if err != nil {
			h.writeJSONRPCError(w, req.ID, ErrCodeInternal, "scope: upstream request failed")
			return
		}
		defer resp.Body.Close()

		respBody, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		if err != nil {
			h.writeJSONRPCError(w, req.ID, ErrCodeInternal, "scope: failed to read upstream response")
			return
		}

		redacted, count := scope.ModifyResponse(respBody, scopeResponseCfg)
		if count > 0 {
			h.auditor.Emit(ctx, audit.Event{
				Type:     audit.EventScopeModified,
				Method:   req.Method,
				ToolName: tc.Name,
				Identity: id.Subject,
				Reason:   fmt.Sprintf("response: %d patterns redacted", count),
			})
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(resp.StatusCode)
		w.Write(redacted)
	} else {
		h.upstream.ServeHTTP(w, r)
	}
}

// responseRecorder captures the upstream response for post-processing (SCOPE redaction).
type responseRecorder struct {
	http.ResponseWriter
	statusCode    int
	body          *bytes.Buffer
	headerWritten bool
}

func (r *responseRecorder) WriteHeader(code int) {
	r.statusCode = code
	r.headerWritten = true
}

func (r *responseRecorder) Write(b []byte) (int, error) {
	if !r.headerWritten {
		r.statusCode = http.StatusOK
		r.headerWritten = true
	}
	return r.body.Write(b)
}

func (h *Handler) writeJSONRPCError(w http.ResponseWriter, id any, code int, message string) {
	resp := NewErrorResponse(id, code, message)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK) // JSON-RPC errors are 200 at the HTTP layer
	json.NewEncoder(w).Encode(resp)
}
