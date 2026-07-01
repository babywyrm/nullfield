package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"

	v1alpha1 "github.com/babywyrm/nullfield/api/v1alpha1"
	"github.com/babywyrm/nullfield/pkg/anomaly"
	"github.com/babywyrm/nullfield/pkg/audit"
	"github.com/babywyrm/nullfield/pkg/budget"
	"github.com/babywyrm/nullfield/pkg/circuit"
	"github.com/babywyrm/nullfield/pkg/credentials"
	"github.com/babywyrm/nullfield/pkg/hold"
	"github.com/babywyrm/nullfield/pkg/identity"
	"github.com/babywyrm/nullfield/pkg/policy"
	"github.com/babywyrm/nullfield/pkg/scope"
)

// GatewayHandler routes tool calls to the appropriate upstream based on
// tool name. Identity verification is shared; policy and registry are per-route.
type GatewayHandler struct {
	router      *Router
	auditor     audit.Emitter
	verifier    identity.Verifier
	integrity   *identity.IntegrityChecker
	velocity    *anomaly.VelocityTracker
	budgets     *budget.Tracker
	holds       *hold.Manager
	breaker     *circuit.Breaker
	credentials *credentials.MultiProvider
	logger      *slog.Logger
}

type GatewayHandlerOpts struct {
	Router      *Router
	Auditor     audit.Emitter
	Verifier    identity.Verifier
	Integrity   *identity.IntegrityChecker
	Velocity    *anomaly.VelocityTracker
	Budgets     *budget.Tracker
	Holds       *hold.Manager
	Breaker     *circuit.Breaker
	Credentials *credentials.MultiProvider
	Logger      *slog.Logger
}

func NewGatewayHandler(opts GatewayHandlerOpts) *GatewayHandler {
	return &GatewayHandler{
		router:      opts.Router,
		auditor:     opts.Auditor,
		verifier:    opts.Verifier,
		integrity:   opts.Integrity,
		velocity:    opts.Velocity,
		budgets:     opts.Budgets,
		holds:       opts.Holds,
		breaker:     opts.Breaker,
		credentials: opts.Credentials,
		logger:      opts.Logger,
	}
}

func (g *GatewayHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		writeJSONRPCErr(w, nil, ErrCodeParse, "failed to read request body")
		return
	}
	r.Body = io.NopCloser(bytes.NewReader(body))

	var req JSONRPCRequest
	if err := json.Unmarshal(body, &req); err != nil {
		// Not JSON-RPC — gateway doesn't know where to send non-MCP traffic.
		writeJSONRPCErr(w, nil, ErrCodeParse, "gateway mode requires JSON-RPC requests")
		return
	}

	ctx := r.Context()

	id, err := g.verifier.Verify(r)
	if err != nil {
		g.auditor.Emit(ctx, audit.Event{
			Type:   audit.EventIdentityFailed,
			Method: req.Method,
			Error:  err.Error(),
		})
		writeJSONRPCErr(w, req.ID, ErrCodeIdentityFailed, "identity verification failed")
		return
	}
	if g.integrity != nil {
		if err := g.integrity.Check(id); err != nil {
			writeJSONRPCErr(w, req.ID, ErrCodeIdentityFailed, "integrity check failed: "+err.Error())
			return
		}
	}

	ctx = identity.WithIdentity(ctx, id)

	if req.Method == MethodToolsCall {
		g.handleToolsCall(ctx, w, r, &req, body, id)
		return
	}

	// Non-tools/call: broadcast to first route (or reject).
	if len(g.router.Routes()) > 0 {
		g.auditor.Emit(ctx, audit.Event{
			Type:     audit.EventMCPRequest,
			Method:   req.Method,
			Identity: id.Subject,
		})
		r.Body = io.NopCloser(bytes.NewReader(body))
		g.router.Routes()[0].Upstream.ServeHTTP(w, r)
		return
	}
	writeJSONRPCErr(w, req.ID, ErrCodeInternal, "no routes configured")
}

func (g *GatewayHandler) handleToolsCall(ctx context.Context, w http.ResponseWriter, r *http.Request, req *JSONRPCRequest, body []byte, id *identity.Identity) {
	tc, err := ParseToolsCall(req)
	if err != nil {
		writeJSONRPCErr(w, req.ID, ErrCodeInvalidPar, err.Error())
		return
	}

	route := g.router.Resolve(tc.Name)
	if route == nil {
		g.auditor.Emit(ctx, eventWithIdentity(audit.Event{
			Type:        audit.EventToolDenied,
			Method:      req.Method,
			ToolName:    tc.Name,
			Gate:        "route",
			ReasonClass: "no_route",
			Reason:      "no route for tool",
		}, id))
		writeJSONRPCErr(w, req.ID, ErrCodeToolUnknown, "no route for tool: "+tc.Name)
		return
	}

	g.logger.InfoContext(ctx, "routed tool call", "tool", tc.Name, "route", route.Name, "upstream", route.UpstreamAddr)

	if !route.Registry.IsRegistered(tc.Name) {
		g.auditor.Emit(ctx, eventWithIdentity(audit.Event{
			Type:        audit.EventToolDenied,
			Method:      req.Method,
			ToolName:    tc.Name,
			Gate:        "registry",
			ReasonClass: "tool_not_registered",
			Route:       route.Name,
			Reason:      fmt.Sprintf("tool not registered in route %q", route.Name),
		}, id))
		writeJSONRPCErr(w, req.ID, ErrCodeToolUnknown, fmt.Sprintf("tool not registered in route %q: %s", route.Name, tc.Name))
		return
	}

	if !g.breaker.Allow(id.SessionID) {
		g.auditor.Emit(ctx, eventWithIdentity(audit.Event{
			Type:        audit.EventCircuitTripped,
			Method:      req.Method,
			ToolName:    tc.Name,
			Gate:        "circuit",
			ReasonClass: "circuit_open",
			Route:       route.Name,
		}, id))
		writeJSONRPCErr(w, req.ID, ErrCodeCircuitOpen, "circuit breaker open — session limit exceeded")
		return
	}

	decision := route.Engine.Evaluate(ctx, policy.Request{
		Method:    req.Method,
		ToolName:  tc.Name,
		Arguments: tc.Arguments,
		Identity:  id,
	})

	if decision.Held && g.holds != nil && decision.MatchedRule != nil && decision.MatchedRule.Hold != nil {
		holdCfg := decision.MatchedRule.Hold
		timeout := 5 * time.Minute
		if holdCfg.Timeout != "" {
			if parsed, err := time.ParseDuration(holdCfg.Timeout); err == nil {
				timeout = parsed
			}
		}

		holdID, ch := g.holds.Hold(tc.Name, tc.Arguments, id.Subject, id.SessionID, decision.Reason, timeout)
		g.auditor.Emit(ctx, eventWithDecision(audit.Event{
			Type:     audit.EventHoldCreated,
			Method:   req.Method,
			ToolName: tc.Name,
			Route:    route.Name,
			Reason:   fmt.Sprintf("held: %s (id=%s, route=%s)", decision.Reason, holdID, route.Name),
		}, decision, id))

		resolution := <-ch
		if !resolution.Approved {
			g.auditor.Emit(ctx, eventWithDecision(audit.Event{
				Type:        audit.EventToolDenied,
				Method:      req.Method,
				ToolName:    tc.Name,
				Gate:        "hold",
				ReasonClass: holdReasonClass(resolution.By),
				Route:       route.Name,
				Reason:      fmt.Sprintf("hold %s: denied by %s", holdID, resolution.By),
			}, decision, id))
			if resolution.By == "timeout" {
				writeJSONRPCErr(w, req.ID, ErrCodeHoldTimeout, "hold timed out without approval")
			} else {
				writeJSONRPCErr(w, req.ID, ErrCodePolicyDenied, "hold denied by "+resolution.By)
			}
			return
		}
	} else if !decision.Allowed {
		g.auditor.Emit(ctx, eventWithDecision(audit.Event{
			Type:     audit.EventToolDenied,
			Method:   req.Method,
			ToolName: tc.Name,
			Route:    route.Name,
			Reason:   decision.Reason,
		}, decision, id))
		writeJSONRPCErr(w, req.ID, ErrCodePolicyDenied, "denied by policy: "+decision.Reason)
		return
	}

	// SCOPE — request modification + credential injection.
	var scopeResponseCfg *v1alpha1.ScopeResponseConfig
	if decision.Scoped && decision.MatchedRule != nil && decision.MatchedRule.Scope != nil {
		scopeCfg := decision.MatchedRule.Scope
		var mods scope.Modifications

		if scopeCfg.Request != nil {
			var modifiedArgs map[string]any
			modifiedArgs, mods = scope.ModifyRequest(tc.Arguments, scopeCfg.Request)

			if g.credentials != nil && len(scopeCfg.Request.InjectCredentials) > 0 {
				for _, cred := range scopeCfg.Request.InjectCredentials {
					val, err := g.credentials.FetchFrom(ctx, cred.From, cred.SecretRef)
					if err != nil {
						writeJSONRPCErr(w, req.ID, ErrCodeScopeViolation, "scope: credential injection failed")
						return
					}
					key := cred.InjectAs
					if key == "" {
						key = cred.SecretRef
					}
					modifiedArgs[key] = val
					mods.InjectedArgs = append(mods.InjectedArgs, key)
				}
			}

			tc.Arguments = modifiedArgs
			newBody, err := scope.RebuildRequestBody(body, modifiedArgs)
			if err != nil {
				writeJSONRPCErr(w, req.ID, ErrCodeScopeViolation, "scope: failed to rebuild request")
				return
			}
			body = newBody
		}

		if scopeCfg.Response != nil {
			scopeResponseCfg = scopeCfg.Response
		}

		g.auditor.Emit(ctx, eventWithDecision(audit.Event{
			Type:     audit.EventScopeModified,
			Method:   req.Method,
			ToolName: tc.Name,
			Route:    route.Name,
			Reason:   fmt.Sprintf("stripped=%v injected=%v route=%s", mods.StrippedArgs, mods.InjectedArgs, route.Name),
		}, decision, id))
	}

	// Budget check.
	if g.budgets != nil && decision.MatchedRule != nil && decision.MatchedRule.Budget != nil {
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
		if err := g.budgets.CheckAndRecord(id.Subject, id.SessionID, perID, perSess); err != nil {
			g.auditor.Emit(ctx, eventWithDecision(audit.Event{
				Type:        audit.EventToolDenied,
				Method:      req.Method,
				ToolName:    tc.Name,
				Gate:        "budget",
				ReasonClass: "budget_exhausted",
				Route:       route.Name,
				Reason:      "budget exhausted: " + err.Error(),
			}, decision, id))
			writeJSONRPCErr(w, req.ID, ErrCodeRateLimited, "budget exhausted: "+err.Error())
			return
		}
	}

	g.breaker.Record(id.SessionID)

	if g.velocity != nil {
		if alert := g.velocity.Record(id.Subject, tc.Name); alert != nil {
			g.auditor.Emit(ctx, eventWithDecision(audit.Event{
				Type:        audit.EventAnomalyVelocity,
				Method:      req.Method,
				ToolName:    tc.Name,
				Gate:        "anomaly",
				ReasonClass: "velocity_limit",
				Route:       route.Name,
				Reason:      fmt.Sprintf("velocity %d/min exceeds threshold %d", alert.CallsPerMin, alert.Threshold),
			}, decision, id))
			if alert.Action == anomaly.AlertActionDeny {
				writeJSONRPCErr(w, req.ID, ErrCodeRateLimited, fmt.Sprintf("velocity limit exceeded: %d calls/min", alert.CallsPerMin))
				return
			}
		}
	}

	g.auditor.Emit(ctx, eventWithDecision(audit.Event{
		Type:     audit.EventToolAllowed,
		Method:   req.Method,
		ToolName: tc.Name,
		Route:    route.Name,
		Args:     tc.Arguments,
	}, decision, id))

	r.Body = io.NopCloser(bytes.NewReader(body))

	if scopeResponseCfg != nil && len(scopeResponseCfg.RedactPatterns) > 0 {
		resp, err := http.Post("http://"+route.UpstreamAddr+r.URL.Path, "application/json", io.NopCloser(bytes.NewReader(body)))
		if err != nil {
			writeJSONRPCErr(w, req.ID, ErrCodeInternal, "scope: upstream request failed")
			return
		}
		defer resp.Body.Close()

		respBody, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		if err != nil {
			writeJSONRPCErr(w, req.ID, ErrCodeInternal, "scope: failed to read upstream response")
			return
		}

		redacted, _ := scope.ModifyResponse(respBody, scopeResponseCfg)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(resp.StatusCode)
		w.Write(redacted)
	} else {
		route.Upstream.ServeHTTP(w, r)
	}
}

func writeJSONRPCErr(w http.ResponseWriter, id any, code int, message string) {
	resp := NewErrorResponse(id, code, message)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(resp)
}
