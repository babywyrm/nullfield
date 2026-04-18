package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"

	"github.com/babywyrm/nullfield/pkg/audit"
	"github.com/babywyrm/nullfield/pkg/circuit"
	"github.com/babywyrm/nullfield/pkg/identity"
	"github.com/babywyrm/nullfield/pkg/policy"
	"github.com/babywyrm/nullfield/pkg/registry"
)

// Handler is the main reverse proxy handler that intercepts MCP traffic.
type Handler struct {
	upstream *httputil.ReverseProxy
	engine   policy.Engine
	auditor  audit.Emitter
	verifier identity.Verifier
	registry *registry.Registry
	breaker  *circuit.Breaker
	logger   *slog.Logger
}

type HandlerOpts struct {
	UpstreamURL *url.URL
	Engine      policy.Engine
	Auditor     audit.Emitter
	Verifier    identity.Verifier
	Registry    *registry.Registry
	Breaker     *circuit.Breaker
	Logger      *slog.Logger
}

func NewHandler(opts HandlerOpts) *Handler {
	proxy := httputil.NewSingleHostReverseProxy(opts.UpstreamURL)
	return &Handler{
		upstream: proxy,
		engine:   opts.Engine,
		auditor:  opts.Auditor,
		verifier: opts.Verifier,
		registry: opts.Registry,
		breaker:  opts.Breaker,
		logger:   opts.Logger,
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

	if !decision.Allowed {
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

	h.breaker.Record(id.SessionID)

	h.auditor.Emit(ctx, audit.Event{
		Type:     audit.EventToolAllowed,
		Method:   req.Method,
		ToolName: tc.Name,
		Identity: id.Subject,
		Args:     tc.Arguments,
	})

	r.Body = io.NopCloser(bytes.NewReader(body))
	h.upstream.ServeHTTP(w, r)
}

func (h *Handler) writeJSONRPCError(w http.ResponseWriter, id any, code int, message string) {
	resp := NewErrorResponse(id, code, message)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK) // JSON-RPC errors are 200 at the HTTP layer
	json.NewEncoder(w).Encode(resp)
}
