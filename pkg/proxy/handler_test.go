package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"testing"

	v1alpha1 "github.com/babywyrm/nullfield/api/v1alpha1"
	"github.com/babywyrm/nullfield/pkg/audit"
	"github.com/babywyrm/nullfield/pkg/circuit"
	"github.com/babywyrm/nullfield/pkg/identity"
	"github.com/babywyrm/nullfield/pkg/inspection"
	"github.com/babywyrm/nullfield/pkg/policy"
	"github.com/babywyrm/nullfield/pkg/registry"
)

// noopEmitter satisfies audit.Emitter without any side-effects.
type noopEmitter struct{}

func (n *noopEmitter) Emit(_ context.Context, _ audit.Event) {}

type captureEmitter struct {
	events []audit.Event
}

func (c *captureEmitter) Emit(_ context.Context, event audit.Event) {
	c.events = append(c.events, event)
}

// allowAllEngine unconditionally allows every request.
type allowAllEngine struct{}

func (a allowAllEngine) Evaluate(_ context.Context, _ policy.Request) policy.Decision {
	return policy.Decision{Allowed: true}
}

// denyAllEngine unconditionally denies every request.
type denyAllEngine struct{}

func (d denyAllEngine) Evaluate(_ context.Context, _ policy.Request) policy.Decision {
	return policy.Decision{Allowed: false, Reason: "test deny"}
}

// inspectEngine allows requests and attaches an inspection config to the matched rule.
type inspectEngine struct {
	onFinding string
}

func (e inspectEngine) Evaluate(_ context.Context, _ policy.Request) policy.Decision {
	return policy.Decision{
		Allowed: true,
		MatchedRule: &v1alpha1.Rule{
			Action: v1alpha1.ActionAllow,
			Inspection: &v1alpha1.InspectionConfig{
				Enabled:           true,
				DetectCredentials: true,
				DetectPII:         true,
				DetectPromptLeak:  true,
				DetectPaths:       true,
				OnFinding:         e.onFinding,
			},
		},
	}
}

// discardLogger returns a logger that throws away all output.
func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// makeHandler builds a Handler wired to the given upstream test server.
// "test_tool" is pre-registered so policy evaluation is reachable.
func makeHandler(t *testing.T, upstream *httptest.Server, engine policy.Engine, verifier identity.Verifier) *Handler {
	t.Helper()
	upstreamURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parse upstream URL: %v", err)
	}
	reg := registry.New()
	reg.Register(v1alpha1.ToolRegistryEntry{Name: "test_tool"})
	return NewHandler(HandlerOpts{
		UpstreamURL: upstreamURL,
		Engine:      engine,
		Auditor:     &noopEmitter{},
		Verifier:    verifier,
		Registry:    reg,
		Breaker:     circuit.New(1000, 0),
		Logger:      discardLogger(),
	})
}

// toolsCallBody encodes a minimal tools/call JSON-RPC request.
func toolsCallBody(toolName string) []byte {
	req := JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      1,
		Method:  MethodToolsCall,
		Params:  json.RawMessage(`{"name":"` + toolName + `","arguments":{}}`),
	}
	b, _ := json.Marshal(req)
	return b
}

// decodeJSONRPC decodes the recorder body into a JSONRPCResponse.
func decodeJSONRPC(t *testing.T, w *httptest.ResponseRecorder) *JSONRPCResponse {
	t.Helper()
	var resp JSONRPCResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode JSON-RPC response: %v", err)
	}
	return &resp
}

// --------------------------------------------------------------------------
// Handler tests
// --------------------------------------------------------------------------

func TestHandler_PermissivePolicyPassesThrough(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{}}`))
	}))
	defer upstream.Close()

	h := makeHandler(t, upstream, allowAllEngine{}, &identity.NoopVerifier{})

	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(toolsCallBody("test_tool")))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected HTTP 200, got %d", w.Code)
	}
	resp := decodeJSONRPC(t, w)
	if resp.Error != nil {
		t.Errorf("expected no JSON-RPC error, got: %+v", resp.Error)
	}
}

func TestHandler_DenyingPolicyReturnsError(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	h := makeHandler(t, upstream, denyAllEngine{}, &identity.NoopVerifier{})

	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(toolsCallBody("test_tool")))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("JSON-RPC errors must still return HTTP 200, got %d", w.Code)
	}
	resp := decodeJSONRPC(t, w)
	if resp.Error == nil {
		t.Fatal("expected JSON-RPC error in response")
	}
	if resp.Error.Code != ErrCodePolicyDenied {
		t.Errorf("expected ErrCodePolicyDenied (%d), got %d", ErrCodePolicyDenied, resp.Error.Code)
	}
}

func TestHandler_AuditEventIncludesPolicyDecisionContext(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	upstreamURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parse upstream URL: %v", err)
	}
	reg := registry.New()
	reg.Register(v1alpha1.ToolRegistryEntry{Name: "test_tool"})
	auditor := &captureEmitter{}
	engine := policy.NewRuleEngine([]v1alpha1.Rule{
		{ID: "read-only", Action: v1alpha1.ActionAllow, MCPMethod: MethodToolsCall, ToolNames: []string{"safe_tool"}},
		{ID: "deny-default", Action: v1alpha1.ActionDeny, MCPMethod: MethodToolsCall, ToolNames: []string{"*"}, Reason: "not an approved path"},
	})
	h := NewHandler(HandlerOpts{
		UpstreamURL: upstreamURL,
		Engine:      engine,
		Auditor:     auditor,
		Verifier:    &identity.NoopVerifier{},
		Registry:    reg,
		Breaker:     circuit.New(1000, 0),
		Logger:      discardLogger(),
	})

	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(toolsCallBody("test_tool")))
	req.Header.Set("Mcp-Session-Id", "session-123")
	w := httptest.NewRecorder()

	h.ServeHTTP(w, req)

	var denied *audit.Event
	for i := range auditor.events {
		if auditor.events[i].Type == audit.EventToolDenied {
			denied = &auditor.events[i]
			break
		}
	}
	if denied == nil {
		t.Fatalf("expected tool.denied audit event, got %+v", auditor.events)
	}
	if denied.Gate != "policy" {
		t.Fatalf("Gate = %q, want policy", denied.Gate)
	}
	if denied.ReasonClass != "policy_denied" {
		t.Fatalf("ReasonClass = %q, want policy_denied", denied.ReasonClass)
	}
	if denied.RuleID != "deny-default" {
		t.Fatalf("RuleID = %q, want deny-default", denied.RuleID)
	}
	if denied.RuleIndex == nil || *denied.RuleIndex != 1 {
		t.Fatalf("RuleIndex = %v, want 1", denied.RuleIndex)
	}
	if denied.SessionID != "session-123" {
		t.Fatalf("SessionID = %q, want session-123", denied.SessionID)
	}
}

func TestHandler_MissingIdentityHeaderReturnsError(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	verifier := identity.NewHeaderVerifier("X-Identity")
	h := makeHandler(t, upstream, allowAllEngine{}, verifier)

	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(toolsCallBody("test_tool")))
	// No X-Identity header intentionally.
	w := httptest.NewRecorder()

	h.ServeHTTP(w, req)

	resp := decodeJSONRPC(t, w)
	if resp.Error == nil {
		t.Fatal("expected JSON-RPC error for missing identity header")
	}
	if resp.Error.Code != ErrCodeIdentityFailed {
		t.Errorf("expected ErrCodeIdentityFailed (%d), got %d", ErrCodeIdentityFailed, resp.Error.Code)
	}
}

func TestHandler_NonToolsCallPassesThrough(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"tools":[]}}`))
	}))
	defer upstream.Close()

	// Even with a deny engine, tools/list should be proxied without policy check.
	h := makeHandler(t, upstream, denyAllEngine{}, &identity.NoopVerifier{})

	listBody, _ := json.Marshal(JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      1,
		Method:  MethodToolsList,
	})
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(listBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected HTTP 200 for tools/list, got %d", w.Code)
	}
	resp := decodeJSONRPC(t, w)
	if resp.Error != nil {
		t.Errorf("tools/list must not be policy-blocked: %+v", resp.Error)
	}
}

func TestHandler_NonJSONBodyPassesThrough(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("pong"))
	}))
	defer upstream.Close()

	h := makeHandler(t, upstream, allowAllEngine{}, &identity.NoopVerifier{})

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	w := httptest.NewRecorder()

	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected HTTP 200 for non-JSON body, got %d", w.Code)
	}
}

func TestHandler_UnregisteredToolReturnsError(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	h := makeHandler(t, upstream, allowAllEngine{}, &identity.NoopVerifier{})

	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(toolsCallBody("unknown_tool")))
	w := httptest.NewRecorder()

	h.ServeHTTP(w, req)

	resp := decodeJSONRPC(t, w)
	if resp.Error == nil {
		t.Fatal("expected JSON-RPC error for unregistered tool")
	}
	if resp.Error.Code != ErrCodeToolUnknown {
		t.Errorf("expected ErrCodeToolUnknown (%d), got %d", ErrCodeToolUnknown, resp.Error.Code)
	}
}

func TestHandler_InvalidToolsCallParamsReturnsError(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	h := makeHandler(t, upstream, allowAllEngine{}, &identity.NoopVerifier{})

	// tools/call with missing tool name.
	badBody, _ := json.Marshal(JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      1,
		Method:  MethodToolsCall,
		Params:  json.RawMessage(`{"arguments":{}}`),
	})
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(badBody))
	w := httptest.NewRecorder()

	h.ServeHTTP(w, req)

	resp := decodeJSONRPC(t, w)
	if resp.Error == nil {
		t.Fatal("expected JSON-RPC error for invalid params")
	}
	if resp.Error.Code != ErrCodeInvalidPar {
		t.Errorf("expected ErrCodeInvalidPar (%d), got %d", ErrCodeInvalidPar, resp.Error.Code)
	}
}

// --------------------------------------------------------------------------
// GatewayHandler tests
// --------------------------------------------------------------------------

func makeGateway(router *Router, verifier identity.Verifier) *GatewayHandler {
	return NewGatewayHandler(GatewayHandlerOpts{
		Router:   router,
		Auditor:  &noopEmitter{},
		Verifier: verifier,
		Breaker:  circuit.New(1000, 0),
		Logger:   discardLogger(),
	})
}

func TestGatewayHandler_NonJSONRPCReturnsError(t *testing.T) {
	g := makeGateway(NewRouter([]*Route{}), &identity.NoopVerifier{})

	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader([]byte("not json at all")))
	w := httptest.NewRecorder()

	g.ServeHTTP(w, req)

	resp := decodeJSONRPC(t, w)
	if resp.Error == nil {
		t.Fatal("expected error for non-JSON-RPC body in gateway mode")
	}
	if resp.Error.Code != ErrCodeParse {
		t.Errorf("expected ErrCodeParse (%d), got %d", ErrCodeParse, resp.Error.Code)
	}
}

func TestGatewayHandler_NoRouteForTool(t *testing.T) {
	g := makeGateway(NewRouter([]*Route{}), &identity.NoopVerifier{})

	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(toolsCallBody("some_tool")))
	w := httptest.NewRecorder()

	g.ServeHTTP(w, req)

	resp := decodeJSONRPC(t, w)
	if resp.Error == nil {
		t.Fatal("expected error when no route configured for tool")
	}
	if resp.Error.Code != ErrCodeToolUnknown {
		t.Errorf("expected ErrCodeToolUnknown (%d), got %d", ErrCodeToolUnknown, resp.Error.Code)
	}
}

func TestGatewayHandler_PolicyDenied(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	upstreamURL, _ := url.Parse(upstream.URL)
	reg := registry.New()
	reg.Register(v1alpha1.ToolRegistryEntry{Name: "test_tool"})

	route := &Route{
		Name:         "test",
		Upstream:     httputil.NewSingleHostReverseProxy(upstreamURL),
		UpstreamAddr: upstreamURL.Host,
		ToolNames:    []string{"test_tool"},
		Engine:       denyAllEngine{},
		Registry:     reg,
	}

	g := makeGateway(NewRouter([]*Route{route}), &identity.NoopVerifier{})

	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(toolsCallBody("test_tool")))
	w := httptest.NewRecorder()

	g.ServeHTTP(w, req)

	resp := decodeJSONRPC(t, w)
	if resp.Error == nil {
		t.Fatal("expected JSON-RPC error for denied policy")
	}
	if resp.Error.Code != ErrCodePolicyDenied {
		t.Errorf("expected ErrCodePolicyDenied (%d), got %d", ErrCodePolicyDenied, resp.Error.Code)
	}
}

func TestGatewayHandler_IdentityFailed(t *testing.T) {
	g := makeGateway(NewRouter([]*Route{}), identity.NewHeaderVerifier("X-Token"))

	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(toolsCallBody("test_tool")))
	// No X-Token header.
	w := httptest.NewRecorder()

	g.ServeHTTP(w, req)

	resp := decodeJSONRPC(t, w)
	if resp.Error == nil {
		t.Fatal("expected error for missing identity header in gateway")
	}
	if resp.Error.Code != ErrCodeIdentityFailed {
		t.Errorf("expected ErrCodeIdentityFailed (%d), got %d", ErrCodeIdentityFailed, resp.Error.Code)
	}
}

func TestGatewayHandler_NoRoutesNonToolsCall(t *testing.T) {
	g := makeGateway(NewRouter([]*Route{}), &identity.NoopVerifier{})

	listBody, _ := json.Marshal(JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      1,
		Method:  MethodToolsList,
	})
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(listBody))
	w := httptest.NewRecorder()

	g.ServeHTTP(w, req)

	resp := decodeJSONRPC(t, w)
	if resp.Error == nil {
		t.Fatal("expected error when no routes configured for non-tools/call")
	}
	if resp.Error.Code != ErrCodeInternal {
		t.Errorf("expected ErrCodeInternal (%d), got %d", ErrCodeInternal, resp.Error.Code)
	}
}

func TestGatewayHandler_ToolNotRegisteredInRoute(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	upstreamURL, _ := url.Parse(upstream.URL)
	// Registry has no tools registered.
	reg := registry.New()

	route := &Route{
		Name:         "empty",
		Upstream:     httputil.NewSingleHostReverseProxy(upstreamURL),
		UpstreamAddr: upstreamURL.Host,
		ToolNames:    []string{"test_tool"},
		Engine:       allowAllEngine{},
		Registry:     reg,
	}

	g := makeGateway(NewRouter([]*Route{route}), &identity.NoopVerifier{})

	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(toolsCallBody("test_tool")))
	w := httptest.NewRecorder()

	g.ServeHTTP(w, req)

	resp := decodeJSONRPC(t, w)
	if resp.Error == nil {
		t.Fatal("expected error for tool not in route registry")
	}
	if resp.Error.Code != ErrCodeToolUnknown {
		t.Errorf("expected ErrCodeToolUnknown (%d), got %d", ErrCodeToolUnknown, resp.Error.Code)
	}
}

// --------------------------------------------------------------------------
// Circuit breaker
// --------------------------------------------------------------------------

func TestHandler_CircuitBreakerTripped(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{}}`))
	}))
	defer upstream.Close()

	upstreamURL, _ := url.Parse(upstream.URL)
	reg := registry.New()
	reg.Register(v1alpha1.ToolRegistryEntry{Name: "test_tool"})

	h := NewHandler(HandlerOpts{
		UpstreamURL: upstreamURL,
		Engine:      allowAllEngine{},
		Auditor:     &noopEmitter{},
		Verifier:    &identity.NoopVerifier{},
		Registry:    reg,
		Breaker:     circuit.New(1, 0), // limit of 1 call per session
		Logger:      discardLogger(),
	})

	// First call: allowed and recorded.
	req1 := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(toolsCallBody("test_tool")))
	req1.Header.Set("Mcp-Session-Id", "circuit-sess")
	w1 := httptest.NewRecorder()
	h.ServeHTTP(w1, req1)
	if w1.Code != http.StatusOK {
		t.Fatalf("first call unexpected HTTP status: %d", w1.Code)
	}

	// Second call with same session: circuit should be open.
	req2 := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(toolsCallBody("test_tool")))
	req2.Header.Set("Mcp-Session-Id", "circuit-sess")
	w2 := httptest.NewRecorder()
	h.ServeHTTP(w2, req2)

	resp2 := decodeJSONRPC(t, w2)
	if resp2.Error == nil {
		t.Fatal("expected circuit breaker error on second call")
	}
	if resp2.Error.Code != ErrCodeCircuitOpen {
		t.Errorf("expected ErrCodeCircuitOpen (%d), got %d", ErrCodeCircuitOpen, resp2.Error.Code)
	}
}

func TestGatewayHandler_CircuitBreakerTripped(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{}}`))
	}))
	defer upstream.Close()

	upstreamURL, _ := url.Parse(upstream.URL)
	reg := registry.New()
	reg.Register(v1alpha1.ToolRegistryEntry{Name: "test_tool"})

	route := &Route{
		Name:         "breaker-route",
		Upstream:     httputil.NewSingleHostReverseProxy(upstreamURL),
		UpstreamAddr: upstreamURL.Host,
		ToolNames:    []string{"test_tool"},
		Engine:       allowAllEngine{},
		Registry:     reg,
	}

	g := NewGatewayHandler(GatewayHandlerOpts{
		Router:   NewRouter([]*Route{route}),
		Auditor:  &noopEmitter{},
		Verifier: &identity.NoopVerifier{},
		Breaker:  circuit.New(1, 0),
		Logger:   discardLogger(),
	})

	// First call succeeds.
	req1 := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(toolsCallBody("test_tool")))
	req1.Header.Set("Mcp-Session-Id", "gw-circ")
	w1 := httptest.NewRecorder()
	g.ServeHTTP(w1, req1)

	// Second call should trip the breaker.
	req2 := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(toolsCallBody("test_tool")))
	req2.Header.Set("Mcp-Session-Id", "gw-circ")
	w2 := httptest.NewRecorder()
	g.ServeHTTP(w2, req2)

	resp2 := decodeJSONRPC(t, w2)
	if resp2.Error == nil {
		t.Fatal("expected circuit breaker error in gateway")
	}
	if resp2.Error.Code != ErrCodeCircuitOpen {
		t.Errorf("expected ErrCodeCircuitOpen (%d), got %d", ErrCodeCircuitOpen, resp2.Error.Code)
	}
}

// --------------------------------------------------------------------------
// BuildRoute
// --------------------------------------------------------------------------

func TestBuildRoute_Valid(t *testing.T) {
	route, err := BuildRoute(RouteConfig{
		Name:      "my-route",
		Upstream:  "localhost:8080",
		ToolNames: []string{"my_tool"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if route.Name != "my-route" {
		t.Errorf("expected Name %q, got %q", "my-route", route.Name)
	}
	if route.UpstreamAddr != "localhost:8080" {
		t.Errorf("expected UpstreamAddr %q, got %q", "localhost:8080", route.UpstreamAddr)
	}
}

func TestBuildRoute_EmptyUpstream(t *testing.T) {
	_, err := BuildRoute(RouteConfig{Name: "bad-route"})
	if err == nil {
		t.Fatal("expected error for empty upstream")
	}
}

func TestBuildRoute_WithToolPrefix(t *testing.T) {
	route, err := BuildRoute(RouteConfig{
		Name:       "prefix-route",
		Upstream:   "localhost:9000",
		ToolPrefix: "pfx.",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if route.ToolPrefix != "pfx." {
		t.Errorf("expected ToolPrefix %q, got %q", "pfx.", route.ToolPrefix)
	}
}

func TestBuildRoute_InvalidRegistryFile(t *testing.T) {
	_, err := BuildRoute(RouteConfig{
		Name:         "bad-reg",
		Upstream:     "localhost:8080",
		RegistryFile: "/nonexistent/registry.yaml",
	})
	if err == nil {
		t.Fatal("expected error for non-existent registry file")
	}
}

func TestBuildRoute_InvalidPolicyFile(t *testing.T) {
	_, err := BuildRoute(RouteConfig{
		Name:       "bad-policy",
		Upstream:   "localhost:8080",
		PolicyFile: "/nonexistent/policy.yaml",
	})
	if err == nil {
		t.Fatal("expected error for non-existent policy file")
	}
}

// --------------------------------------------------------------------------
// LoadGatewayConfig
// --------------------------------------------------------------------------

func writeTemp(t *testing.T, content string) string {
	t.Helper()
	f, err := os.CreateTemp("", "gw-*.yaml")
	if err != nil {
		t.Fatalf("create temp file: %v", err)
	}
	t.Cleanup(func() { os.Remove(f.Name()) })
	f.WriteString(content)
	f.Close()
	return f.Name()
}

func TestLoadGatewayConfig_Valid(t *testing.T) {
	path := writeTemp(t, `
gateway:
  routes:
    - name: my-route
      upstream: localhost:9000
      toolPrefix: my.
`)
	cfg, err := LoadGatewayConfig(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cfg.Gateway.Routes) != 1 {
		t.Errorf("expected 1 route, got %d", len(cfg.Gateway.Routes))
	}
	if cfg.Gateway.Routes[0].Name != "my-route" {
		t.Errorf("expected route name %q, got %q", "my-route", cfg.Gateway.Routes[0].Name)
	}
}

func TestLoadGatewayConfig_MissingFile(t *testing.T) {
	_, err := LoadGatewayConfig("/nonexistent/path.yaml")
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestLoadGatewayConfig_NoRoutes(t *testing.T) {
	path := writeTemp(t, "gateway:\n  routes: []\n")
	_, err := LoadGatewayConfig(path)
	if err == nil {
		t.Fatal("expected error for config with no routes")
	}
}

func TestLoadGatewayConfig_MissingRouteName(t *testing.T) {
	path := writeTemp(t, `
gateway:
  routes:
    - upstream: localhost:9000
      toolPrefix: x.
`)
	_, err := LoadGatewayConfig(path)
	if err == nil {
		t.Fatal("expected error for route with no name")
	}
}

func TestLoadGatewayConfig_MissingUpstream(t *testing.T) {
	path := writeTemp(t, `
gateway:
  routes:
    - name: my-route
      toolPrefix: x.
`)
	_, err := LoadGatewayConfig(path)
	if err == nil {
		t.Fatal("expected error for route with no upstream")
	}
}

func TestLoadGatewayConfig_MissingToolMatch(t *testing.T) {
	path := writeTemp(t, `
gateway:
  routes:
    - name: my-route
      upstream: localhost:9000
`)
	_, err := LoadGatewayConfig(path)
	if err == nil {
		t.Fatal("expected error when neither toolPrefix nor toolNames is set")
	}
}

// --------------------------------------------------------------------------
// GatewayHandler allowed path passes through to upstream
// --------------------------------------------------------------------------

func TestGatewayHandler_AllowedPassesThrough(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"content":"ok"}}`))
	}))
	defer upstream.Close()

	upstreamURL, _ := url.Parse(upstream.URL)
	reg := registry.New()
	reg.Register(v1alpha1.ToolRegistryEntry{Name: "test_tool"})

	route := &Route{
		Name:         "allow-route",
		Upstream:     httputil.NewSingleHostReverseProxy(upstreamURL),
		UpstreamAddr: upstreamURL.Host,
		ToolNames:    []string{"test_tool"},
		Engine:       allowAllEngine{},
		Registry:     reg,
	}

	g := makeGateway(NewRouter([]*Route{route}), &identity.NoopVerifier{})

	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(toolsCallBody("test_tool")))
	w := httptest.NewRecorder()

	g.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected HTTP 200, got %d", w.Code)
	}
	resp := decodeJSONRPC(t, w)
	if resp.Error != nil {
		t.Errorf("expected no JSON-RPC error, got: %+v", resp.Error)
	}
}

// --------------------------------------------------------------------------
// Handler: RuleEngine-based allow (exercises policy.NewRuleEngine code path)
// --------------------------------------------------------------------------

func TestHandler_RuleEngineAllow(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{}}`))
	}))
	defer upstream.Close()

	upstreamURL, _ := url.Parse(upstream.URL)
	reg := registry.New()
	reg.Register(v1alpha1.ToolRegistryEntry{Name: "test_tool"})

	engine := policy.NewRuleEngine([]v1alpha1.Rule{
		{Action: v1alpha1.ActionAllow, ToolNames: []string{"*"}},
	})

	h := NewHandler(HandlerOpts{
		UpstreamURL: upstreamURL,
		Engine:      engine,
		Auditor:     &noopEmitter{},
		Verifier:    &identity.NoopVerifier{},
		Registry:    reg,
		Breaker:     circuit.New(1000, 0),
		Logger:      discardLogger(),
	})

	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(toolsCallBody("test_tool")))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected HTTP 200, got %d", w.Code)
	}
	resp := decodeJSONRPC(t, w)
	if resp.Error != nil {
		t.Errorf("rule engine allow path should not error: %+v", resp.Error)
	}
}

// --------------------------------------------------------------------------
// Response Inspection
// --------------------------------------------------------------------------

func makeHandlerWithInspector(t *testing.T, upstream *httptest.Server, engine policy.Engine) *Handler {
	t.Helper()
	upstreamURL, _ := url.Parse(upstream.URL)
	reg := registry.New()
	reg.Register(v1alpha1.ToolRegistryEntry{Name: "test_tool"})
	return NewHandler(HandlerOpts{
		UpstreamURL: upstreamURL,
		Engine:      engine,
		Auditor:     &noopEmitter{},
		Verifier:    &identity.NoopVerifier{},
		Registry:    reg,
		Breaker:     circuit.New(1000, 0),
		Inspector:   inspection.New(inspection.DefaultConfig()),
		Logger:      discardLogger(),
	})
}

func TestHandler_InspectionRedactsCredentials(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"content":"password: supersecretval123"}}`))
	}))
	defer upstream.Close()

	h := makeHandlerWithInspector(t, upstream, inspectEngine{onFinding: "REDACT"})

	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(toolsCallBody("test_tool")))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	body := w.Body.String()
	if strings.Contains(body, "supersecretval123") {
		t.Fatal("expected credential to be redacted from response")
	}
	if !strings.Contains(body, "[REDACTED]") {
		t.Fatal("expected [REDACTED] placeholder in response")
	}
}

func TestHandler_InspectionDeniesOnFinding(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"content":"SSN: 123-45-6789"}}`))
	}))
	defer upstream.Close()

	h := makeHandlerWithInspector(t, upstream, inspectEngine{onFinding: "DENY"})

	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(toolsCallBody("test_tool")))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	resp := decodeJSONRPC(t, w)
	if resp.Error == nil {
		t.Fatal("expected JSON-RPC error for inspection DENY")
	}
	if resp.Error.Code != ErrCodeInspectionBlock {
		t.Errorf("expected ErrCodeInspectionBlock (%d), got %d", ErrCodeInspectionBlock, resp.Error.Code)
	}
}

func TestHandler_InspectionAllowsCleanResponse(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"content":"The weather is sunny."}}`))
	}))
	defer upstream.Close()

	h := makeHandlerWithInspector(t, upstream, inspectEngine{onFinding: "DENY"})

	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(toolsCallBody("test_tool")))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	resp := decodeJSONRPC(t, w)
	if resp.Error != nil {
		t.Errorf("clean response should not trigger inspection block: %+v", resp.Error)
	}
}

func TestHandler_InspectionAuditOnlyMode(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"content":"password: leakedsecret99"}}`))
	}))
	defer upstream.Close()

	h := makeHandlerWithInspector(t, upstream, inspectEngine{onFinding: "AUDIT"})

	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(toolsCallBody("test_tool")))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	body := w.Body.String()
	if !strings.Contains(body, "leakedsecret99") {
		t.Fatal("AUDIT mode should not modify the response")
	}
}

func TestHandler_NoInspectorSkipsInspection(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"content":"password: shouldpassthrough"}}`))
	}))
	defer upstream.Close()

	h := makeHandler(t, upstream, allowAllEngine{}, &identity.NoopVerifier{})

	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(toolsCallBody("test_tool")))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	body := w.Body.String()
	if !strings.Contains(body, "shouldpassthrough") {
		t.Fatal("without inspector, response should pass through unmodified")
	}
}

func TestHandler_InspectionRedactsPromptLeak(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"content":"System prompt: You are an AI assistant that helps with hacking"}}`))
	}))
	defer upstream.Close()

	h := makeHandlerWithInspector(t, upstream, inspectEngine{onFinding: "REDACT"})

	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(toolsCallBody("test_tool")))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	body := w.Body.String()
	if strings.Contains(body, "You are an AI assistant") {
		t.Fatal("expected prompt leak to be redacted")
	}
}

func TestHandler_InspectionRedactsInternalPaths(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"content":"token at /var/run/secrets/kubernetes/serviceaccount/token"}}`))
	}))
	defer upstream.Close()

	h := makeHandlerWithInspector(t, upstream, inspectEngine{onFinding: "REDACT"})

	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(toolsCallBody("test_tool")))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	body := w.Body.String()
	if strings.Contains(body, "/var/run/secrets/kubernetes") {
		t.Fatal("expected k8s path to be redacted")
	}
}
