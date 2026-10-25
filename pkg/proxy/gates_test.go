package proxy

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	v1alpha1 "github.com/babywyrm/nullfield/api/v1alpha1"
	"github.com/babywyrm/nullfield/pkg/anomaly"
	"github.com/babywyrm/nullfield/pkg/audit"
	"github.com/babywyrm/nullfield/pkg/budget"
	"github.com/babywyrm/nullfield/pkg/circuit"
	"github.com/babywyrm/nullfield/pkg/identity"
	"github.com/babywyrm/nullfield/pkg/policy"
	"github.com/babywyrm/nullfield/pkg/registry"
)

// The proxy and the gateway run the same gates after policy. Every case here
// runs against both.

type gated struct {
	rule     v1alpha1.Rule
	budgets  *budget.Tracker
	velocity *anomaly.VelocityTracker
}

func frontDoors(t *testing.T, g gated, rec *captureEmitter) map[string]http.Handler {
	t.Helper()
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{}}`))
	}))
	t.Cleanup(upstream.Close)
	u, _ := url.Parse(upstream.URL)
	reg := registry.New()
	reg.Register(v1alpha1.ToolRegistryEntry{Name: "test_tool"})
	engine := policy.NewRuleEngine([]v1alpha1.Rule{g.rule})

	return map[string]http.Handler{
		"proxy": NewHandler(HandlerOpts{
			UpstreamURL: u, Engine: engine, Auditor: rec, Verifier: &identity.NoopVerifier{},
			Registry: reg, Breaker: circuit.New(1000, 0), Budgets: g.budgets, Velocity: g.velocity,
			Logger: discardLogger(),
		}),
		"gateway": NewGatewayHandler(GatewayHandlerOpts{
			Router: NewRouter([]*Route{{
				Name: "r", Upstream: httputil.NewSingleHostReverseProxy(u), UpstreamAddr: u.Host,
				ToolNames: []string{"test_tool"}, Engine: engine, Registry: reg,
			}}),
			Auditor: rec, Verifier: &identity.NoopVerifier{}, Breaker: circuit.New(1000, 0),
			Budgets: g.budgets, Velocity: g.velocity, Logger: discardLogger(),
		}),
	}
}

func send(t *testing.T, h http.Handler, session string) *JSONRPCResponse {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(toolsCallBody("test_tool")))
	if session != "" {
		req.Header.Set("Mcp-Session-Id", session)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	return decodeJSONRPC(t, w)
}

func wantCode(t *testing.T, resp *JSONRPCResponse, code int) {
	t.Helper()
	if resp.Error == nil {
		t.Fatalf("call succeeded, want error %d", code)
	}
	if resp.Error.Code != code {
		t.Fatalf("error %d (%s), want %d", resp.Error.Code, resp.Error.Message, code)
	}
}

func lastEvent(t *testing.T, rec *captureEmitter, typ audit.EventType) audit.Event {
	t.Helper()
	for i := len(rec.events) - 1; i >= 0; i-- {
		if rec.events[i].Type == typ {
			return rec.events[i]
		}
	}
	t.Fatalf("no %s event emitted", typ)
	return audit.Event{}
}

func perHour(perIdentity, perSession int) v1alpha1.Rule {
	b := &v1alpha1.BudgetConfig{}
	if perIdentity > 0 {
		b.PerIdentity = &v1alpha1.BudgetLimits{MaxCallsPerHour: perIdentity}
	}
	if perSession > 0 {
		b.PerSession = &v1alpha1.BudgetLimits{MaxCallsPerHour: perSession}
	}
	return v1alpha1.Rule{Action: v1alpha1.ActionAllow, Budget: b}
}

func TestABudgetRefusesTheCallPastItsLimit(t *testing.T) {
	for _, name := range []string{"proxy", "gateway"} {
		t.Run(name, func(t *testing.T) {
			rec := &captureEmitter{}
			h := frontDoors(t, gated{rule: perHour(1, 0), budgets: budget.New()}, rec)[name]
			if resp := send(t, h, "s1"); resp.Error != nil {
				t.Fatalf("first call refused: %s", resp.Error.Message)
			}
			wantCode(t, send(t, h, "s1"), ErrCodeRateLimited)
			e := lastEvent(t, rec, audit.EventToolDenied)
			if e.Gate != "budget" || e.ReasonClass != "budget_exhausted" ||
				!strings.HasPrefix(e.Reason, "budget exhausted") {
				t.Errorf("event %s/%s %q, want budget/budget_exhausted", e.Gate, e.ReasonClass, e.Reason)
			}
		})
	}
}

func TestPerSessionBudgetRefusesACallThatPresentsNoSession(t *testing.T) {
	for _, name := range []string{"proxy", "gateway"} {
		t.Run(name, func(t *testing.T) {
			rec := &captureEmitter{}
			h := frontDoors(t, gated{rule: perHour(0, 100), budgets: budget.New()}, rec)[name]
			// Without Mcp-Session-Id there is nothing to charge a per-session
			// budget to. Admitting the call would make the budget optional.
			wantCode(t, send(t, h, ""), ErrCodePolicyDenied)
			if e := lastEvent(t, rec, audit.EventToolDenied); e.ReasonClass != "budget_unattributable" {
				t.Errorf("reason class %q, want budget_unattributable", e.ReasonClass)
			}
		})
	}
}

func TestARulesMaxCallsPerMinuteIsEnforced(t *testing.T) {
	for _, name := range []string{"proxy", "gateway"} {
		t.Run(name, func(t *testing.T) {
			rec := &captureEmitter{}
			rule := v1alpha1.Rule{Action: v1alpha1.ActionAllow, MaxCallsPerMin: 1}
			h := frontDoors(t, gated{rule: rule}, rec)[name]
			if resp := send(t, h, "s1"); resp.Error != nil {
				t.Fatalf("first call refused: %s", resp.Error.Message)
			}
			wantCode(t, send(t, h, "s1"), ErrCodeRateLimited)
			if e := lastEvent(t, rec, audit.EventToolDenied); e.Gate != "rate" {
				t.Errorf("gate %q, want rate", e.Gate)
			}
		})
	}
}

func TestAVelocityAlertThatDeniesRefusesTheCall(t *testing.T) {
	for _, name := range []string{"proxy", "gateway"} {
		t.Run(name, func(t *testing.T) {
			rec := &captureEmitter{}
			v := anomaly.NewVelocityTracker(anomaly.VelocityConfig{Threshold: 1, AlertAction: anomaly.AlertActionDeny})
			h := frontDoors(t, gated{rule: v1alpha1.Rule{Action: v1alpha1.ActionAllow}, velocity: v}, rec)[name]
			send(t, h, "s1")
			wantCode(t, send(t, h, "s1"), ErrCodeRateLimited)
			if e := lastEvent(t, rec, audit.EventAnomalyVelocity); e.ReasonClass != "velocity_limit" {
				t.Errorf("reason class %q, want velocity_limit", e.ReasonClass)
			}
		})
	}
}

func TestAVelocityAlertThatLogsIsAuditedAndTheCallProceeds(t *testing.T) {
	for _, name := range []string{"proxy", "gateway"} {
		t.Run(name, func(t *testing.T) {
			rec := &captureEmitter{}
			v := anomaly.NewVelocityTracker(anomaly.VelocityConfig{Threshold: 1})
			h := frontDoors(t, gated{rule: v1alpha1.Rule{Action: v1alpha1.ActionAllow}, velocity: v}, rec)[name]
			send(t, h, "s1")
			if resp := send(t, h, "s1"); resp.Error != nil {
				t.Fatalf("log-only alert refused the call: %s", resp.Error.Message)
			}
			lastEvent(t, rec, audit.EventAnomalyVelocity)
		})
	}
}

func TestAGatewayRouteRefusesARunTokenPolicy(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policy.yaml")
	doc := "apiVersion: nullfield.io/v1alpha1\nkind: NullfieldPolicy\nmetadata:\n  name: t\nspec:\n  runToken:\n    jwksUri: http://controller/jwks\n    audience: cluster.local\n  rules:\n    - action: ALLOW\n"
	if err := os.WriteFile(path, []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := BuildRoute(RouteConfig{Name: "r", Upstream: "localhost:1", PolicyFile: path}); err == nil {
		t.Fatal("a gateway route accepted a run token it cannot bind")
	}
}
