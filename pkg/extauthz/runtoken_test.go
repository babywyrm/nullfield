package extauthz

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"
	"time"

	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"github.com/golang-jwt/jwt/v5"
	"google.golang.org/grpc/codes"

	v1alpha1 "github.com/babywyrm/nullfield/api/v1alpha1"
	"github.com/babywyrm/nullfield/pkg/audit"
	"github.com/babywyrm/nullfield/pkg/budget"
	"github.com/babywyrm/nullfield/pkg/circuit"
	"github.com/babywyrm/nullfield/pkg/gates"
	"github.com/babywyrm/nullfield/pkg/identity"
	"github.com/babywyrm/nullfield/pkg/policy"
)

// controller stands in for the run controller: it publishes a JWKS and mints
// run tokens.
type controller struct {
	key *rsa.PrivateKey
	srv *httptest.Server
}

func newController(t *testing.T) *controller {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]any{{
			"kty": "RSA", "kid": "k", "alg": "RS256",
			"n": base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
			"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
		}}})
	}))
	t.Cleanup(srv.Close)
	return &controller{key: key, srv: srv}
}

func (c *controller) verifier() *identity.RunTokenVerifier {
	return identity.NewRunTokenVerifier(identity.RunTokenConfig{JWKSURI: c.srv.URL, Audience: "cluster.local"})
}

func (c *controller) mint(t *testing.T, run, workload string) string {
	t.Helper()
	return c.mintWithContext(t, run, workload, nil)
}

func (c *controller) mintWithContext(t *testing.T, run, workload string, tctx map[string]any) string {
	t.Helper()
	now := time.Now()
	claims := jwt.MapClaims{
		"aud": "cluster.local", "iat": now.Unix(), "exp": now.Add(10 * time.Minute).Unix(),
		"txn": run, "sub": "team-sre", "scope": "triage", "req_wl": workload,
	}
	if tctx != nil {
		claims["tctx"] = tctx
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"], tok.Header["typ"] = "k", identity.RunTokenType
	s, err := tok.SignedString(c.key)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func withRunToken(token string) *authv3.CheckRequest {
	h := map[string]string{}
	if token != "" {
		h["txn-token"] = token
	}
	return checkRequest(spiffeRunner, toolsCallBody, h)
}

func check(t *testing.T, s *Server, req *authv3.CheckRequest) *authv3.CheckResponse {
	t.Helper()
	resp, err := s.Check(t.Context(), req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func allowRun(id string) policy.Engine {
	return policy.NewRuleEngine([]v1alpha1.Rule{
		{Action: v1alpha1.ActionAllow, CELExpression: `has(request.run) && request.run.id == "` + id + `" && request.identity.subject == "team-sre"`},
		{Action: v1alpha1.ActionDeny},
	})
}

func TestABoundRunTokenReachesPolicyAndIsStrippedBeforeForwarding(t *testing.T) {
	c, rec := newController(t), &recorder{}
	s := NewServer(Config{Mode: ModeEnforce, Audit: rec, Engine: allowRun("run-1"), RunTokens: c.verifier()})

	resp := check(t, s, withRunToken(c.mint(t, "run-1", spiffeRunner)))
	if codes.Code(resp.GetStatus().GetCode()) != codes.OK {
		t.Fatalf("refused: %v", resp.GetDeniedResponse().GetBody())
	}
	if !slices.Contains(resp.GetOkResponse().GetHeadersToRemove(), "txn-token") {
		t.Error("the run token would be forwarded upstream")
	}
	e := rec.events[len(rec.events)-1]
	if e.RunID != "run-1" || e.Identity != "team-sre" || e.Assurance != AssuranceMedium {
		t.Errorf("audit run_id=%q identity=%q assurance=%q", e.RunID, e.Identity, e.Assurance)
	}
}

func TestACallWithoutARunTokenIsRefusedUnlessTokensAreOptional(t *testing.T) {
	c, rec := newController(t), &recorder{}
	allowAll := policy.NewRuleEngine([]v1alpha1.Rule{{Action: v1alpha1.ActionAllow}})

	s := NewServer(Config{Mode: ModeEnforce, Audit: rec, Engine: allowAll, RunTokens: c.verifier()})
	if got := status(t, s, withRunToken("")); got != codes.PermissionDenied {
		t.Fatalf("tokenless call: %v, want PermissionDenied", got)
	}
	if e := rec.events[len(rec.events)-1]; e.Gate != GateRunToken || e.ReasonClass != ReasonRunTokenMissing {
		t.Errorf("recorded gate=%q class=%q", e.Gate, e.ReasonClass)
	}

	s = NewServer(Config{Mode: ModeEnforce, Audit: rec, Engine: allowAll, RunTokens: c.verifier(), RunTokenOptional: true})
	if got := status(t, s, withRunToken("")); got != codes.OK {
		t.Fatalf("tokenless call with optional tokens: %v, want OK", got)
	}
}

func TestARunTokenIssuedToAnotherWorkloadIsRefused(t *testing.T) {
	c, rec := newController(t), &recorder{}
	s := NewServer(Config{Mode: ModeEnforce, Audit: rec, Engine: allowRun("run-1"), RunTokens: c.verifier(), RunTokenOptional: true})

	stolen := c.mint(t, "run-1", "spiffe://cluster.local/ns/agents/sa/other")
	if got := status(t, s, withRunToken(stolen)); got != codes.PermissionDenied {
		t.Fatalf("a token minted for another pod: %v, want PermissionDenied", got)
	}
	if e := rec.events[len(rec.events)-1]; e.ReasonClass != ReasonRunTokenUnbound {
		t.Errorf("recorded class=%q", e.ReasonClass)
	}
	// Optional admits a missing token, never a bad one.
	if got := status(t, s, withRunToken("not-a-jwt")); got != codes.PermissionDenied {
		t.Fatalf("a malformed token with optional tokens: %v, want PermissionDenied", got)
	}
	if e := rec.events[len(rec.events)-1]; e.ReasonClass != ReasonRunTokenInvalid {
		t.Errorf("recorded class=%q", e.ReasonClass)
	}
}

func TestPerSessionBudgetsCountPerRun(t *testing.T) {
	c := newController(t)
	s := NewServer(Config{
		Mode: ModeEnforce, Audit: &recorder{}, RunTokens: c.verifier(),
		Engine: policy.NewRuleEngine([]v1alpha1.Rule{{
			Action: v1alpha1.ActionAllow,
			Budget: &v1alpha1.BudgetConfig{PerSession: &v1alpha1.BudgetLimits{MaxCallsPerHour: 1}},
		}}),
		Gates: gates.Gates{Budgets: budget.New()},
	})
	first, second := c.mint(t, "run-1", spiffeRunner), c.mint(t, "run-2", spiffeRunner)

	if got := status(t, s, withRunToken(first)); got != codes.OK {
		t.Fatalf("run-1 first call: %v", got)
	}
	if got := status(t, s, withRunToken(first)); got != codes.PermissionDenied {
		t.Fatalf("run-1 second call: %v, want PermissionDenied", got)
	}
	if got := status(t, s, withRunToken(second)); got != codes.OK {
		t.Fatalf("run-2 shares the pod but not run-1's budget: %v", got)
	}
}

func TestTheCircuitBreakerTripsPerRun(t *testing.T) {
	c := newController(t)
	s := NewServer(Config{
		Mode: ModeEnforce, Audit: &recorder{}, RunTokens: c.verifier(),
		Engine: policy.NewRuleEngine([]v1alpha1.Rule{{Action: v1alpha1.ActionAllow}}),
		Gates:  gates.Gates{Breaker: circuit.New(1, 0)},
	})
	first, second := c.mint(t, "run-1", spiffeRunner), c.mint(t, "run-2", spiffeRunner)

	if got := status(t, s, withRunToken(first)); got != codes.OK {
		t.Fatalf("run-1 first call: %v", got)
	}
	if got := status(t, s, withRunToken(first)); got != codes.PermissionDenied {
		t.Fatalf("run-1 past its breaker: %v, want PermissionDenied", got)
	}
	if got := status(t, s, withRunToken(second)); got != codes.OK {
		t.Fatalf("run-2 shares the pod but not run-1's breaker: %v", got)
	}
}

// A controller ends a run on its trip, once. Every refused call after it is
// still a decision event, but not another signal.
func TestATrippedRunSignalsOnce(t *testing.T) {
	c := newController(t)
	rec := &recorder{}
	s := NewServer(Config{
		Mode: ModeEnforce, Audit: rec, RunTokens: c.verifier(),
		Engine: policy.NewRuleEngine([]v1alpha1.Rule{{Action: v1alpha1.ActionAllow}}),
		Gates:  gates.Gates{Breaker: circuit.New(1, 0)},
	})
	token := c.mint(t, "run-1", spiffeRunner)
	for range 3 {
		status(t, s, withRunToken(token))
	}
	var trips []audit.Event
	for _, e := range rec.events {
		if e.Type == audit.EventCircuitTripped {
			trips = append(trips, e)
		}
	}
	if len(trips) != 1 {
		t.Fatalf("%d circuit.tripped events, want 1", len(trips))
	}
	if e := trips[0]; e.RunID != "run-1" || e.WorkloadPrincipal != spiffeRunner || e.Gate != gates.GateCircuit {
		t.Fatalf("trip event = %+v, want run-1 from %s at gate circuit", e, spiffeRunner)
	}
}

func TestARunTokenIsForwardedOnlyToAVerifiedListedService(t *testing.T) {
	c := newController(t)
	token := c.mint(t, "run-1", spiffeRunner)
	s := NewServer(Config{
		Mode: ModeEnforce, Audit: &recorder{}, Engine: allowRun("run-1"),
		RunTokens:      c.verifier(),
		RunTokenForwardTo: []string{"MCP-GitHub.tools.svc.cluster.local."},
		LookupAddr:     clusterDNS,
	})

	callTo := func(host, addr string) bool {
		req := toAddress(host, addr)
		req.Attributes.Request.Http.Headers = map[string]string{"txn-token": token}
		resp := check(t, s, req)
		if codes.Code(resp.GetStatus().GetCode()) != codes.OK {
			t.Fatalf("%s (%s) refused: %v", host, addr, resp.GetDeniedResponse().GetBody())
		}
		return !slices.Contains(resp.GetOkResponse().GetHeadersToRemove(), "txn-token")
	}

	// Routed to the listed Service: Host may be short or full, because the
	// reverse-resolved VIP proves where the call is going.
	for _, host := range []string{"mcp-github", "mcp-github.tools.svc.cluster.local"} {
		if !callTo(host, "10.43.0.10") {
			t.Errorf("Host %q to 10.43.0.10 (mcp-github): token was stripped, want forwarded", host)
		}
	}
	// Routed to another in-mesh Service that is not in forwardTo: stripped.
	if callTo("run-controller", "10.43.0.20") {
		t.Error("call to unlisted Service run-controller: token was forwarded, want stripped")
	}
	// Unresolvable destination (ServiceEntry VIP, pod IP) with Host claiming to
	// be the listed Service: unverified, so stripped.
	for _, addr := range []string{"240.240.0.1", "10.42.0.5", ""} {
		if callTo("mcp-github.tools.svc.cluster.local", addr) {
			t.Errorf("unverified destination %q: token was forwarded on Host claim alone", addr)
		}
	}
}

func TestADelegatedRunTokenRecordsBothPresenterAndOriginAndSharesTheRunBreaker(t *testing.T) {
	const spiffeMCP = "spiffe://cluster.local/ns/tools/sa/mcp-github"
	c := newController(t)
	rec := &recorder{}
	verifier := identity.NewRunTokenVerifier(identity.RunTokenConfig{
		JWKSURI:  c.srv.URL,
		Audience: "cluster.local",
		Delegates: []identity.RunTokenDelegate{
			{Workload: spiffeMCP, For: []string{"spiffe://cluster.local/ns/agents/sa/*"}},
		},
	})
	s := NewServer(Config{
		Mode:      ModeEnforce,
		Audit:     rec,
		RunTokens: verifier,
		Engine: policy.NewRuleEngine([]v1alpha1.Rule{
			{Action: v1alpha1.ActionAllow, CELExpression: `has(request.run) && request.run.workload == "` + spiffeRunner + `"`},
			{Action: v1alpha1.ActionDeny},
		}),
		Gates: gates.Gates{Breaker: circuit.New(2, 0)},
	})

	token := c.mint(t, "run-1", spiffeRunner)

	// Hop 1: agent calls MCP server (1st call in run-1).
	if got := status(t, s, checkRequest(spiffeRunner, toolsCallBody, map[string]string{"txn-token": token})); got != codes.OK {
		t.Fatalf("hop 1 (agent): %v", got)
	}
	if e := rec.events[len(rec.events)-1]; e.WorkloadPrincipal != spiffeRunner || e.RunWorkload != "" {
		t.Errorf("direct call audit: workload_principal=%q run_workload=%q", e.WorkloadPrincipal, e.RunWorkload)
	}

	// Hop 2: MCP server presents the agent's token on an outbound call (2nd call in run-1).
	if got := status(t, s, checkRequest(spiffeMCP, toolsCallBody, map[string]string{"txn-token": token})); got != codes.OK {
		t.Fatalf("hop 2 (delegated MCP server): %v", got)
	}
	e := rec.events[len(rec.events)-1]
	if e.RunID != "run-1" || e.WorkloadPrincipal != spiffeMCP || e.RunWorkload != spiffeRunner || e.Assurance != AssuranceMedium {
		t.Errorf("delegated audit: run_id=%q workload_principal=%q run_workload=%q assurance=%q",
			e.RunID, e.WorkloadPrincipal, e.RunWorkload, e.Assurance)
	}

	// 3rd call in the same run trips the shared breaker (limit 2).
	if got := status(t, s, checkRequest(spiffeMCP, toolsCallBody, map[string]string{"txn-token": token})); got != codes.PermissionDenied {
		t.Fatalf("3rd call in run-1 across hops: %v, want PermissionDenied from shared breaker", got)
	}
	// Both the circuit.tripped event and the decision event record the presenter and origin.
	for _, ev := range rec.events[len(rec.events)-2:] {
		if ev.WorkloadPrincipal != spiffeMCP || ev.RunWorkload != spiffeRunner {
			t.Errorf("%s: workload_principal=%q run_workload=%q", ev.Type, ev.WorkloadPrincipal, ev.RunWorkload)
		}
	}
}

func TestAnExchangedRunTokenBindsToTheServerAndSharesTheRunsBudget(t *testing.T) {
	const spiffeMCP = "spiffe://cluster.local/ns/tools/sa/mcp-github"
	c := newController(t)
	rec := &recorder{}
	// No delegates configured: each hop must present a token bound to itself.
	s := NewServer(Config{
		Mode:              ModeEnforce,
		Audit:             rec,
		RunTokens:         c.verifier(),
		RunTokenForwardTo: []string{"mcp-github.tools.svc.cluster.local"},
		LookupAddr:        clusterDNS,
		Engine: policy.NewRuleEngine([]v1alpha1.Rule{
			{
				Action:        v1alpha1.ActionAllow,
				CELExpression: `has(request.run) && request.arguments.repo in request.run.context.repos`,
				Budget:        &v1alpha1.BudgetConfig{PerSession: &v1alpha1.BudgetLimits{MaxCallsPerHour: 2}},
			},
			{Action: v1alpha1.ActionDeny},
		}),
		Gates: gates.Gates{Budgets: budget.New()},
	})

	callRepo := func(principal, host, addr, token, repo string) *authv3.CheckResponse {
		body := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo","arguments":{"repo":"` + repo + `"}}}`
		req := checkRequest(principal, body, map[string]string{"txn-token": token})
		req.Attributes.Request.Http.Host = host
		if addr != "" {
			req.Attributes.Destination = toAddress(host, addr).Attributes.Destination
		}
		return check(t, s, req)
	}

	// Hop 1: agent calls mcp-github; token is forwarded so mcp-github can exchange it.
	agentTok := c.mintWithContext(t, "run-x", spiffeRunner, map[string]any{"repos": []any{"acme/widgets", "acme/docs"}})
	resp1 := callRepo(spiffeRunner, "mcp-github", "10.43.0.10", agentTok, "acme/widgets")
	if codes.Code(resp1.GetStatus().GetCode()) != codes.OK {
		t.Fatalf("hop 1 refused: %v", resp1.GetDeniedResponse().GetBody())
	}
	if slices.Contains(resp1.GetOkResponse().GetHeadersToRemove(), "txn-token") {
		t.Fatal("hop 1 stripped txn-token; mcp-github would have nothing to exchange")
	}

	// Without exchange, mcp-github cannot present the agent's token when no delegate is configured.
	if got := codes.Code(callRepo(spiffeMCP, "run-controller", "10.43.0.20", agentTok, "acme/widgets").GetStatus().GetCode()); got != codes.PermissionDenied {
		t.Fatalf("unexchanged agent token from mcp-github: %v, want PermissionDenied", got)
	}

	// Exchange: controller mints a token bound to spiffeMCP with the same txn and narrowed tctx.
	exchangedTok := c.mintWithContext(t, "run-x", spiffeMCP, map[string]any{"repos": []any{"acme/widgets"}})

	// Narrowed out repo is refused by policy before charging the run's budget.
	if got := codes.Code(callRepo(spiffeMCP, "run-controller", "10.43.0.20", exchangedTok, "acme/docs").GetStatus().GetCode()); got != codes.PermissionDenied {
		t.Fatalf("repo narrowed out by exchange: %v, want PermissionDenied", got)
	}

	// Hop 2: allowed, stripped toward unlisted Service, and consumes the 2nd call of run-x's budget.
	resp2 := callRepo(spiffeMCP, "run-controller", "10.43.0.20", exchangedTok, "acme/widgets")
	if codes.Code(resp2.GetStatus().GetCode()) != codes.OK {
		t.Fatalf("hop 2 refused: %v", resp2.GetDeniedResponse().GetBody())
	}
	if !slices.Contains(resp2.GetOkResponse().GetHeadersToRemove(), "txn-token") {
		t.Fatal("hop 2 did not strip txn-token toward unlisted Service")
	}
	if e := rec.events[len(rec.events)-1]; e.RunID != "run-x" || e.WorkloadPrincipal != spiffeMCP || e.RunWorkload != "" {
		t.Errorf("hop 2 audit: run_id=%q workload=%q run_workload=%q", e.RunID, e.WorkloadPrincipal, e.RunWorkload)
	}

	// A 3rd call under run-x is refused by the shared per-run budget (limit 2).
	if got := codes.Code(callRepo(spiffeMCP, "run-controller", "10.43.0.20", exchangedTok, "acme/widgets").GetStatus().GetCode()); got != codes.PermissionDenied {
		t.Fatalf("3rd call in run-x: %v, want PermissionDenied from shared run budget", got)
	}
}
