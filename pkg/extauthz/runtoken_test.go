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
	now := time.Now()
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"aud": "cluster.local", "iat": now.Unix(), "exp": now.Add(10 * time.Minute).Unix(),
		"txn": run, "sub": "team-sre", "scope": "triage", "req_wl": workload,
	})
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
