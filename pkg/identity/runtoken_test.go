package identity

import (
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const (
	runner = "spiffe://cluster.local/ns/agents/sa/incident-triage"
	domain = "cluster.local"
)

func runClaims() jwt.MapClaims {
	now := time.Now()
	return jwt.MapClaims{
		"aud":    domain,
		"iat":    now.Unix(),
		"exp":    now.Add(10 * time.Minute).Unix(),
		"txn":    "run-7f3a",
		"sub":    "team-sre",
		"scope":  "incident.triage",
		"req_wl": runner,
		"tctx":   map[string]any{"repos": []any{"acme/widgets"}},
	}
}

// verifyRun mints a token with the given typ header and claims and verifies
// it as presented by workload.
func verifyRun(t *testing.T, cfg RunTokenConfig, typ string, claims jwt.MapClaims, workload string) (*Identity, *Run, error) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	srv := buildJWKSServer(t, "k", &key.PublicKey)
	t.Cleanup(srv.Close)
	cfg.JWKSURI = srv.URL
	if cfg.Audience == "" {
		cfg.Audience = domain
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = "k"
	if typ != "" {
		tok.Header["typ"] = typ
	}
	signed, err := tok.SignedString(key)
	if err != nil {
		t.Fatal(err)
	}
	return NewRunTokenVerifier(cfg).Verify(signed, workload)
}

func TestARunTokenBoundToTheCallingWorkloadIsAccepted(t *testing.T) {
	id, run, err := verifyRun(t, RunTokenConfig{}, RunTokenType, runClaims(), runner)
	if err != nil {
		t.Fatal(err)
	}
	if id.Subject != "team-sre" || run.ID != "run-7f3a" || run.Workload != runner {
		t.Fatalf("identity %+v run %+v", id, run)
	}
	if repos, _ := run.Context["repos"].([]any); len(repos) != 1 || repos[0] != "acme/widgets" {
		t.Fatalf("tctx not carried: %+v", run.Context)
	}
}

func TestAMissingRunTokenIsReportedAsMissing(t *testing.T) {
	_, _, err := NewRunTokenVerifier(RunTokenConfig{Audience: domain, JWKSURI: "http://unused"}).Verify("", runner)
	if !errors.Is(err, ErrRunTokenMissing) {
		t.Fatalf("got %v, want ErrRunTokenMissing", err)
	}
}

func TestARunTokenIssuedToAnotherWorkloadIsRefused(t *testing.T) {
	_, _, err := verifyRun(t, RunTokenConfig{}, RunTokenType, runClaims(), "spiffe://cluster.local/ns/agents/sa/other")
	if !errors.Is(err, ErrRunTokenUnbound) {
		t.Fatalf("got %v, want ErrRunTokenUnbound", err)
	}
}

func TestARunTokenWithNoAttestedWorkloadIsRefused(t *testing.T) {
	if _, _, err := verifyRun(t, RunTokenConfig{}, RunTokenType, runClaims(), ""); !errors.Is(err, ErrRunTokenUnbound) {
		t.Fatalf("got %v, want ErrRunTokenUnbound", err)
	}
}

func TestAMalformedRunTokenIsRefused(t *testing.T) {
	without := func(k string) jwt.MapClaims { c := runClaims(); delete(c, k); return c }
	with := func(k string, v any) jwt.MapClaims { c := runClaims(); c[k] = v; return c }
	now := time.Now()

	for name, tc := range map[string]struct {
		typ    string
		claims jwt.MapClaims
		cfg    RunTokenConfig
	}{
		// An access token from the same issuer must not stand in for one.
		"no typ":         {"", runClaims(), RunTokenConfig{}},
		"access token":   {"at+jwt", runClaims(), RunTokenConfig{}},
		"other domain":   {RunTokenType, with("aud", "other.local"), RunTokenConfig{}},
		"no exp":         {RunTokenType, without("exp"), RunTokenConfig{}},
		"no iat":         {RunTokenType, without("iat"), RunTokenConfig{}},
		"no txn":         {RunTokenType, without("txn"), RunTokenConfig{}},
		"no req_wl":      {RunTokenType, without("req_wl"), RunTokenConfig{}},
		"expired":        {RunTokenType, with("exp", now.Add(-time.Minute).Unix()), RunTokenConfig{}},
		"too long-lived": {RunTokenType, with("exp", now.Add(2*time.Hour).Unix()), RunTokenConfig{MaxLifetime: time.Hour}},
	} {
		t.Run(name, func(t *testing.T) {
			_, _, err := verifyRun(t, tc.cfg, tc.typ, tc.claims, runner)
			if err == nil {
				t.Fatal("accepted")
			}
			if errors.Is(err, ErrRunTokenMissing) || errors.Is(err, ErrRunTokenUnbound) {
				t.Fatalf("misclassified: %v", err)
			}
		})
	}
}

func TestAListedDelegateMayPresentARunTokenIssuedToAnAllowedWorkload(t *testing.T) {
	const (
		mcpGitHub = "spiffe://cluster.local/ns/tools/sa/mcp-github"
		mcpSlack  = "spiffe://cluster.local/ns/tools/sa/mcp-slack"
		otherRun  = "spiffe://cluster.local/ns/other/sa/job"
	)
	cfg := RunTokenConfig{Delegates: []RunTokenDelegate{
		{Workload: mcpGitHub, For: []string{"spiffe://cluster.local/ns/agents/sa/*"}},
	}}

	_, run, err := verifyRun(t, cfg, RunTokenType, runClaims(), mcpGitHub)
	if err != nil {
		t.Fatalf("listed delegate refused: %v", err)
	}
	if run.Workload != runner || run.Presenter != mcpGitHub {
		t.Fatalf("run = %+v, want workload=%s presenter=%s", run, runner, mcpGitHub)
	}

	// Direct presenter still works and sets Presenter to itself.
	if _, direct, err := verifyRun(t, cfg, RunTokenType, runClaims(), runner); err != nil || direct.Presenter != runner {
		t.Fatalf("direct call: err=%v run=%+v", err, direct)
	}

	// An unlisted server presenting the agent's token is refused as unbound.
	if _, _, err := verifyRun(t, cfg, RunTokenType, runClaims(), mcpSlack); !errors.Is(err, ErrRunTokenUnbound) {
		t.Fatalf("unlisted presenter: got %v, want ErrRunTokenUnbound", err)
	}

	// Listed server presenting a token issued to a workload outside its `for` list is refused.
	outside := runClaims()
	outside["req_wl"] = otherRun
	if _, _, err := verifyRun(t, cfg, RunTokenType, outside, mcpGitHub); !errors.Is(err, ErrRunTokenUnbound) {
		t.Fatalf("req_wl outside for: got %v, want ErrRunTokenUnbound", err)
	}
}
