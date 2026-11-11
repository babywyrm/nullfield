package identity

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// A run token is an IETF Transaction Token (draft-ietf-oauth-transaction-tokens)
// minted by the controller that launched a run.
const (
	RunTokenHeader = "Txn-Token"
	RunTokenType   = "txntoken+jwt"
)

var (
	ErrRunTokenMissing = errors.New("run token missing")
	ErrRunTokenUnbound = errors.New("run token not issued to this workload")
)

// Run is what a verified run token says about the run.
type Run struct {
	// ID is the txn claim.
	ID string
	// Workload is the req_wl claim, already checked against the caller or an
	// allowed delegate.
	Workload string
	// Presenter is the attested workload that presented the token on this hop.
	// Equal to Workload on a direct call; the delegate's principal when a
	// listed MCP server forwards the run token.
	Presenter string
	// Context is the tctx claim: what the controller fixed for this run.
	Context map[string]any
}

// RunTokenDelegate permits Workload to present a run token whose req_wl matches
// an entry in For (an exact SPIFFE ID or a prefix ending in "/*").
type RunTokenDelegate struct {
	Workload string
	For      []string
}

type RunTokenConfig struct {
	JWKSURI string
	// Audience is the trust domain the token must name in aud.
	Audience    string
	Issuer      string
	MaxLifetime time.Duration
	ClockSkew   time.Duration
	Delegates   []RunTokenDelegate
}

type RunTokenVerifier struct {
	jwks      *JWKSVerifier
	delegates []RunTokenDelegate
}

func NewRunTokenVerifier(cfg RunTokenConfig) *RunTokenVerifier {
	return &RunTokenVerifier{
		jwks: NewJWKSVerifier(JWKSVerifierConfig{
			ProviderName:  "run-token",
			Issuer:        cfg.Issuer,
			JWKSURI:       cfg.JWKSURI,
			Audiences:     []string{cfg.Audience},
			ClockSkew:     cfg.ClockSkew,
			Header:        RunTokenHeader,
			RequireExpiry: true,
			MaxLifetime:   cfg.MaxLifetime,
			Bare:          true,
			Type:          RunTokenType,
		}),
		delegates: cfg.Delegates,
	}
}

// Verify checks token, the Txn-Token header value, and that it was issued to
// workload, the attested principal of the caller (or that workload is a
// configured delegate for req_wl). A token is only as good as its binding: one
// copied out of a pod must fail everywhere else.
func (v *RunTokenVerifier) Verify(token, workload string) (*Identity, *Run, error) {
	if token == "" {
		return nil, nil, ErrRunTokenMissing
	}
	id, err := v.jwks.Verify(&http.Request{Header: http.Header{RunTokenHeader: {token}}})
	if err != nil {
		return nil, nil, fmt.Errorf("run token: %w", err)
	}
	for _, c := range []string{"iat", "txn", "req_wl"} {
		if _, ok := id.Claims[c]; !ok {
			return nil, nil, fmt.Errorf("run token: missing %s claim", c)
		}
	}
	run := &Run{
		ID:        claimString(id.Claims, "txn"),
		Workload:  claimString(id.Claims, "req_wl"),
		Presenter: workload,
	}
	run.Context, _ = id.Claims["tctx"].(map[string]any)
	if run.ID == "" || run.Workload == "" {
		return nil, nil, fmt.Errorf("run token: txn and req_wl must be non-empty strings")
	}
	if workload == "" || (run.Workload != workload && !v.mayPresent(workload, run.Workload)) {
		return nil, nil, fmt.Errorf("%w: issued to %q, presented by %q", ErrRunTokenUnbound, run.Workload, workload)
	}
	id.SessionID = run.ID
	return id, run, nil
}

func (v *RunTokenVerifier) mayPresent(presenter, reqWorkload string) bool {
	for _, d := range v.delegates {
		if d.Workload != presenter {
			continue
		}
		for _, pattern := range d.For {
			if pattern == reqWorkload {
				return true
			}
			if prefix, ok := strings.CutSuffix(pattern, "/*"); ok && strings.HasPrefix(reqWorkload, prefix+"/") {
				return true
			}
		}
	}
	return false
}
