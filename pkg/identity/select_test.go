package identity

import (
	"errors"
	"strings"
	"testing"
)

func TestVerifierFromEnv(t *testing.T) {
	t.Run("a JWKS URL with an issuer builds a real verifier", func(t *testing.T) {
		v, err := VerifierFromEnv(EnvVerifierConfig{
			JWKSURL: "https://idp.example.com/.well-known/jwks.json",
			Issuer:  "https://idp.example.com",
			Header:  "Authorization",
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if _, ok := v.(*JWKSVerifier); !ok {
			t.Fatalf("expected a *JWKSVerifier, got %T", v)
		}
	})

	// The bug this function exists to close. Setting a variable named
	// NULLFIELD_JWKS_URL used to select HeaderVerifier, which accepts any
	// bearer token unverified -- so an operator who thought they had turned on
	// JWKS validation had turned on trusting the caller.
	t.Run("a JWKS URL without an issuer refuses rather than falling back", func(t *testing.T) {
		v, err := VerifierFromEnv(EnvVerifierConfig{
			JWKSURL: "https://idp.example.com/.well-known/jwks.json",
			Header:  "Authorization",
		})
		if err == nil {
			t.Fatalf("expected an error, got verifier %T", v)
		}
		if !errors.Is(err, ErrJWKSIssuerRequired) {
			t.Errorf("error should be ErrJWKSIssuerRequired, got: %v", err)
		}
		if !strings.Contains(err.Error(), "NULLFIELD_JWKS_ISSUER") {
			t.Errorf("the error must name the variable to set, got: %v", err)
		}
	})

	t.Run("nothing configured returns no verifier and no error", func(t *testing.T) {
		v, err := VerifierFromEnv(EnvVerifierConfig{Header: "Authorization"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if v != nil {
			t.Errorf("expected nil so the caller can fall back, got %T", v)
		}
	})

	// The unverified path still exists for local development, but it has to be
	// asked for by a name that says what it does.
	t.Run("trusting the header is available but must be named", func(t *testing.T) {
		v, err := VerifierFromEnv(EnvVerifierConfig{TrustHeader: true, Header: "Authorization"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if _, ok := v.(*HeaderVerifier); !ok {
			t.Fatalf("expected a *HeaderVerifier, got %T", v)
		}
	})

	t.Run("asking for both is a contradiction, not a preference", func(t *testing.T) {
		_, err := VerifierFromEnv(EnvVerifierConfig{
			JWKSURL:     "https://idp.example.com/.well-known/jwks.json",
			Issuer:      "https://idp.example.com",
			TrustHeader: true,
			Header:      "Authorization",
		})
		if err == nil {
			t.Fatal("expected an error when validation and trust-the-header are both requested")
		}
	})
}
