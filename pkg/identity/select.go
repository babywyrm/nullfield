package identity

import (
	"errors"
	"fmt"
	"time"
)

// ErrJWKSIssuerRequired is returned when a JWKS URL is configured without the
// issuer needed to validate against it.
var ErrJWKSIssuerRequired = errors.New("JWKS URL configured without an issuer")

// EnvVerifierConfig is the environment-variable path to identity verification,
// used when the policy does not declare identity.providers.
type EnvVerifierConfig struct {
	JWKSURL     string
	Issuer      string
	Audiences   []string
	ClockSkew   time.Duration
	AllowedAlgs []string
	Header      string

	// TrustHeader accepts any bearer token without verifying it, taking the
	// token itself as the subject. Development only.
	TrustHeader bool
}

// VerifierFromEnv builds a verifier from environment configuration, or returns
// nil when none is requested so the caller can fall back.
//
// A JWKS URL without an issuer is an error rather than a fallback. Setting
// NULLFIELD_JWKS_URL used to select HeaderVerifier, which never fetches the
// JWKS and accepts any bearer token unverified -- so the variable that looks
// like it turns on validation turned on trusting the caller instead. Failing
// to start is the only honest answer to a half-configured verifier.
func VerifierFromEnv(cfg EnvVerifierConfig) (Verifier, error) {
	if cfg.JWKSURL != "" && cfg.TrustHeader {
		return nil, errors.New(
			"NULLFIELD_JWKS_URL and NULLFIELD_TRUST_HEADER_IDENTITY are both set: " +
				"one validates tokens and the other accepts them unverified, so pick one")
	}

	if cfg.JWKSURL != "" {
		if cfg.Issuer == "" {
			return nil, fmt.Errorf(
				"%w: set NULLFIELD_JWKS_ISSUER to the expected iss claim, or declare "+
					"identity.providers in the policy. A JWKS URL alone cannot validate a token",
				ErrJWKSIssuerRequired)
		}
		return NewJWKSVerifier(JWKSVerifierConfig{
			ProviderName: "env",
			Issuer:       cfg.Issuer,
			JWKSURI:      cfg.JWKSURL,
			Audiences:    cfg.Audiences,
			ClockSkew:    cfg.ClockSkew,
			AllowedAlgs:  cfg.AllowedAlgs,
			Header:       cfg.Header,
		}), nil
	}

	if cfg.TrustHeader {
		return NewHeaderVerifier(cfg.Header), nil
	}

	return nil, nil
}
