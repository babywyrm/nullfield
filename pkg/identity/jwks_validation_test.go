package identity

import (
	"crypto/rand"
	"crypto/rsa"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// verify signs claims with a fresh key and runs them through a verifier built
// from cfg, returning the verification error.
func verify(t *testing.T, cfg JWKSVerifierConfig, claims jwt.MapClaims) error {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	srv := buildJWKSServer(t, "k", &key.PublicKey)
	t.Cleanup(srv.Close)
	cfg.Issuer, cfg.JWKSURI = "https://issuer.example", srv.URL
	claims["iss"] = cfg.Issuer
	claims["sub"] = "agent"

	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("Authorization", "Bearer "+signRSAJWT(t, key, "k", claims))
	_, err = NewJWKSVerifier(cfg).Verify(r)
	return err
}

func TestATokenWithoutExpiryIsAcceptedUnlessExpiryIsRequired(t *testing.T) {
	if err := verify(t, JWKSVerifierConfig{}, jwt.MapClaims{}); err != nil {
		t.Fatalf("default config refused a token with no exp: %v", err)
	}
	if err := verify(t, JWKSVerifierConfig{RequireExpiry: true}, jwt.MapClaims{}); err == nil {
		t.Fatal("requireExpiry accepted a token that never expires")
	}
}

func TestMaxLifetimeRefusesATokenIssuedForLonger(t *testing.T) {
	now := time.Now()
	cfg := JWKSVerifierConfig{MaxLifetime: time.Hour}
	long := jwt.MapClaims{"iat": now.Unix(), "exp": now.Add(24 * time.Hour).Unix()}
	if err := verify(t, cfg, long); err == nil {
		t.Fatal("a 24h token passed a 1h maxLifetime")
	}
	short := jwt.MapClaims{"iat": now.Unix(), "exp": now.Add(30 * time.Minute).Unix()}
	if err := verify(t, cfg, short); err != nil {
		t.Fatalf("a 30m token failed a 1h maxLifetime: %v", err)
	}
}

func TestMaxLifetimeRefusesATokenThatNeverExpires(t *testing.T) {
	if err := verify(t, JWKSVerifierConfig{MaxLifetime: time.Hour}, jwt.MapClaims{}); err == nil {
		t.Fatal("a token with no exp has no lifetime to bound, and was accepted")
	}
}

func TestMaxLifetimeWithoutIssuedAtBoundsTheTimeLeft(t *testing.T) {
	// Leaving out iat must not exempt a token from the bound.
	exp := time.Now().Add(24 * time.Hour).Unix()
	if err := verify(t, JWKSVerifierConfig{MaxLifetime: time.Hour}, jwt.MapClaims{"exp": exp}); err == nil {
		t.Fatal("a token valid for 24h passed a 1h maxLifetime by omitting iat")
	}
}
