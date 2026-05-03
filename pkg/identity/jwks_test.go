package identity

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// buildJWKSServer spins up an httptest.Server that serves the RSA public key
// as a minimal JWKS document.
func buildJWKSServer(t *testing.T, kid string, key *rsa.PublicKey) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		n := base64.RawURLEncoding.EncodeToString(key.N.Bytes())
		e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes())
		jwks := map[string]any{
			"keys": []map[string]any{
				{"kty": "RSA", "kid": kid, "alg": "RS256", "use": "sig", "n": n, "e": e},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(jwks)
	}))
}

// signRSAJWT creates a signed RS256 JWT with the given claims and kid.
func signRSAJWT(t *testing.T, key *rsa.PrivateKey, kid string, claims jwt.MapClaims) string {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = kid
	signed, err := tok.SignedString(key)
	if err != nil {
		t.Fatalf("sign JWT: %v", err)
	}
	return signed
}

func TestJWKSVerifier_ValidJWT(t *testing.T) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	kid := "test-kid-1"
	issuer := "https://test.issuer.example"

	srv := buildJWKSServer(t, kid, &privKey.PublicKey)
	defer srv.Close()

	v := NewJWKSVerifier(JWKSVerifierConfig{
		ProviderName: "testprovider",
		Issuer:       issuer,
		JWKSURI:      srv.URL,
		CacheTTL:     5 * time.Minute,
	})

	now := time.Now()
	signed := signRSAJWT(t, privKey, kid, jwt.MapClaims{
		"sub": "alice",
		"iss": issuer,
		"iat": now.Unix(),
		"exp": now.Add(time.Hour).Unix(),
	})

	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("Authorization", "Bearer "+signed)
	r.Header.Set("Mcp-Session-Id", "jwks-sess")

	id, err := v.Verify(r)
	if err != nil {
		t.Fatalf("verify failed: %v", err)
	}
	if id.Subject != "alice" {
		t.Errorf("expected Subject %q, got %q", "alice", id.Subject)
	}
	if id.Issuer != issuer {
		t.Errorf("expected Issuer %q, got %q", issuer, id.Issuer)
	}
	if id.SessionID != "jwks-sess" {
		t.Errorf("expected SessionID %q, got %q", "jwks-sess", id.SessionID)
	}
	if id.Provider != "testprovider" {
		t.Errorf("expected Provider %q, got %q", "testprovider", id.Provider)
	}
}

func TestJWKSVerifier_CacheHit(t *testing.T) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	kid := "cache-kid"
	issuer := "https://cache.issuer.example"

	fetchCount := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fetchCount++
		n := base64.RawURLEncoding.EncodeToString(privKey.N.Bytes())
		e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(privKey.E)).Bytes())
		jwks := map[string]any{
			"keys": []map[string]any{
				{"kty": "RSA", "kid": kid, "alg": "RS256", "use": "sig", "n": n, "e": e},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(jwks)
	}))
	defer srv.Close()

	v := NewJWKSVerifier(JWKSVerifierConfig{
		Issuer:   issuer,
		JWKSURI:  srv.URL,
		CacheTTL: 5 * time.Minute,
	})

	now := time.Now()
	makeClaims := func() jwt.MapClaims {
		return jwt.MapClaims{
			"sub": "bob", "iss": issuer,
			"iat": now.Unix(), "exp": now.Add(time.Hour).Unix(),
		}
	}

	r1 := httptest.NewRequest("GET", "/", nil)
	r1.Header.Set("Authorization", "Bearer "+signRSAJWT(t, privKey, kid, makeClaims()))
	if _, err := v.Verify(r1); err != nil {
		t.Fatalf("first verify failed: %v", err)
	}

	r2 := httptest.NewRequest("GET", "/", nil)
	r2.Header.Set("Authorization", "Bearer "+signRSAJWT(t, privKey, kid, makeClaims()))
	if _, err := v.Verify(r2); err != nil {
		t.Fatalf("second verify failed: %v", err)
	}

	// JWKS should only be fetched once; second call should use cache.
	if fetchCount != 1 {
		t.Errorf("expected JWKS fetched 1 time, got %d", fetchCount)
	}
}

func TestJWKSVerifier_MissingHeader(t *testing.T) {
	v := NewJWKSVerifier(JWKSVerifierConfig{
		Issuer:  "https://issuer.example",
		JWKSURI: "http://unused",
	})
	r := httptest.NewRequest("GET", "/", nil)
	_, err := v.Verify(r)
	if err == nil {
		t.Fatal("expected error for missing Authorization header")
	}
}

func TestJWKSVerifier_MalformedBearer(t *testing.T) {
	v := NewJWKSVerifier(JWKSVerifierConfig{
		Issuer:  "https://issuer.example",
		JWKSURI: "http://unused",
	})
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("Authorization", "not-a-bearer")
	_, err := v.Verify(r)
	if err == nil {
		t.Fatal("expected error for malformed Bearer token")
	}
}

func TestJWKSVerifier_MatchesIssuer(t *testing.T) {
	v := NewJWKSVerifier(JWKSVerifierConfig{
		Issuer:  "https://example.com",
		JWKSURI: "http://unused",
	})
	if !v.MatchesIssuer("https://example.com") {
		t.Error("expected MatchesIssuer to return true for matching issuer")
	}
	if v.MatchesIssuer("https://other.com") {
		t.Error("expected MatchesIssuer to return false for non-matching issuer")
	}
}

func TestJWKSVerifier_WithAudience_Valid(t *testing.T) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	kid := "aud-kid"
	issuer := "https://aud.issuer.example"
	audience := "myapp"

	srv := buildJWKSServer(t, kid, &privKey.PublicKey)
	defer srv.Close()

	v := NewJWKSVerifier(JWKSVerifierConfig{
		Issuer:    issuer,
		JWKSURI:   srv.URL,
		Audiences: []string{audience},
		CacheTTL:  5 * time.Minute,
	})

	now := time.Now()
	signed := signRSAJWT(t, privKey, kid, jwt.MapClaims{
		"sub": "charlie",
		"iss": issuer,
		"aud": audience,
		"iat": now.Unix(),
		"exp": now.Add(time.Hour).Unix(),
	})

	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("Authorization", "Bearer "+signed)

	if _, err := v.Verify(r); err != nil {
		t.Fatalf("verify with valid audience failed: %v", err)
	}
}

func TestJWKSVerifier_WithAudience_Mismatch(t *testing.T) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	kid := "aud-mismatch-kid"
	issuer := "https://aud-mm.issuer.example"

	srv := buildJWKSServer(t, kid, &privKey.PublicKey)
	defer srv.Close()

	v := NewJWKSVerifier(JWKSVerifierConfig{
		Issuer:    issuer,
		JWKSURI:   srv.URL,
		Audiences: []string{"expected-app"},
		CacheTTL:  5 * time.Minute,
	})

	now := time.Now()
	signed := signRSAJWT(t, privKey, kid, jwt.MapClaims{
		"sub": "dave",
		"iss": issuer,
		"aud": "wrong-app",
		"iat": now.Unix(),
		"exp": now.Add(time.Hour).Unix(),
	})

	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("Authorization", "Bearer "+signed)

	_, err = v.Verify(r)
	if err == nil {
		t.Fatal("expected error for audience mismatch")
	}
}

func TestJWKSVerifier_InferIdentityType_Human(t *testing.T) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	kid := "type-human-kid"
	issuer := "https://type.issuer.example"

	srv := buildJWKSServer(t, kid, &privKey.PublicKey)
	defer srv.Close()

	v := NewJWKSVerifier(JWKSVerifierConfig{
		Issuer:   issuer,
		JWKSURI:  srv.URL,
		CacheTTL: 5 * time.Minute,
	})

	now := time.Now()
	signed := signRSAJWT(t, privKey, kid, jwt.MapClaims{
		"sub":           "human-user",
		"iss":           issuer,
		"identity_type": "human",
		"iat":           now.Unix(),
		"exp":           now.Add(time.Hour).Unix(),
	})

	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("Authorization", "Bearer "+signed)

	id, err := v.Verify(r)
	if err != nil {
		t.Fatalf("verify failed: %v", err)
	}
	if id.Type != IdentityHuman {
		t.Errorf("expected IdentityHuman, got %q", id.Type)
	}
}

func TestJWKSVerifier_WithScopesAndGroups(t *testing.T) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	kid := "sg-kid"
	issuer := "https://sg.issuer.example"

	srv := buildJWKSServer(t, kid, &privKey.PublicKey)
	defer srv.Close()

	v := NewJWKSVerifier(JWKSVerifierConfig{
		Issuer:   issuer,
		JWKSURI:  srv.URL,
		CacheTTL: 5 * time.Minute,
	})

	now := time.Now()
	signed := signRSAJWT(t, privKey, kid, jwt.MapClaims{
		"sub":    "scoped-user",
		"iss":    issuer,
		"scope":  "read write",
		"groups": []any{"admins", "devs"},
		"jti":    "unique-jti-123",
		"iat":    now.Unix(),
		"exp":    now.Add(time.Hour).Unix(),
	})

	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("Authorization", "Bearer "+signed)

	id, err := v.Verify(r)
	if err != nil {
		t.Fatalf("verify failed: %v", err)
	}
	if len(id.Scopes) != 2 {
		t.Errorf("expected 2 scopes, got %v", id.Scopes)
	}
	if len(id.Groups) != 2 {
		t.Errorf("expected 2 groups, got %v", id.Groups)
	}
	if id.JTI != "unique-jti-123" {
		t.Errorf("expected JTI %q, got %q", "unique-jti-123", id.JTI)
	}
}
