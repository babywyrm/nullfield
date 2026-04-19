package identity

import (
	"crypto/rsa"
	"crypto/ecdsa"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"crypto/elliptic"
	"encoding/base64"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// JWKSVerifier validates JWTs against a JWKS endpoint for a single identity provider.
type JWKSVerifier struct {
	providerName string
	issuer       string
	jwksURI      string
	audiences    []string
	clockSkew    time.Duration
	allowedAlgs  map[string]bool
	header       string

	mu       sync.RWMutex
	keys     map[string]any // kid -> *rsa.PublicKey or *ecdsa.PublicKey
	fetchedAt time.Time
	cacheTTL  time.Duration
}

type JWKSVerifierConfig struct {
	ProviderName string
	Issuer       string
	JWKSURI      string
	Audiences    []string
	ClockSkew    time.Duration
	AllowedAlgs  []string
	Header       string
	CacheTTL     time.Duration
}

func NewJWKSVerifier(cfg JWKSVerifierConfig) *JWKSVerifier {
	algs := make(map[string]bool)
	if len(cfg.AllowedAlgs) == 0 {
		algs["RS256"] = true
		algs["ES256"] = true
	} else {
		for _, a := range cfg.AllowedAlgs {
			algs[strings.ToUpper(a)] = true
		}
	}
	if cfg.Header == "" {
		cfg.Header = "Authorization"
	}
	if cfg.CacheTTL == 0 {
		cfg.CacheTTL = 5 * time.Minute
	}
	return &JWKSVerifier{
		providerName: cfg.ProviderName,
		issuer:       cfg.Issuer,
		jwksURI:      cfg.JWKSURI,
		audiences:    cfg.Audiences,
		clockSkew:    cfg.ClockSkew,
		allowedAlgs:  algs,
		header:       cfg.Header,
		keys:         make(map[string]any),
		cacheTTL:     cfg.CacheTTL,
	}
}

func (v *JWKSVerifier) Verify(r *http.Request) (*Identity, error) {
	raw := r.Header.Get(v.header)
	if raw == "" {
		return nil, fmt.Errorf("missing header: %s", v.header)
	}
	tokenStr := strings.TrimPrefix(raw, "Bearer ")
	if tokenStr == raw {
		return nil, fmt.Errorf("malformed Bearer token")
	}

	token, err := jwt.Parse(tokenStr, v.keyFunc,
		jwt.WithLeeway(v.clockSkew),
		jwt.WithIssuer(v.issuer),
	)
	if err != nil {
		return nil, fmt.Errorf("token validation failed: %w", err)
	}
	if !token.Valid {
		return nil, fmt.Errorf("invalid token")
	}

	alg := token.Method.Alg()
	if !v.allowedAlgs[alg] {
		return nil, fmt.Errorf("disallowed signing algorithm: %s", alg)
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("unexpected claims type")
	}

	if len(v.audiences) > 0 {
		if err := v.checkAudience(claims); err != nil {
			return nil, err
		}
	}

	id := &Identity{
		Subject:   claimString(claims, "sub"),
		Issuer:    claimString(claims, "iss"),
		SessionID: r.Header.Get("Mcp-Session-Id"),
		Provider:  v.providerName,
		Raw:       tokenStr,
		Type:      inferIdentityType(claims),
		Groups:    claimStringSlice(claims, "groups"),
		Scopes:    strings.Fields(claimString(claims, "scope")),
		Claims:    map[string]any(claims),
		JTI:       claimString(claims, "jti"),
	}
	if exp, ok := claims["exp"].(float64); ok {
		id.ExpiresAt = int64(exp)
	}

	return id, nil
}

func (v *JWKSVerifier) MatchesIssuer(iss string) bool {
	return v.issuer == iss
}

func (v *JWKSVerifier) keyFunc(token *jwt.Token) (any, error) {
	kid, _ := token.Header["kid"].(string)
	if kid == "" {
		return nil, fmt.Errorf("token missing kid header")
	}

	if key := v.getCachedKey(kid); key != nil {
		return key, nil
	}

	if err := v.fetchKeys(); err != nil {
		return nil, fmt.Errorf("failed to fetch JWKS: %w", err)
	}

	if key := v.getCachedKey(kid); key != nil {
		return key, nil
	}
	return nil, fmt.Errorf("key %s not found in JWKS", kid)
}

func (v *JWKSVerifier) getCachedKey(kid string) any {
	v.mu.RLock()
	defer v.mu.RUnlock()
	if time.Since(v.fetchedAt) > v.cacheTTL {
		return nil
	}
	return v.keys[kid]
}

func (v *JWKSVerifier) fetchKeys() error {
	resp, err := http.Get(v.jwksURI)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return err
	}

	var jwks struct {
		Keys []json.RawMessage `json:"keys"`
	}
	if err := json.Unmarshal(body, &jwks); err != nil {
		return fmt.Errorf("invalid JWKS response: %w", err)
	}

	newKeys := make(map[string]any, len(jwks.Keys))
	for _, raw := range jwks.Keys {
		var header struct {
			KID string `json:"kid"`
			KTY string `json:"kty"`
			Alg string `json:"alg"`
		}
		if err := json.Unmarshal(raw, &header); err != nil {
			continue
		}

		switch header.KTY {
		case "RSA":
			key, err := parseRSAKey(raw)
			if err == nil {
				newKeys[header.KID] = key
			}
		case "EC":
			key, err := parseECKey(raw)
			if err == nil {
				newKeys[header.KID] = key
			}
		}
	}

	v.mu.Lock()
	v.keys = newKeys
	v.fetchedAt = time.Now()
	v.mu.Unlock()
	return nil
}

func (v *JWKSVerifier) checkAudience(claims jwt.MapClaims) error {
	aud, err := claims.GetAudience()
	if err != nil || len(aud) == 0 {
		return fmt.Errorf("token missing audience claim")
	}
	for _, expected := range v.audiences {
		for _, got := range aud {
			if expected == got {
				return nil
			}
		}
	}
	return fmt.Errorf("audience mismatch: got %v, want one of %v", aud, v.audiences)
}

func inferIdentityType(claims jwt.MapClaims) IdentityType {
	if typ, ok := claims["identity_type"].(string); ok {
		switch typ {
		case "human":
			return IdentityHuman
		case "agent":
			return IdentityAgent
		case "autonomous":
			return IdentityAutonomous
		}
	}
	if _, ok := claims["sub"].(string); ok {
		if scope := claimString(claims, "scope"); strings.Contains(scope, "openid") {
			return IdentityHuman
		}
	}
	return IdentityUnknown
}

func claimString(claims jwt.MapClaims, key string) string {
	if v, ok := claims[key].(string); ok {
		return v
	}
	return ""
}

func claimStringSlice(claims jwt.MapClaims, key string) []string {
	switch v := claims[key].(type) {
	case []any:
		out := make([]string, 0, len(v))
		for _, item := range v {
			if s, ok := item.(string); ok {
				out = append(out, s)
			}
		}
		return out
	case []string:
		return v
	}
	return nil
}

func parseRSAKey(raw json.RawMessage) (*rsa.PublicKey, error) {
	var k struct {
		N string `json:"n"`
		E string `json:"e"`
	}
	if err := json.Unmarshal(raw, &k); err != nil {
		return nil, err
	}
	nb, err := base64.RawURLEncoding.DecodeString(k.N)
	if err != nil {
		return nil, err
	}
	eb, err := base64.RawURLEncoding.DecodeString(k.E)
	if err != nil {
		return nil, err
	}
	return &rsa.PublicKey{
		N: new(big.Int).SetBytes(nb),
		E: int(new(big.Int).SetBytes(eb).Int64()),
	}, nil
}

func parseECKey(raw json.RawMessage) (*ecdsa.PublicKey, error) {
	var k struct {
		Crv string `json:"crv"`
		X   string `json:"x"`
		Y   string `json:"y"`
	}
	if err := json.Unmarshal(raw, &k); err != nil {
		return nil, err
	}
	var curve elliptic.Curve
	switch k.Crv {
	case "P-256":
		curve = elliptic.P256()
	case "P-384":
		curve = elliptic.P384()
	case "P-521":
		curve = elliptic.P521()
	default:
		return nil, fmt.Errorf("unsupported curve: %s", k.Crv)
	}
	xb, err := base64.RawURLEncoding.DecodeString(k.X)
	if err != nil {
		return nil, err
	}
	yb, err := base64.RawURLEncoding.DecodeString(k.Y)
	if err != nil {
		return nil, err
	}
	return &ecdsa.PublicKey{
		Curve: curve,
		X:     new(big.Int).SetBytes(xb),
		Y:     new(big.Int).SetBytes(yb),
	}, nil
}
