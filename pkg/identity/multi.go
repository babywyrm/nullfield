package identity

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/golang-jwt/jwt/v5"
)

// MultiVerifier tries multiple JWKS providers in order, matching by issuer claim.
// Falls back to the first provider if the token can't be pre-parsed for issuer.
type MultiVerifier struct {
	providers []*JWKSVerifier
	header    string
}

func NewMultiVerifier(providers []*JWKSVerifier, header string) *MultiVerifier {
	if header == "" {
		header = "Authorization"
	}
	return &MultiVerifier{providers: providers, header: header}
}

func (m *MultiVerifier) Verify(r *http.Request) (*Identity, error) {
	raw := r.Header.Get(m.header)
	if raw == "" {
		return nil, fmt.Errorf("missing header: %s", m.header)
	}
	tokenStr := strings.TrimPrefix(raw, "Bearer ")

	iss := peekIssuer(tokenStr)

	if iss != "" {
		for _, p := range m.providers {
			if p.MatchesIssuer(iss) {
				return p.Verify(r)
			}
		}
		return nil, fmt.Errorf("no provider configured for issuer: %s", iss)
	}

	var lastErr error
	for _, p := range m.providers {
		id, err := p.Verify(r)
		if err == nil {
			return id, nil
		}
		lastErr = err
	}
	return nil, fmt.Errorf("all providers failed, last error: %w", lastErr)
}

// peekIssuer extracts the iss claim without verifying the signature.
func peekIssuer(tokenStr string) string {
	parser := jwt.NewParser(jwt.WithoutClaimsValidation())
	token, _, err := parser.ParseUnverified(tokenStr, jwt.MapClaims{})
	if err != nil {
		return ""
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return ""
	}
	iss, _ := claims["iss"].(string)
	return iss
}
