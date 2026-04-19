package identity

import (
	"context"
	"fmt"
	"net/http"
	"strings"
)

// IdentityType classifies the caller.
type IdentityType string

const (
	IdentityHuman      IdentityType = "human"
	IdentityAgent      IdentityType = "agent"
	IdentityAutonomous IdentityType = "autonomous"
	IdentityUnknown    IdentityType = "unknown"
)

type Identity struct {
	Subject      string
	Issuer       string
	SessionID    string
	Scopes       []string
	Raw          string
	Type         IdentityType
	Provider     string
	Groups       []string
	Claims       map[string]any
	ExpiresAt    int64
	JTI          string
}

type contextKey struct{}

func WithIdentity(ctx context.Context, id *Identity) context.Context {
	return context.WithValue(ctx, contextKey{}, id)
}

func FromContext(ctx context.Context) *Identity {
	id, _ := ctx.Value(contextKey{}).(*Identity)
	return id
}

// Verifier extracts and validates identity from an HTTP request.
type Verifier interface {
	Verify(r *http.Request) (*Identity, error)
}

// HeaderVerifier extracts a Bearer token from the configured header.
// In v0.1 it trusts the token as-is; JWKS validation is wired in later.
type HeaderVerifier struct {
	Header string
}

func NewHeaderVerifier(header string) *HeaderVerifier {
	return &HeaderVerifier{Header: header}
}

func (v *HeaderVerifier) Verify(r *http.Request) (*Identity, error) {
	val := r.Header.Get(v.Header)
	if val == "" {
		return nil, fmt.Errorf("missing identity header: %s", v.Header)
	}

	token := strings.TrimPrefix(val, "Bearer ")
	if token == val {
		return nil, fmt.Errorf("malformed Bearer token in %s", v.Header)
	}

	// v0.1: trust the token subject. Later: JWKS validation.
	return &Identity{
		Subject:   token,
		SessionID: r.Header.Get("Mcp-Session-Id"),
		Raw:       token,
	}, nil
}

// NoopVerifier always returns a synthetic identity (for dev/testing).
type NoopVerifier struct{}

func (v *NoopVerifier) Verify(r *http.Request) (*Identity, error) {
	return &Identity{
		Subject:   "dev-user",
		SessionID: r.Header.Get("Mcp-Session-Id"),
	}, nil
}
