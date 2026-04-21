package credentials

import (
	"context"
	"fmt"
	"os"
)

// Provider fetches secrets for credential injection.
type Provider interface {
	Fetch(ctx context.Context, ref string) (string, error)
}

// EnvProvider reads secrets from environment variables (dev/testing).
type EnvProvider struct{}

func (p *EnvProvider) Fetch(_ context.Context, ref string) (string, error) {
	val := os.Getenv(ref)
	if val == "" {
		return "", fmt.Errorf("env credential %q not found", ref)
	}
	return val, nil
}

// StaticProvider returns pre-loaded secrets (testing only).
type StaticProvider struct {
	Secrets map[string]string
}

func (p *StaticProvider) Fetch(_ context.Context, ref string) (string, error) {
	val, ok := p.Secrets[ref]
	if !ok {
		return "", fmt.Errorf("static credential %q not found", ref)
	}
	return val, nil
}

// MultiProvider routes credential fetches to the correct backend
// based on the "from" field in the CredentialRef.
type MultiProvider struct {
	providers map[string]Provider
}

func NewMultiProvider() *MultiProvider {
	return &MultiProvider{providers: make(map[string]Provider)}
}

func (p *MultiProvider) Register(name string, provider Provider) {
	p.providers[name] = provider
}

func (p *MultiProvider) Fetch(ctx context.Context, ref string) (string, error) {
	return p.FetchFrom(ctx, "", ref)
}

// FetchFrom fetches a credential from a specific backend.
func (p *MultiProvider) FetchFrom(ctx context.Context, from, ref string) (string, error) {
	if from == "" {
		from = "env"
	}
	provider, ok := p.providers[from]
	if !ok {
		return "", fmt.Errorf("unknown credential provider %q", from)
	}
	return provider.Fetch(ctx, ref)
}

func (p *MultiProvider) HasProvider(name string) bool {
	_, ok := p.providers[name]
	return ok
}
