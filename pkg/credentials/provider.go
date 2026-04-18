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
