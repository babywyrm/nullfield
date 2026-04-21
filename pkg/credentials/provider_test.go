package credentials

import (
	"context"
	"testing"
	"time"
)

func TestEnvProvider(t *testing.T) {
	t.Setenv("TEST_CRED_123", "secret-value")

	p := &EnvProvider{}
	val, err := p.Fetch(context.Background(), "TEST_CRED_123")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if val != "secret-value" {
		t.Fatalf("expected 'secret-value', got %q", val)
	}

	_, err = p.Fetch(context.Background(), "NONEXISTENT_CRED")
	if err == nil {
		t.Fatal("expected error for missing env var")
	}
}

func TestStaticProvider(t *testing.T) {
	p := &StaticProvider{Secrets: map[string]string{
		"db-pass": "hunter2",
	}}

	val, err := p.Fetch(context.Background(), "db-pass")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if val != "hunter2" {
		t.Fatalf("expected 'hunter2', got %q", val)
	}

	_, err = p.Fetch(context.Background(), "missing")
	if err == nil {
		t.Fatal("expected error for missing key")
	}
}

func TestMultiProvider(t *testing.T) {
	mp := NewMultiProvider()
	mp.Register("static", &StaticProvider{Secrets: map[string]string{
		"api-key": "sk-test-123",
	}})
	mp.Register("env", &EnvProvider{})

	t.Setenv("MY_ENV_SECRET", "env-val")

	val, err := mp.FetchFrom(context.Background(), "static", "api-key")
	if err != nil {
		t.Fatalf("static fetch failed: %v", err)
	}
	if val != "sk-test-123" {
		t.Fatalf("expected 'sk-test-123', got %q", val)
	}

	val, err = mp.FetchFrom(context.Background(), "env", "MY_ENV_SECRET")
	if err != nil {
		t.Fatalf("env fetch failed: %v", err)
	}
	if val != "env-val" {
		t.Fatalf("expected 'env-val', got %q", val)
	}

	// Default routes to env.
	val, err = mp.FetchFrom(context.Background(), "", "MY_ENV_SECRET")
	if err != nil {
		t.Fatalf("default fetch failed: %v", err)
	}
	if val != "env-val" {
		t.Fatalf("expected 'env-val', got %q", val)
	}

	_, err = mp.FetchFrom(context.Background(), "vault", "anything")
	if err == nil {
		t.Fatal("expected error for unregistered provider")
	}

	if !mp.HasProvider("static") {
		t.Fatal("expected HasProvider('static') to return true")
	}
	if mp.HasProvider("vault") {
		t.Fatal("expected HasProvider('vault') to return false")
	}
}

func TestCachedProvider(t *testing.T) {
	calls := 0
	inner := &StaticProvider{Secrets: map[string]string{"key": "val"}}
	counting := &countingProvider{inner: inner, calls: &calls}

	cached := NewCachedProvider(counting, 1*time.Hour)

	val, err := cached.Fetch(context.Background(), "key")
	if err != nil {
		t.Fatalf("first fetch failed: %v", err)
	}
	if val != "val" {
		t.Fatalf("expected 'val', got %q", val)
	}
	if calls != 1 {
		t.Fatalf("expected 1 call, got %d", calls)
	}

	// Second fetch should be cached.
	val, err = cached.Fetch(context.Background(), "key")
	if err != nil {
		t.Fatalf("cached fetch failed: %v", err)
	}
	if val != "val" {
		t.Fatalf("expected 'val', got %q", val)
	}
	if calls != 1 {
		t.Fatalf("expected still 1 call after cache hit, got %d", calls)
	}
}

func TestCachedProviderSweep(t *testing.T) {
	inner := &StaticProvider{Secrets: map[string]string{"key": "val"}}
	cached := NewCachedProvider(inner, 1*time.Millisecond)

	_, err := cached.Fetch(context.Background(), "key")
	if err != nil {
		t.Fatalf("fetch failed: %v", err)
	}

	time.Sleep(5 * time.Millisecond)
	cached.Sweep()

	cached.mu.RLock()
	_, exists := cached.cache["key"]
	cached.mu.RUnlock()
	if exists {
		t.Fatal("expected cache entry to be swept")
	}
}

type countingProvider struct {
	inner Provider
	calls *int
}

func (p *countingProvider) Fetch(ctx context.Context, ref string) (string, error) {
	*p.calls++
	return p.inner.Fetch(ctx, ref)
}
