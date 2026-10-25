package main

import (
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	v1alpha1 "github.com/babywyrm/nullfield/api/v1alpha1"
)

func TestBuildGatesRegistry(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	spec := &v1alpha1.NullfieldPolicySpec{}

	t.Run("unset runs no registry gate", func(t *testing.T) {
		t.Setenv("NULLFIELD_REGISTRY_PATH", "") // restores the caller's value after
		os.Unsetenv("NULLFIELD_REGISTRY_PATH")
		g, err := buildGates(spec, logger)
		if err != nil || g.Registry != nil {
			t.Fatalf("registry %v, err %v; want neither", g.Registry, err)
		}
		if g.Rates == nil {
			t.Fatal("no rate counter, so every rule with maxCallsPerMinute would refuse")
		}
	})

	t.Run("set but unreadable refuses to start", func(t *testing.T) {
		t.Setenv("NULLFIELD_REGISTRY_PATH", filepath.Join(t.TempDir(), "missing.yaml"))
		if _, err := buildGates(spec, logger); err == nil {
			t.Fatal("started without the registry it was given")
		}
	})

	t.Run("set and readable loads it", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "tools.yaml")
		os.WriteFile(path, []byte("apiVersion: nullfield.io/v1alpha1\nkind: ToolRegistry\ntools:\n  - name: echo\n"), 0o600)
		t.Setenv("NULLFIELD_REGISTRY_PATH", path)
		g, err := buildGates(spec, logger)
		if err != nil {
			t.Fatal(err)
		}
		if !g.Registry.IsRegistered("echo") {
			t.Fatal("echo not registered")
		}
	})
}

func TestAPolicyRunTokenBlockBuildsAVerifier(t *testing.T) {
	if v := runTokens(&v1alpha1.NullfieldPolicySpec{}); v != nil {
		t.Fatal("a verifier with no runToken block")
	}
	spec := &v1alpha1.NullfieldPolicySpec{RunToken: &v1alpha1.RunTokenConfig{
		JWKSURI: "http://controller/jwks", Audience: "cluster.local", MaxLifetime: "15m",
	}}
	if runTokens(spec) == nil {
		t.Fatal("a runToken block was dropped: every call would go unverified")
	}
}

func TestTheBreakerRunsOnlyWithRunTokensAndDeclaredLimits(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	rt := &v1alpha1.RunTokenConfig{JWKSURI: "http://controller/jwks", Audience: "cluster.local"}
	limits := v1alpha1.CircuitBreaker{MaxToolCallsPerSession: 50}
	t.Setenv("NULLFIELD_REGISTRY_PATH", "")
	os.Unsetenv("NULLFIELD_REGISTRY_PATH")

	for name, tc := range map[string]struct {
		spec v1alpha1.NullfieldPolicySpec
		want bool
	}{
		// Without run tokens there is no session on the mesh to key it on.
		"limits, no run tokens": {v1alpha1.NullfieldPolicySpec{CircuitBreaker: limits}, false},
		// The environment default ends a session at 5m, which would cut off a
		// long run nobody asked to limit.
		"run tokens, no limits": {v1alpha1.NullfieldPolicySpec{RunToken: rt}, false},
		"run tokens and limits": {v1alpha1.NullfieldPolicySpec{RunToken: rt, CircuitBreaker: limits}, true},
	} {
		t.Run(name, func(t *testing.T) {
			g, err := buildGates(&tc.spec, logger)
			if err != nil {
				t.Fatal(err)
			}
			if got := g.Breaker != nil; got != tc.want {
				t.Fatalf("breaker built = %v, want %v", got, tc.want)
			}
		})
	}
}
