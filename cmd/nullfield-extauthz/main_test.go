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
