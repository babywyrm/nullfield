package policy

import (
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"
)

const testPolicy = `apiVersion: nullfield.io/v1alpha1
kind: NullfieldPolicy
metadata:
  name: test
spec:
  selector:
    matchLabels: {}
  rules:
    - action: DENY
      mcpMethod: tools/call
      toolNames: ["*"]
`

const updatedPolicy = `apiVersion: nullfield.io/v1alpha1
kind: NullfieldPolicy
metadata:
  name: test
spec:
  selector:
    matchLabels: {}
  rules:
    - action: ALLOW
      mcpMethod: tools/call
      toolNames: ["safe.tool"]
    - action: DENY
      mcpMethod: tools/call
      toolNames: ["*"]
`

func TestHotLoader_LoadInitial(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.yaml")
	os.WriteFile(path, []byte(testPolicy), 0644)

	logger := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	loader := NewHotLoader(path, time.Second, logger)

	engine, err := loader.LoadInitial()
	if err != nil {
		t.Fatalf("LoadInitial failed: %v", err)
	}
	if engine == nil {
		t.Fatal("engine is nil")
	}
}

func TestHotLoader_DetectsChange(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.yaml")
	os.WriteFile(path, []byte(testPolicy), 0644)

	logger := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	loader := NewHotLoader(path, 50*time.Millisecond, logger)

	_, err := loader.LoadInitial()
	if err != nil {
		t.Fatalf("LoadInitial failed: %v", err)
	}

	reloaded := false
	loader.OnReload(func(e Engine) {
		reloaded = true
	})

	os.WriteFile(path, []byte(updatedPolicy), 0644)

	stop := make(chan struct{})
	go loader.Watch(stop)
	time.Sleep(200 * time.Millisecond)
	close(stop)

	if !reloaded {
		t.Fatal("expected reload callback to fire")
	}

	engine := loader.Engine()
	if engine == nil {
		t.Fatal("engine is nil after reload")
	}
}

func TestHotLoader_NoReloadOnSameContent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.yaml")
	os.WriteFile(path, []byte(testPolicy), 0644)

	logger := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	loader := NewHotLoader(path, 50*time.Millisecond, logger)

	_, err := loader.LoadInitial()
	if err != nil {
		t.Fatalf("LoadInitial failed: %v", err)
	}

	reloaded := false
	loader.OnReload(func(e Engine) {
		reloaded = true
	})

	stop := make(chan struct{})
	go loader.Watch(stop)
	time.Sleep(200 * time.Millisecond)
	close(stop)

	if reloaded {
		t.Fatal("should not reload when content is unchanged")
	}
}

func TestHotLoader_ForceReload(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.yaml")
	os.WriteFile(path, []byte(testPolicy), 0644)

	logger := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	loader := NewHotLoader(path, time.Minute, logger)

	_, err := loader.LoadInitial()
	if err != nil {
		t.Fatalf("LoadInitial failed: %v", err)
	}

	os.WriteFile(path, []byte(updatedPolicy), 0644)

	if err := loader.ForceReload(); err != nil {
		t.Fatalf("ForceReload failed: %v", err)
	}
}

func TestHotLoader_InvalidFileKeepsCurrent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.yaml")
	os.WriteFile(path, []byte(testPolicy), 0644)

	logger := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	loader := NewHotLoader(path, 50*time.Millisecond, logger)

	_, err := loader.LoadInitial()
	if err != nil {
		t.Fatalf("LoadInitial failed: %v", err)
	}

	os.WriteFile(path, []byte("invalid: yaml: [broken"), 0644)

	stop := make(chan struct{})
	go loader.Watch(stop)
	time.Sleep(200 * time.Millisecond)
	close(stop)

	engine := loader.Engine()
	if engine == nil {
		t.Fatal("engine should still be valid after failed reload")
	}
}
