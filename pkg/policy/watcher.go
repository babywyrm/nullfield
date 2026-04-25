// Package policy watcher provides hot-reload for policy files.
// When the policy YAML changes on disk (e.g., ConfigMap update),
// the watcher detects the change and swaps the rule engine atomically.
package policy

import (
	"crypto/sha256"
	"fmt"
	"log/slog"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

// HotLoader watches a policy file and reloads the rule engine when it changes.
type HotLoader struct {
	path     string
	interval time.Duration
	logger   *slog.Logger
	engine   atomic.Pointer[RuleEngine]
	lastHash [32]byte
	mu       sync.Mutex
	onReload func(Engine)
}

// NewHotLoader creates a watcher that polls the policy file at the given interval.
func NewHotLoader(path string, interval time.Duration, logger *slog.Logger) *HotLoader {
	return &HotLoader{
		path:     path,
		interval: interval,
		logger:   logger,
	}
}

// OnReload registers a callback invoked after a successful reload.
func (h *HotLoader) OnReload(fn func(Engine)) {
	h.onReload = fn
}

// Engine returns the current rule engine.
func (h *HotLoader) Engine() *RuleEngine {
	return h.engine.Load()
}

// LoadInitial loads the policy file for the first time.
func (h *HotLoader) LoadInitial() (*RuleEngine, error) {
	spec, err := LoadSpecFromFile(h.path)
	if err != nil {
		return nil, err
	}
	engine := NewRuleEngine(spec.Rules)
	h.engine.Store(engine)

	data, _ := os.ReadFile(h.path)
	h.lastHash = sha256.Sum256(data)

	h.logger.Info("policy loaded", "path", h.path, "rules", len(spec.Rules))
	return engine, nil
}

// Watch starts the polling loop. Blocks until ctx.Done or stop is called.
func (h *HotLoader) Watch(stop <-chan struct{}) {
	ticker := time.NewTicker(h.interval)
	defer ticker.Stop()

	for {
		select {
		case <-stop:
			return
		case <-ticker.C:
			h.check()
		}
	}
}

func (h *HotLoader) check() {
	h.mu.Lock()
	defer h.mu.Unlock()

	data, err := os.ReadFile(h.path)
	if err != nil {
		return
	}

	hash := sha256.Sum256(data)
	if hash == h.lastHash {
		return
	}

	spec, err := LoadSpecFromFile(h.path)
	if err != nil {
		h.logger.Warn("policy reload failed, keeping current policy", "error", err)
		return
	}

	engine := NewRuleEngine(spec.Rules)
	h.engine.Store(engine)
	h.lastHash = hash

	h.logger.Info("policy hot-reloaded", "path", h.path, "rules", len(spec.Rules))

	if h.onReload != nil {
		h.onReload(engine)
	}
}

// ForceReload triggers an immediate reload regardless of hash.
func (h *HotLoader) ForceReload() error {
	h.mu.Lock()
	defer h.mu.Unlock()

	spec, err := LoadSpecFromFile(h.path)
	if err != nil {
		return fmt.Errorf("force reload: %w", err)
	}

	engine := NewRuleEngine(spec.Rules)
	h.engine.Store(engine)

	data, _ := os.ReadFile(h.path)
	h.lastHash = sha256.Sum256(data)

	h.logger.Info("policy force-reloaded", "path", h.path, "rules", len(spec.Rules))
	return nil
}
