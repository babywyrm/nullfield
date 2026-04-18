package main

import (
	"context"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/babywyrm/nullfield/internal/config"
	"github.com/babywyrm/nullfield/pkg/audit"
	"github.com/babywyrm/nullfield/pkg/circuit"
	"github.com/babywyrm/nullfield/pkg/identity"
	"github.com/babywyrm/nullfield/pkg/policy"
	"github.com/babywyrm/nullfield/pkg/proxy"
	"github.com/babywyrm/nullfield/pkg/registry"

	v1alpha1 "github.com/babywyrm/nullfield/api/v1alpha1"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(logger)

	cfg, err := config.Load()
	if err != nil {
		logger.Error("failed to load config", "error", err)
		os.Exit(1)
	}

	upstream, err := url.Parse("http://" + cfg.UpstreamAddr)
	if err != nil {
		logger.Error("invalid upstream address", "addr", cfg.UpstreamAddr, "error", err)
		os.Exit(1)
	}

	reg := registry.New()
	if cfg.ToolRegistryPath != "" {
		if err := reg.LoadFromFile(cfg.ToolRegistryPath); err != nil {
			logger.Warn("could not load tool registry, starting with empty set", "path", cfg.ToolRegistryPath, "error", err)
		} else {
			logger.Info("loaded tool registry", "path", cfg.ToolRegistryPath, "tools", len(reg.All()))
		}
	}

	var verifier identity.Verifier
	if cfg.IdentityJWKSURL != "" {
		verifier = identity.NewHeaderVerifier(cfg.IdentityTokenHeader)
	} else {
		logger.Warn("no JWKS URL configured, using noop identity verifier (dev mode)")
		verifier = &identity.NoopVerifier{}
	}

	breaker := circuit.New(cfg.CircuitMaxCalls, cfg.CircuitMaxDuration)

	// Sweep expired sessions every 60s.
	go func() {
		ticker := time.NewTicker(60 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			breaker.Sweep()
		}
	}()

	auditor := audit.NewLogEmitter(logger)

	var rules []v1alpha1.Rule
	if cfg.PolicyPath != "" {
		loaded, err := policy.LoadFromFile(cfg.PolicyPath)
		if err != nil {
			logger.Warn("could not load policy file, using default deny-all", "path", cfg.PolicyPath, "error", err)
		} else {
			rules = loaded
			logger.Info("loaded policy", "path", cfg.PolicyPath, "rules", len(rules))
		}
	}
	if len(rules) == 0 {
		logger.Info("no policy rules loaded, defaulting to deny-all for tools/call")
		rules = []v1alpha1.Rule{
			{
				Action:          v1alpha1.ActionDeny,
				MCPMethod:       "tools/call",
				ToolNames:       []string{"*"},
				RequireIdentity: true,
			},
		}
	}
	engine := policy.NewRuleEngine(rules)

	handler := proxy.NewHandler(proxy.HandlerOpts{
		UpstreamURL: upstream,
		Engine:      engine,
		Auditor:     auditor,
		Verifier:    verifier,
		Registry:    reg,
		Breaker:     breaker,
		Logger:      logger,
	})

	// Admin server — health, readiness, metrics.
	adminMux := http.NewServeMux()
	adminMux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	})
	adminMux.HandleFunc("/readyz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	})

	proxyServer := &http.Server{
		Addr:         cfg.ListenAddr,
		Handler:      handler,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	adminServer := &http.Server{
		Addr:    cfg.AdminAddr,
		Handler: adminMux,
	}

	go func() {
		logger.Info("admin server starting", "addr", cfg.AdminAddr)
		if err := adminServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Error("admin server error", "error", err)
		}
	}()

	go func() {
		logger.Info("nullfield proxy starting", "addr", cfg.ListenAddr, "upstream", cfg.UpstreamAddr)
		if err := proxyServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Error("proxy server error", "error", err)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	logger.Info("shutting down")
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	proxyServer.Shutdown(ctx)
	adminServer.Shutdown(ctx)
	logger.Info("nullfield stopped")
}
