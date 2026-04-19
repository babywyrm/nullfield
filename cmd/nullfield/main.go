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

	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/babywyrm/nullfield/internal/config"
	"github.com/babywyrm/nullfield/pkg/anomaly"
	"github.com/babywyrm/nullfield/pkg/audit"
	"github.com/babywyrm/nullfield/pkg/budget"
	"github.com/babywyrm/nullfield/pkg/circuit"
	"github.com/babywyrm/nullfield/pkg/controller"
	"github.com/babywyrm/nullfield/pkg/hold"
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

	var ctrlClient *controller.Client
	if cfg.ControllerAddr != "" {
		var err error
		ctrlClient, err = controller.NewClient(cfg.ControllerAddr, logger)
		if err != nil {
			logger.Error("failed to connect to controller", "addr", cfg.ControllerAddr, "error", err)
			os.Exit(1)
		}
		defer ctrlClient.Close()
		logger.Info("controller mode enabled", "addr", cfg.ControllerAddr)
	}

	reg := registry.New()
	if cfg.ToolRegistryPath != "" {
		if err := reg.LoadFromFile(cfg.ToolRegistryPath); err != nil {
			logger.Warn("could not load tool registry, starting with empty set", "path", cfg.ToolRegistryPath, "error", err)
		} else {
			logger.Info("loaded tool registry", "path", cfg.ToolRegistryPath, "tools", len(reg.All()))
		}
	}

	emitters := []audit.Emitter{
		audit.NewLogEmitter(logger),
		audit.NewMetricsEmitter(),
	}

	if cfg.AuditEndpoint != "" {
		shutdown, err := audit.InitOTLP(context.Background(), cfg.AuditEndpoint, logger)
		if err != nil {
			logger.Warn("failed to init OTLP exporter", "error", err)
		} else {
			emitters = append(emitters, audit.NewOTLPEmitter())
			defer shutdown(context.Background())
		}
	}

	if ctrlClient != nil {
		emitters = append(emitters, &controllerEmitter{client: ctrlClient, logger: logger})
	}

	auditor := audit.NewMultiEmitter(emitters...)

	// Load full policy spec (identity, integrity, rules).
	var spec *v1alpha1.NullfieldPolicySpec
	if cfg.PolicyPath != "" {
		loaded, err := policy.LoadSpecFromFile(cfg.PolicyPath)
		if err != nil {
			logger.Warn("could not load policy file, using default deny-all", "path", cfg.PolicyPath, "error", err)
		} else {
			spec = loaded
			logger.Info("loaded policy", "path", cfg.PolicyPath, "rules", len(spec.Rules))
		}
	}
	if spec == nil || len(spec.Rules) == 0 {
		logger.Info("no policy rules loaded, defaulting to deny-all for tools/call")
		spec = &v1alpha1.NullfieldPolicySpec{
			Rules: []v1alpha1.Rule{
				{
					Action:          v1alpha1.ActionDeny,
					MCPMethod:       "tools/call",
					ToolNames:       []string{"*"},
					RequireIdentity: true,
				},
			},
		}
	}

	// Identity verification — opt-in via policy identity.enabled.
	var verifier identity.Verifier
	if spec.Identity != nil && spec.Identity.Enabled && len(spec.Identity.Providers) > 0 {
		var providers []*identity.JWKSVerifier
		for _, p := range spec.Identity.Providers {
			var clockSkew time.Duration
			if p.ClockSkew != "" {
				clockSkew, _ = time.ParseDuration(p.ClockSkew)
			}
			var allowedAlgs []string
			if spec.Identity.Validation != nil {
				allowedAlgs = spec.Identity.Validation.AllowedAlgorithms
			}
			providers = append(providers, identity.NewJWKSVerifier(identity.JWKSVerifierConfig{
				ProviderName: p.Name,
				Issuer:       p.Issuer,
				JWKSURI:      p.JWKSURI,
				Audiences:    p.Audiences,
				ClockSkew:    clockSkew,
				AllowedAlgs:  allowedAlgs,
				Header:       cfg.IdentityTokenHeader,
			}))
			logger.Info("configured identity provider", "name", p.Name, "issuer", p.Issuer)
		}
		verifier = identity.NewMultiVerifier(providers, cfg.IdentityTokenHeader)
		logger.Info("identity validation enabled", "providers", len(providers))
	} else if cfg.IdentityJWKSURL != "" {
		verifier = identity.NewHeaderVerifier(cfg.IdentityTokenHeader)
	} else {
		logger.Warn("no identity providers configured, using noop verifier (dev mode)")
		verifier = &identity.NoopVerifier{}
	}

	// Integrity checks — opt-in via policy integrity.enabled.
	var integrityChecker *identity.IntegrityChecker
	if spec.Integrity != nil && spec.Integrity.Enabled {
		integrityChecker = identity.NewIntegrityChecker(identity.IntegrityConfig{
			BindToSession: spec.Integrity.BindToSession,
			DetectReplay:  spec.Integrity.DetectReplay,
		})
		logger.Info("integrity checks enabled",
			"sessionBinding", spec.Integrity.BindToSession,
			"replayDetection", spec.Integrity.DetectReplay)
	}

	breaker := circuit.New(cfg.CircuitMaxCalls, cfg.CircuitMaxDuration)

	// Sweep expired sessions and replay entries every 60s.
	go func() {
		ticker := time.NewTicker(60 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			breaker.Sweep()
			if integrityChecker != nil {
				integrityChecker.Sweep()
			}
		}
	}()

	engine := policy.NewRuleEngine(spec.Rules)

	// Anomaly detection — opt-in via policy anomaly.enabled.
	var velocityTracker *anomaly.VelocityTracker
	if spec.Anomaly != nil && spec.Anomaly.Enabled && spec.Anomaly.Velocity != nil {
		action := anomaly.AlertActionLog
		if spec.Anomaly.Velocity.AlertAction == "DENY" {
			action = anomaly.AlertActionDeny
		}
		velocityTracker = anomaly.NewVelocityTracker(anomaly.VelocityConfig{
			Threshold:   spec.Anomaly.Velocity.Threshold,
			AlertAction: action,
		})
		logger.Info("anomaly detection enabled",
			"velocityThreshold", spec.Anomaly.Velocity.Threshold,
			"alertAction", spec.Anomaly.Velocity.AlertAction)
	}

	var budgetTracker *budget.Tracker
	if ctrlClient == nil {
		for _, r := range spec.Rules {
			if r.Budget != nil {
				budgetTracker = budget.New()
				logger.Info("budget tracking enabled")
				break
			}
		}
	}

	var holdManager *hold.Manager
	if ctrlClient == nil {
		for _, r := range spec.Rules {
			if r.Action == v1alpha1.ActionHold {
				holdManager = hold.NewManager()
				logger.Info("hold manager enabled")
				break
			}
		}
	}

	handler := proxy.NewHandler(proxy.HandlerOpts{
		UpstreamURL: upstream,
		Engine:      engine,
		Auditor:     auditor,
		Verifier:    verifier,
		Integrity:   integrityChecker,
		Velocity:    velocityTracker,
		Budgets:     budgetTracker,
		Holds:       holdManager,
		Registry:    reg,
		Breaker:     breaker,
		Logger:      logger,
	})

	if ctrlClient != nil {
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			if err := ctrlClient.RegisterSidecar(ctx, &controller.RegisterSidecarRequest{
				PodName:   os.Getenv("HOSTNAME"),
				Version:   "dev",
				ToolCount: int32(len(reg.All())),
				RuleCount: int32(len(spec.Rules)),
			}); err != nil {
				logger.Warn("failed to register with controller", "error", err)
			} else {
				logger.Info("registered with controller")
			}
		}()
	}

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
	adminMux.Handle("/metrics", promhttp.Handler())
	if holdManager != nil {
		hold.RegisterAdminHandlers(adminMux, holdManager)
		logger.Info("hold admin API registered at /admin/holds")
	}

	writeTimeout := 30 * time.Second
	if holdManager != nil {
		writeTimeout = 10 * time.Minute
	}

	proxyServer := &http.Server{
		Addr:         cfg.ListenAddr,
		Handler:      handler,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: writeTimeout,
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

type controllerEmitter struct {
	client *controller.Client
	logger *slog.Logger
}

func (e *controllerEmitter) Emit(_ context.Context, event audit.Event) {
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := e.client.ReportEvent(ctx, &controller.ReportEventRequest{
			EventType: string(event.Type),
			Method:    event.Method,
			Tool:      event.ToolName,
			Identity:  event.Identity,
			Reason:    event.Reason,
		}); err != nil {
			e.logger.Debug("controller report failed", "error", err)
		}
	}()
}
