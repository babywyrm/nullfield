package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/babywyrm/nullfield/internal/config"
	"github.com/babywyrm/nullfield/pkg/anomaly"
	"github.com/babywyrm/nullfield/pkg/audit"
	"github.com/babywyrm/nullfield/pkg/budget"
	"github.com/babywyrm/nullfield/pkg/circuit"
	"github.com/babywyrm/nullfield/pkg/controller"
	"github.com/babywyrm/nullfield/pkg/credentials"
	"github.com/babywyrm/nullfield/pkg/hold"
	"github.com/babywyrm/nullfield/pkg/identity"
	"github.com/babywyrm/nullfield/pkg/inspection"
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

	var upstream *url.URL
	if cfg.UpstreamAddr != "" {
		upstream, err = url.Parse("http://" + cfg.UpstreamAddr)
		if err != nil {
			logger.Error("invalid upstream address", "addr", cfg.UpstreamAddr, "error", err)
			os.Exit(1)
		}
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

	// Tool lifecycle tracking — monitors upstream tools/list for drift and
	// rug-pull attacks (MCP-T03). Takes an initial snapshot and reconciles
	// periodically against the live tool set from the upstream server.
	lifecycleTracker := registry.NewLifecycleTracker(10)
	lifecycleTracker.Snapshot(reg)
	if upstream != nil && len(reg.All()) > 0 {
		go runLifecycleReconciliation(upstream.String(), reg, lifecycleTracker, logger)
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

	// Hot policy reload — polls the policy file for changes and swaps the
	// engine atomically. The hotLoaderEngine wrapper delegates Evaluate()
	// to the latest engine so swaps are transparent to in-flight requests.
	var activeEngine policy.Engine = engine
	if cfg.PolicyPath != "" {
		hotLoader := policy.NewHotLoader(cfg.PolicyPath, 10*time.Second, logger)
		if _, err := hotLoader.LoadInitial(); err != nil {
			logger.Warn("hot-loader initial load failed, using static engine", "error", err)
		} else {
			stopHotLoad := make(chan struct{})
			go hotLoader.Watch(stopHotLoad)
			defer close(stopHotLoad)
			activeEngine = &hotLoaderEngine{loader: hotLoader}
			logger.Info("policy hot-reload enabled", "interval", "10s")
		}
	}

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

	// Credential providers — always register env; vault and k8s are opt-in.
	credProvider := credentials.NewMultiProvider()
	credProvider.Register("env", &credentials.EnvProvider{})
	credProvider.Register("static", &credentials.StaticProvider{Secrets: map[string]string{}})

	if cfg.VaultAddr != "" {
		vp, err := credentials.NewVaultProvider(credentials.VaultConfig{
			Addr:       cfg.VaultAddr,
			Role:       cfg.VaultRole,
			Token:      os.Getenv("VAULT_TOKEN"),
			AuthMethod: cfg.VaultAuthMethod,
		})
		if err != nil {
			logger.Warn("vault provider init failed, vault credentials disabled", "error", err)
		} else {
			credProvider.Register("vault", credentials.NewCachedProvider(vp, cfg.CredentialCacheTTL))
			logger.Info("vault credential provider enabled", "addr", cfg.VaultAddr)
		}
	}

	// Build handler — gateway mode (multi-upstream) or sidecar mode (single upstream).
	var httpHandler http.Handler
	if cfg.RoutesPath != "" {
		gwCfg, err := proxy.LoadGatewayConfig(cfg.RoutesPath)
		if err != nil {
			logger.Error("failed to load gateway routes", "path", cfg.RoutesPath, "error", err)
			os.Exit(1)
		}
		var routes []*proxy.Route
		for _, rc := range gwCfg.Gateway.Routes {
			route, err := proxy.BuildRoute(rc)
			if err != nil {
				logger.Error("failed to build route", "name", rc.Name, "error", err)
				os.Exit(1)
			}
			routes = append(routes, route)
			logger.Info("gateway route loaded", "name", rc.Name, "upstream", rc.Upstream,
				"prefix", rc.ToolPrefix, "tools", len(route.Registry.All()))
		}
		router := proxy.NewRouter(routes)
		httpHandler = proxy.NewGatewayHandler(proxy.GatewayHandlerOpts{
			Router:      router,
			Auditor:     auditor,
			Verifier:    verifier,
			Integrity:   integrityChecker,
			Velocity:    velocityTracker,
			Budgets:     budgetTracker,
			Holds:       holdManager,
			Breaker:     breaker,
			Credentials: credProvider,
			Logger:      logger,
		})
		logger.Info("gateway mode enabled", "routes", len(routes))
	} else {
		// Response inspection — create an inspector with default rules when
		// any policy rule defines an inspection: block.
		var inspector *inspection.Inspector
		for _, r := range spec.Rules {
			if r.Inspection != nil && r.Inspection.Enabled {
				inspector = inspection.New(inspection.DefaultConfig())
				logger.Info("response inspection enabled")
				break
			}
		}

		httpHandler = proxy.NewHandler(proxy.HandlerOpts{
			UpstreamURL: upstream,
			Engine:      activeEngine,
			Auditor:     auditor,
			Verifier:    verifier,
			Integrity:   integrityChecker,
			Velocity:    velocityTracker,
			Budgets:     budgetTracker,
			Holds:       holdManager,
			Registry:    reg,
			Breaker:     breaker,
			Credentials: credProvider,
			Inspector:   inspector,
			Logger:      logger,
		})
	}

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
		Handler:      httpHandler,
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
		if cfg.RoutesPath != "" {
			logger.Info("nullfield gateway starting", "addr", cfg.ListenAddr, "routes", cfg.RoutesPath)
		} else {
			logger.Info("nullfield proxy starting", "addr", cfg.ListenAddr, "upstream", cfg.UpstreamAddr)
		}
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

// hotLoaderEngine wraps a HotLoader to satisfy the policy.Engine interface.
// On each Evaluate call it delegates to the latest atomically-swapped engine.
type hotLoaderEngine struct {
	loader *policy.HotLoader
}

func (h *hotLoaderEngine) Evaluate(ctx context.Context, req policy.Request) policy.Decision {
	return h.loader.Engine().Evaluate(ctx, req)
}

func (e *controllerEmitter) Emit(_ context.Context, event audit.Event) {
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := e.client.ReportEvent(ctx, &controller.ReportEventRequest{
			EventType:   string(event.Type),
			Method:      event.Method,
			Tool:        event.ToolName,
			Identity:    event.Identity,
			SessionId:   event.SessionID,
			Reason:      event.Reason,
			Target:      event.Target,
			Gate:        event.Gate,
			ReasonClass: event.ReasonClass,
			RuleIndex:   int32PtrFromIntPtr(event.RuleIndex),
			RuleId:      event.RuleID,
			PolicyRef:   event.PolicyRef,
			RegistryRef: event.RegistryRef,
			Route:       event.Route,
			Labels:      event.Labels,
			Timestamp:   timestamppb.New(event.Time),
		}); err != nil {
			e.logger.Debug("controller report failed", "error", err)
		}
	}()
}

func int32PtrFromIntPtr(v *int) *int32 {
	if v == nil {
		return nil
	}
	out := int32(*v)
	return &out
}

// runLifecycleReconciliation periodically fetches tools/list from the upstream
// MCP server and reconciles against the local registry. Logs rug-pull warnings
// when tool definitions change post-startup (MCP-T03).
func runLifecycleReconciliation(upstreamURL string, reg *registry.Registry, tracker *registry.LifecycleTracker, logger *slog.Logger) {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		liveTools, err := fetchUpstreamTools(upstreamURL)
		if err != nil {
			logger.Debug("lifecycle reconciliation: upstream fetch failed", "error", err)
			continue
		}

		report := registry.Reconcile(reg, liveTools)
		tracker.Snapshot(reg)

		if !report.HasDrift() {
			continue
		}

		if report.HasRugPull() {
			for _, rp := range report.RugPulls() {
				logger.Warn("RUG-PULL DETECTED: tool definition changed post-startup",
					"tool", rp.ToolName,
					"previousHash", rp.PreviousHash,
					"currentHash", rp.CurrentHash)
			}
		}
		if len(report.Added) > 0 {
			names := make([]string, len(report.Added))
			for i, a := range report.Added {
				names[i] = a.ToolName
			}
			logger.Warn("tool drift: new tools appeared upstream", "tools", names)
		}
		if len(report.Removed) > 0 {
			names := make([]string, len(report.Removed))
			for i, r := range report.Removed {
				names[i] = r.ToolName
			}
			logger.Info("tool drift: tools removed upstream", "tools", names)
		}
	}
}

// fetchUpstreamTools calls the MCP tools/list endpoint on the upstream server.
func fetchUpstreamTools(upstreamURL string) ([]v1alpha1.ToolRegistryEntry, error) {
	body, _ := json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "tools/list",
		"params":  map[string]any{},
	})

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Post(upstreamURL, "application/json", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var rpcResp struct {
		Result struct {
			Tools []struct {
				Name        string `json:"name"`
				Description string `json:"description,omitempty"`
			} `json:"tools"`
		} `json:"result"`
	}
	if err := json.Unmarshal(data, &rpcResp); err != nil {
		return nil, err
	}

	entries := make([]v1alpha1.ToolRegistryEntry, len(rpcResp.Result.Tools))
	for i, t := range rpcResp.Result.Tools {
		entries[i] = v1alpha1.ToolRegistryEntry{
			Name:        t.Name,
			Description: t.Description,
		}
	}
	return entries, nil
}
