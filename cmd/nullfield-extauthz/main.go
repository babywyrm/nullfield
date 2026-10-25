// Command nullfield-extauthz answers Envoy external authorization checks using
// nullfield's policy engine. The mesh intercepts; this decides.
//
// It is a separate binary from the proxy on purpose: the proxy terminates and
// forwards traffic, this only ever answers questions about it. Keeping them
// apart means a fault in the decision service cannot drop a request it was never
// carrying.
package main

import (
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"syscall"

	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"google.golang.org/grpc"
	"google.golang.org/grpc/health"
	healthv1 "google.golang.org/grpc/health/grpc_health_v1"

	v1alpha1 "github.com/babywyrm/nullfield/api/v1alpha1"
	"github.com/babywyrm/nullfield/internal/config"
	"github.com/babywyrm/nullfield/pkg/anomaly"
	"github.com/babywyrm/nullfield/pkg/audit"
	"github.com/babywyrm/nullfield/pkg/budget"
	"github.com/babywyrm/nullfield/pkg/extauthz"
	"github.com/babywyrm/nullfield/pkg/gates"
	"github.com/babywyrm/nullfield/pkg/policy"
	"github.com/babywyrm/nullfield/pkg/registry"
)

var version = "dev"

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))

	cfg, err := config.Load()
	if err != nil {
		logger.Error("configuration", "error", err)
		os.Exit(1)
	}

	spec, err := loadSpec(cfg.PolicyPath)
	if err != nil {
		logger.Error("policy engine", "error", err)
		os.Exit(1)
	}
	g, err := buildGates(spec, logger)
	if err != nil {
		logger.Error("gates", "error", err)
		os.Exit(1)
	}

	mode := extauthz.Mode(cfg.ExtAuthzMode)
	if !mode.Valid() {
		// Loud, because silently observing when an operator asked to enforce is
		// a security failure, and silently enforcing is an availability one.
		logger.Warn("unrecognised ext_authz mode, defaulting to observe",
			"configured", cfg.ExtAuthzMode,
			"valid", []string{string(extauthz.ModeNoOp), string(extauthz.ModeObserve), string(extauthz.ModeEnforce)})
	}

	server := extauthz.NewServer(extauthz.Config{
		Mode:   mode,
		Engine: policy.NewRuleEngine(spec.Rules),
		Gates:  g,
		Audit: audit.NewMultiEmitter(
			audit.NewLogEmitter(logger),
			audit.NewMetricsEmitter(),
		),
		Logger:  logger,
		LogPeer: os.Getenv("NULLFIELD_EXTAUTHZ_LOG_PEER") == "true",
	})

	listener, err := net.Listen("tcp", cfg.ExtAuthzListenAddr)
	if err != nil {
		logger.Error("listen", "addr", cfg.ExtAuthzListenAddr, "error", err)
		os.Exit(1)
	}

	grpcServer := grpc.NewServer()
	authv3.RegisterAuthorizationServer(grpcServer, server)

	// The standard gRPC health service, so Kubernetes can use a grpc probe. A
	// tcpSocket probe would report a listening socket as healthy even if the
	// Authorization service failed to register, which is the one failure that
	// matters here.
	healthSrv := health.NewServer()
	healthSrv.SetServingStatus("", healthv1.HealthCheckResponse_SERVING)
	healthv1.RegisterHealthServer(grpcServer, healthSrv)

	go func() {
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
		<-sig
		logger.Info("shutting down")
		healthSrv.SetServingStatus("", healthv1.HealthCheckResponse_NOT_SERVING)
		grpcServer.GracefulStop()
	}()

	logger.Info("nullfield ext_authz listening",
		"addr", cfg.ExtAuthzListenAddr,
		"mode", server.Mode(),
		"policy", cfg.PolicyPath,
		"version", version)

	if err := grpcServer.Serve(listener); err != nil {
		logger.Error("serve", "error", err)
		os.Exit(1)
	}
}

// loadSpec loads the same policy file the proxy loads, through the same call
// cmd/nullfield makes.
//
// Hot reload via policy.NewHotLoader is deliberately not wired here. The proxy
// wraps its engine so swaps stay transparent to in-flight requests; doing that
// correctly for a second entrypoint is its own change, and shipping it untested
// alongside a new front door would tangle two failure modes together.
func loadSpec(path string) (*v1alpha1.NullfieldPolicySpec, error) {
	if path == "" {
		return nil, fmt.Errorf("no policy path configured")
	}
	spec, err := policy.LoadSpecFromFile(path)
	if err != nil {
		return nil, fmt.Errorf("load policy from %s: %w", path, err)
	}
	return spec, nil
}

// buildGates builds the gates the proxy runs, from the same policy.
//
// There is no circuit breaker: it is keyed on the MCP session, which the mesh
// does not carry, so it could never trip.
func buildGates(spec *v1alpha1.NullfieldPolicySpec, logger *slog.Logger) (gates.Gates, error) {
	g := gates.Gates{Rates: gates.NewRates()}

	// Only when set explicitly. config.Load defaults the path, and an arbiter
	// deployed without a registry must not start refusing every tool because a
	// file it was never given is missing. One it was given and cannot read is a
	// refusal to start, not a quietly absent gate.
	if path, ok := os.LookupEnv("NULLFIELD_REGISTRY_PATH"); ok {
		g.Registry = registry.New()
		if err := g.Registry.LoadFromFile(path); err != nil {
			return g, fmt.Errorf("load tool registry from %s: %w", path, err)
		}
		logger.Info("loaded tool registry", "path", path, "tools", len(g.Registry.All()))
	}

	for _, r := range spec.Rules {
		if r.Budget != nil {
			g.Budgets = budget.New()
			logger.Info("budget tracking enabled")
			break
		}
	}

	if a := spec.Anomaly; a != nil && a.Enabled && a.Velocity != nil {
		action := anomaly.AlertActionLog
		if a.Velocity.AlertAction == "DENY" {
			action = anomaly.AlertActionDeny
		}
		g.Velocity = anomaly.NewVelocityTracker(anomaly.VelocityConfig{
			Threshold: a.Velocity.Threshold, AlertAction: action,
		})
		logger.Info("anomaly detection enabled",
			"velocityThreshold", a.Velocity.Threshold, "alertAction", a.Velocity.AlertAction)
	}
	return g, nil
}
