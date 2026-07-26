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

	"github.com/babywyrm/nullfield/internal/config"
	"github.com/babywyrm/nullfield/pkg/audit"
	"github.com/babywyrm/nullfield/pkg/extauthz"
	"github.com/babywyrm/nullfield/pkg/policy"
)

var version = "dev"

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))

	cfg, err := config.Load()
	if err != nil {
		logger.Error("configuration", "error", err)
		os.Exit(1)
	}

	engine, err := buildEngine(cfg.PolicyPath)
	if err != nil {
		logger.Error("policy engine", "error", err)
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
		Engine: engine,
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

// buildEngine loads the same policy file the proxy loads, through the same two
// calls cmd/nullfield makes.
//
// Hot reload via policy.NewHotLoader is deliberately not wired here. The proxy
// wraps its engine so swaps stay transparent to in-flight requests; doing that
// correctly for a second entrypoint is its own change, and shipping it untested
// alongside a new front door would tangle two failure modes together.
func buildEngine(path string) (policy.Engine, error) {
	if path == "" {
		return nil, fmt.Errorf("no policy path configured")
	}
	spec, err := policy.LoadSpecFromFile(path)
	if err != nil {
		return nil, fmt.Errorf("load policy from %s: %w", path, err)
	}
	return policy.NewRuleEngine(spec.Rules), nil
}
