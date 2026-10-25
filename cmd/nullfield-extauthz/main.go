// Command nullfield-extauthz answers Envoy external authorization checks using
// nullfield's policy engine. The mesh intercepts; this decides.
//
// It is a separate binary from the proxy on purpose: the proxy terminates and
// forwards traffic, this only ever answers questions about it. Keeping them
// apart means a fault in the decision service cannot drop a request it was never
// carrying.
package main

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"google.golang.org/grpc"
	"google.golang.org/grpc/health"
	healthv1 "google.golang.org/grpc/health/grpc_health_v1"

	v1alpha1 "github.com/babywyrm/nullfield/api/v1alpha1"
	"github.com/babywyrm/nullfield/internal/config"
	"github.com/babywyrm/nullfield/pkg/anomaly"
	"github.com/babywyrm/nullfield/pkg/audit"
	"github.com/babywyrm/nullfield/pkg/budget"
	"github.com/babywyrm/nullfield/pkg/circuit"
	"github.com/babywyrm/nullfield/pkg/extauthz"
	"github.com/babywyrm/nullfield/pkg/gates"
	"github.com/babywyrm/nullfield/pkg/identity"
	"github.com/babywyrm/nullfield/pkg/operations"
	"github.com/babywyrm/nullfield/pkg/policy"
	"github.com/babywyrm/nullfield/pkg/registry"
	"github.com/babywyrm/nullfield/pkg/signals"
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

	if g.Breaker != nil {
		// ponytail: Sweep only drops runs past twice maxSessionDuration, so a
		// calls-only limit keeps one small entry per run until restart. Bound it
		// by token expiry if run volume makes that matter.
		go func() {
			for range time.Tick(time.Minute) {
				g.Breaker.Sweep()
			}
		}()
	}

	rt := runTokens(spec)
	if rt != nil {
		logger.Info("run tokens verified", "audience", spec.RunToken.Audience, "optional", spec.RunToken.Optional)
	}
	var ops *operations.Map
	if dir := os.Getenv("NULLFIELD_OPERATIONS_DIR"); dir != "" {
		if ops, err = operations.LoadDir(dir); err != nil {
			logger.Error("operation maps", "error", err)
			os.Exit(1)
		}
		logger.Info("loaded operation maps", "dir", dir)
	}
	emitters := []audit.Emitter{audit.NewLogEmitter(logger), audit.NewMetricsEmitter()}
	if endpoint := os.Getenv("NULLFIELD_AUDIT_ENDPOINT"); endpoint != "" {
		shutdown, err := audit.InitOTLP(context.Background(), endpoint, logger)
		if err != nil {
			logger.Error("OTLP export", "endpoint", endpoint, "error", err)
			os.Exit(1)
		}
		defer shutdown(context.Background())
		emitters = append(emitters, audit.NewOTLPEmitter())
	}

	sinks, err := signalSinks(logger)
	if err != nil {
		logger.Error("signals", "error", err)
		os.Exit(1)
	}
	emitters = append(emitters, sinks...)

	server := extauthz.NewServer(extauthz.Config{
		Mode:             mode,
		Engine:           policy.NewRuleEngine(spec.Rules),
		Gates:            g,
		RunTokens:        rt,
		RunTokenOptional: rt != nil && spec.RunToken.Optional,
		Operations:       ops,
		Audit:            audit.NewMultiEmitter(emitters...),
		Logger:           logger,
		LogPeer:          os.Getenv("NULLFIELD_EXTAUTHZ_LOG_PEER") == "true",
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

// runTokens builds the run token verifier the policy asks for, or nil.
// LoadSpecFromFile has already refused a block missing its keys or trust
// domain, or with an unparseable duration.
func runTokens(spec *v1alpha1.NullfieldPolicySpec) *identity.RunTokenVerifier {
	rt := spec.RunToken
	if rt == nil {
		return nil
	}
	maxLifetime, _ := time.ParseDuration(rt.MaxLifetime)
	clockSkew, _ := time.ParseDuration(rt.ClockSkew)
	return identity.NewRunTokenVerifier(identity.RunTokenConfig{
		JWKSURI: rt.JWKSURI, Audience: rt.Audience, Issuer: rt.Issuer,
		MaxLifetime: maxLifetime, ClockSkew: clockSkew,
	})
}

// signalSinks builds the outward event channels the environment asks for. A
// channel asked for and not buildable, or an event type this service never
// emits, refuses to start rather than never signalling.
func signalSinks(logger *slog.Logger) ([]audit.Emitter, error) {
	emitted := map[audit.EventType]bool{
		audit.EventCircuitTripped: true, audit.EventArbiterDecision: true, audit.EventAnomalyVelocity: true,
	}
	types := []audit.EventType{audit.EventCircuitTripped}
	if v := os.Getenv("NULLFIELD_SIGNAL_EVENTS"); v != "" {
		types = nil
		for _, t := range strings.Split(v, ",") {
			t := audit.EventType(strings.TrimSpace(t))
			if !emitted[t] {
				return nil, fmt.Errorf("NULLFIELD_SIGNAL_EVENTS: %q is not an event this service emits", t)
			}
			types = append(types, t)
		}
	}

	var sinks []audit.Emitter
	if os.Getenv("NULLFIELD_SIGNAL_KUBE_EVENTS") == "true" {
		k, err := signals.NewKubeEvents(signals.InCluster())
		if err != nil {
			return nil, err
		}
		sinks = append(sinks, signals.NewSink("kube-events", types, k.Deliver, logger))
		logger.Info("signalling as Kubernetes Events", "types", types)
	}
	if u := os.Getenv("NULLFIELD_SIGNAL_WEBHOOK_URL"); u != "" {
		secret, err := os.ReadFile(os.Getenv("NULLFIELD_SIGNAL_WEBHOOK_SECRET_FILE"))
		if err != nil {
			return nil, fmt.Errorf("NULLFIELD_SIGNAL_WEBHOOK_SECRET_FILE: %w", err)
		}
		w, err := signals.NewWebhook(u, bytes.TrimSpace(secret))
		if err != nil {
			return nil, err
		}
		sinks = append(sinks, signals.NewSink("webhook", types, w.Deliver, logger))
		logger.Info("signalling by webhook", "types", types)
	}
	return sinks, nil
}

// buildGates builds the gates the proxy runs, from the same policy.
//
// The circuit breaker is keyed on a session, and the mesh's only session is a
// run token's run ID, so it runs only with run tokens. It also needs limits
// the policy declares: the environment default ends a session after 5m,
// which would cut off a long run nobody asked to limit.
func buildGates(spec *v1alpha1.NullfieldPolicySpec, logger *slog.Logger) (gates.Gates, error) {
	g := gates.Gates{Rates: gates.NewRates()}

	if cb := spec.CircuitBreaker; spec.RunToken != nil && (cb.MaxToolCallsPerSession > 0 || cb.MaxSessionDuration > 0) {
		g.Breaker = circuit.New(cb.MaxToolCallsPerSession, cb.MaxSessionDuration)
		logger.Info("circuit breaker per run",
			"maxCallsPerRun", cb.MaxToolCallsPerSession, "maxRunDuration", cb.MaxSessionDuration)
	}

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
