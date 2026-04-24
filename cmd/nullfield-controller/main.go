package main

import (
	"context"
	"encoding/json"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	"google.golang.org/grpc"

	pb "github.com/babywyrm/nullfield/api/v1alpha1/controllerpb"
	"github.com/babywyrm/nullfield/pkg/controller"
	"github.com/babywyrm/nullfield/pkg/crdwatcher"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(logger)

	grpcAddr := envOr("NULLFIELD_CONTROLLER_GRPC_ADDR", ":9092")
	adminAddr := envOr("NULLFIELD_CONTROLLER_ADMIN_ADDR", ":9093")
	healthAddr := envOr("NULLFIELD_CONTROLLER_HEALTH_ADDR", ":9091")
	webhookURL := envOr("NULLFIELD_ALERTING_WEBHOOK", "")

	holds := controller.NewHoldStore()
	budgets := controller.NewBudgetStore(controller.BudgetLimits{})
	events := controller.NewEventBuffer(0)
	sidecars := controller.NewSidecarRegistry()
	alerter := controller.NewAlerter(webhookURL, logger)

	srv := &controller.Server{
		Holds:    holds,
		Budgets:  budgets,
		Events:   events,
		Sidecars: sidecars,
		Alerter:  alerter,
		Logger:   logger,
	}

	// Background sweep: clean stale budgets and sidecars every 60s.
	go func() {
		ticker := time.NewTicker(60 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			budgets.Sweep()
			if n := sidecars.Sweep(); n > 0 {
				logger.Info("swept stale sidecars", "count", n)
			}
		}
	}()

	// --- CRD watcher (opt-in via NULLFIELD_CRD_WATCH=true) ---
	if envOr("NULLFIELD_CRD_WATCH", "") == "true" {
		crdWatchNS := envOr("NULLFIELD_CRD_WATCH_NAMESPACE", "")
		intervalStr := envOr("NULLFIELD_CRD_WATCH_INTERVAL", "30s")
		interval, err := time.ParseDuration(intervalStr)
		if err != nil {
			interval = 30 * time.Second
		}

		watcher, err := crdwatcher.New(crdwatcher.Config{
			Namespace:    crdWatchNS,
			SyncInterval: interval,
		}, logger)
		if err != nil {
			logger.Warn("CRD watcher init failed, CRD sync disabled", "error", err)
		} else {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			go watcher.Run(ctx, interval)
			logger.Info("CRD watcher enabled", "namespace", crdWatchNS, "interval", interval)
		}
	}

	// --- gRPC server ---
	lis, err := net.Listen("tcp", grpcAddr)
	if err != nil {
		logger.Error("failed to listen on gRPC addr", "addr", grpcAddr, "error", err)
		os.Exit(1)
	}
	grpcServer := grpc.NewServer()
	pb.RegisterNullfieldControllerServer(grpcServer, srv)

	go func() {
		logger.Info("gRPC server starting", "addr", grpcAddr)
		if err := grpcServer.Serve(lis); err != nil {
			logger.Error("gRPC server error", "error", err)
		}
	}()

	// --- Admin HTTP server ---
	adminMux := http.NewServeMux()
	adminMux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	})
	adminMux.HandleFunc("/readyz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	})

	adminMux.HandleFunc("/admin/holds", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		writeJSON(w, holds.List())
	})

	adminMux.HandleFunc("/admin/holds/", func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path[len("/admin/holds/"):]
		if path == "" {
			http.Error(w, "hold ID required", http.StatusBadRequest)
			return
		}

		// POST /admin/holds/{id}/approve or /admin/holds/{id}/deny
		var holdID, action string
		if i := lastSlash(path); i >= 0 {
			holdID = path[:i]
			action = path[i+1:]
		} else {
			holdID = path
		}

		if action == "" {
			if r.Method != http.MethodGet {
				http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
				return
			}
			h, ok := holds.Get(holdID)
			if !ok {
				http.Error(w, "not found", http.StatusNotFound)
				return
			}
			writeJSON(w, h)
			return
		}

		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		approver := r.Header.Get("X-Approver")
		if approver == "" {
			approver = "admin-api"
		}

		switch action {
		case "approve":
			if err := holds.Approve(holdID, approver); err != nil {
				http.Error(w, err.Error(), http.StatusNotFound)
				return
			}
			writeJSON(w, map[string]string{"status": "approved", "hold": holdID})
		case "deny":
			if err := holds.Deny(holdID, approver); err != nil {
				http.Error(w, err.Error(), http.StatusNotFound)
				return
			}
			writeJSON(w, map[string]string{"status": "denied", "hold": holdID})
		default:
			http.Error(w, "unknown action: "+action, http.StatusBadRequest)
		}
	})

	adminMux.HandleFunc("/admin/budgets", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		writeJSON(w, budgets.GetUsage())
	})

	adminMux.HandleFunc("/admin/events", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		eventType := r.URL.Query().Get("type")
		writeJSON(w, events.List(eventType, 200))
	})

	adminMux.HandleFunc("/admin/targets", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		writeJSON(w, sidecars.List())
	})

	adminServer := &http.Server{
		Addr:         adminAddr,
		Handler:      adminMux,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 10 * time.Minute, // long for hold SSE/polling
		IdleTimeout:  120 * time.Second,
	}

	go func() {
		logger.Info("admin HTTP server starting", "addr", adminAddr)
		if err := adminServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Error("admin server error", "error", err)
		}
	}()

	// --- Health/metrics server ---
	healthMux := http.NewServeMux()
	healthMux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	})
	healthMux.HandleFunc("/readyz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	})
	healthMux.Handle("/metrics", promhttp.Handler())

	healthServer := &http.Server{
		Addr:    healthAddr,
		Handler: healthMux,
	}

	go func() {
		logger.Info("health/metrics server starting", "addr", healthAddr)
		if err := healthServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Error("health server error", "error", err)
		}
	}()

	// --- Graceful shutdown ---
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	logger.Info("shutting down")
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	grpcServer.GracefulStop()
	adminServer.Shutdown(ctx)
	healthServer.Shutdown(ctx)
	logger.Info("nullfield-controller stopped")
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}

func lastSlash(s string) int {
	for i := len(s) - 1; i >= 0; i-- {
		if s[i] == '/' {
			return i
		}
	}
	return -1
}
