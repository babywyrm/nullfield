package main

import (
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/babywyrm/nullfield/pkg/injector"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(logger)

	cfg := injector.DefaultSidecarConfig()
	wh := injector.NewWebhook(cfg, logger)

	mux := http.NewServeMux()
	mux.Handle("/mutate", wh)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	})

	certFile := os.Getenv("NULLFIELD_INJECTOR_TLS_CERT")
	keyFile := os.Getenv("NULLFIELD_INJECTOR_TLS_KEY")
	addr := os.Getenv("NULLFIELD_INJECTOR_ADDR")
	if addr == "" {
		addr = ":8443"
	}

	server := &http.Server{
		Addr:    addr,
		Handler: mux,
	}

	go func() {
		if certFile != "" && keyFile != "" {
			logger.Info("nullfield injector starting (TLS)", "addr", addr)
			if err := server.ListenAndServeTLS(certFile, keyFile); err != nil && err != http.ErrServerClosed {
				logger.Error("injector server error", "error", err)
				os.Exit(1)
			}
		} else {
			logger.Warn("nullfield injector starting (plaintext — dev mode only)", "addr", addr)
			if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				logger.Error("injector server error", "error", err)
				os.Exit(1)
			}
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	logger.Info("nullfield injector shutting down")
}
