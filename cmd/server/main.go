package main

import (
	"context"
	"errors"
	"flag"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/StefanPetrov49/imagescan-operator/internal/results"
)

func main() {
	dir := flag.String("results-dir", "/data", "directory with scan reports and summaries")
	addr := flag.String("addr", ":8080", "listen address")
	flag.Parse()

	log := slog.New(slog.NewJSONHandler(os.Stdout, nil))

	store, err := results.NewStore(*dir)
	if err != nil {
		log.Error("opening results dir", "dir", *dir, "err", err)
		os.Exit(1)
	}
	defer store.Close()

	srv := &http.Server{
		Addr:              *addr,
		Handler:           results.NewHandler(store, log),
		ReadHeaderTimeout: 5 * time.Second, // slow clients can't hold connections open forever
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	// Graceful shutdown: Kubernetes sends SIGTERM before killing the container.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, os.Interrupt)
	defer stop()
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
	}()

	log.Info("serving scan results", "addr", *addr, "dir", *dir)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Error("server failed", "err", err)
		os.Exit(1)
	}
}
