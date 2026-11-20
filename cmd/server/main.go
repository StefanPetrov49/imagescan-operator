// Command server serves scan results from the results volume over HTTP (read-only).
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
	log := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	if err := run(log); err != nil {
		log.Error("Server failed", "err", err)
		os.Exit(1)
	}
}

func run(log *slog.Logger) error {
	dir := flag.String("results-dir", "/data", "directory with scan reports and summaries")
	addr := flag.String("addr", ":8080", "listen address")
	flag.Parse()

	store, err := results.NewStore(*dir, log)
	if err != nil {
		return err
	}
	defer func() { _ = store.Close() }() // read-only: a failed Close loses nothing

	srv := &http.Server{
		Addr:              *addr,
		Handler:           results.NewHandler(store, log),
		ReadHeaderTimeout: 5 * time.Second, // slow clients can't hold connections open forever
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	// Graceful shutdown: Kubernetes sends SIGTERM before killing the container.
	// ListenAndServe returns as soon as Shutdown starts, so wait until Shutdown is done,
	// otherwise requests that are still running would be cut off.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, os.Interrupt)
	defer stop()
	shutdownDone := make(chan struct{})
	go func() {
		defer close(shutdownDone)
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := srv.Shutdown(shutdownCtx); err != nil {
			log.Warn("Graceful shutdown incomplete", "err", err)
		}
	}()

	log.Info("Serving scan results", "addr", *addr, "dir", *dir)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	<-shutdownDone
	return nil
}
