// Command worker runs FyberFlix background jobs (transcode, purge, janitor).
package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/fyberflix/fyberflix/services/content/internal/config"
	"github.com/fyberflix/fyberflix/services/content/internal/objstore"
	"github.com/fyberflix/fyberflix/services/content/internal/s3sign"
	"github.com/fyberflix/fyberflix/services/content/internal/store"
	"github.com/fyberflix/fyberflix/services/content/internal/worker"
)

func main() {
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, nil)))
	cfg, err := config.Load()
	if err != nil {
		slog.Error("config", "err", err)
		os.Exit(1)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	st, err := store.Open(ctx, cfg.DatabaseURL)
	if err != nil {
		slog.Error("database", "err", err)
		os.Exit(1)
	}
	defer st.Close()
	obj := objstore.New(s3sign.Creds{AccessKey: cfg.S3AccessKey, SecretKey: cfg.S3SecretKey, Region: cfg.S3Region},
		cfg.S3Endpoint, cfg.S3PublicEndpoint)
	host, _ := os.Hostname()
	w := worker.New(worker.Config{ID: host, OriginalsBucket: cfg.OriginalsBucket, MediaBucket: cfg.MediaBucket,
		Concurrency: cfg.WorkerConcurrency}, st, obj)
	slog.Info("worker started", "concurrency", cfg.WorkerConcurrency)
	w.Run(ctx)
	slog.Info("worker stopped")
}
