package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/zeaipc/fyberflix/services/auth/internal/config"
	"github.com/zeaipc/fyberflix/services/auth/internal/faceclient"
	"github.com/zeaipc/fyberflix/services/auth/internal/httpapi"
	"github.com/zeaipc/fyberflix/services/auth/internal/store"
	"github.com/zeaipc/fyberflix/services/auth/internal/token"
)

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	cfg, err := config.Load()
	if err != nil {
		log.Error("config", "err", err)
		os.Exit(1)
	}
	signer, err := token.NewSigner(cfg.JWTSeed, cfg.JWTKeyID, cfg.TokenIssuer, cfg.TokenAudience, cfg.AccessTTL)
	if err != nil {
		log.Error("token signer", "err", err)
		os.Exit(1)
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	pool, err := pgxpool.New(ctx, cfg.DatabaseURL)
	if err != nil {
		log.Error("db", "err", err)
		os.Exit(1)
	}
	defer pool.Close()

	api := httpapi.New(store.New(pool), faceclient.New(cfg.FaceURL, cfg.FaceToken), signer,
		httpapi.Config{SessionTTL: cfg.SessionTTL, HoldTTL: cfg.HoldTTL, RefreshTTL: cfg.RefreshTTL,
			MaxRefresh: cfg.MaxRefresh, PublicBaseURL: cfg.PublicBaseURL}, log)
	srv := &http.Server{
		Addr: cfg.HTTPAddr, Handler: api.Handler(),
		ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 40 * time.Second, // face frames upload
		WriteTimeout: 60 * time.Second, IdleTimeout: 60 * time.Second,
	}
	go func() {
		<-ctx.Done()
		sctx, c := context.WithTimeout(context.Background(), 15*time.Second)
		defer c()
		_ = srv.Shutdown(sctx)
	}()
	log.Info("auth-service listening", "addr", cfg.HTTPAddr)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Error("server", "err", err)
		os.Exit(1)
	}
}
