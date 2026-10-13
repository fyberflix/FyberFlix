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

	"github.com/fyberflix/fyberflix/services/auth/internal/config"
	"github.com/fyberflix/fyberflix/services/auth/internal/faceclient"
	"github.com/fyberflix/fyberflix/services/auth/internal/httpapi"
	"github.com/fyberflix/fyberflix/services/auth/internal/janitor"
	"github.com/fyberflix/fyberflix/services/auth/internal/mailer"
	"github.com/fyberflix/fyberflix/services/auth/internal/riskclient"
	"github.com/fyberflix/fyberflix/services/auth/internal/store"
	"github.com/fyberflix/fyberflix/services/auth/internal/token"
)

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	cfg, err := config.Load()
	if err != nil {
		log.Error("config", "err", err)
		os.Exit(1)
	}
	acc, err := config.LoadAccount()
	if err != nil {
		log.Error("config", "err", err)
		os.Exit(1)
	}
	rk, err := config.LoadRisk(acc.AppEnv)
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

	pg := store.New(pool)
	face := faceclient.New(cfg.FaceURL, cfg.FaceToken)
	var mail httpapi.Mailer = mailer.Log{L: log}
	if acc.MailMode == "smtp" {
		mail = mailer.SMTP{Host: acc.SMTPHost, Port: acc.SMTPPort, User: acc.SMTPUser, Pass: acc.SMTPPass, From: acc.SMTPFrom}
	}
	api := httpapi.New(pg, face, signer,
		httpapi.Config{SessionTTL: cfg.SessionTTL, HoldTTL: cfg.HoldTTL, RefreshTTL: cfg.RefreshTTL,
			MaxRefresh: cfg.MaxRefresh, PublicBaseURL: cfg.PublicBaseURL}, log).
		WithAccount(pg, mail, httpapi.AccountConfig{OTPPepper: acc.OTPPepper})
	    WithRecovery(pg)
	if rk.URL != "" {
		api.WithRisk(riskclient.New(rk.URL, rk.Token), pg)
	} else {
		log.Warn("RISK_URL not set: risk checks are OFF (development only)")
	}
	go janitor.Run(ctx, pg, face, log, 5*time.Minute)
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
