// Command content is the FyberFlix content API (reels/videos).
package main

import (
	"context"
	"crypto/rand"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/fyberflix/fyberflix/libs/authz"
	"github.com/fyberflix/fyberflix/services/content/internal/api"
	"github.com/fyberflix/fyberflix/services/content/internal/config"
	"github.com/fyberflix/fyberflix/services/content/internal/objstore"
	"github.com/fyberflix/fyberflix/services/content/internal/s3sign"
	"github.com/fyberflix/fyberflix/services/content/internal/store"
)

func newUUID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
}

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
	ver := authz.New(authz.Config{JWKSURL: cfg.AuthJWKSURL, Issuer: cfg.AuthIssuer, Audience: cfg.AuthAudience})
	srv := api.New(api.Config{OriginalsBucket: cfg.OriginalsBucket, MaxUploadBytes: cfg.MaxUploadBytes,
		UploadURLTTL: cfg.UploadURLTTL, MediaBaseURL: cfg.MediaBaseURL}, st, obj, ver, newUUID)

	hs := &http.Server{Addr: cfg.Addr, Handler: srv.Handler(),
		ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second,
		WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16 << 10}
	go func() {
		<-ctx.Done()
		sc, c := context.WithTimeout(context.Background(), 10*time.Second)
		defer c()
		_ = hs.Shutdown(sc)
	}()
	slog.Info("content api listening", "addr", cfg.Addr)
	if err := hs.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		slog.Error("server", "err", err)
		os.Exit(1)
	}
}
