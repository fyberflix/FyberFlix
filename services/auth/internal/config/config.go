package config

import (
	"fmt"
	"os"
	"strings"
	"time"
)

type Config struct {
	HTTPAddr      string
	DatabaseURL   string
	PublicBaseURL string // e.g. https://FyberFlix.zeaipc.in

	SessionTTL time.Duration // whole signup session
	HoldTTL    time.Duration // how long offered numbers stay reserved
	MaxRefresh int           // "show me 10 new numbers" limit per signup session

	FaceURL       string
	FaceToken     string
	JWTSeed       string // base64 of 32 bytes (Ed25519 seed)
	JWTKeyID      string
	AccessTTL     time.Duration
	RefreshTTL    time.Duration
	TokenIssuer   string
	TokenAudience string
}

func Load() (Config, error) {
	c := Config{
		HTTPAddr:      env("HTTP_ADDR", ":8080"),
		DatabaseURL:   os.Getenv("DATABASE_URL"),
		PublicBaseURL: strings.TrimRight(env("PUBLIC_BASE_URL", "https://FyberFlix.zeaipc.in"), "/"),
		SessionTTL:    30 * time.Minute,
		HoldTTL:       15 * time.Minute,
		MaxRefresh:    5,
		FaceURL:       os.Getenv("FACE_URL"),
		FaceToken:     os.Getenv("FACE_SERVICE_TOKEN"),
		JWTSeed:       os.Getenv("AUTH_JWT_SEED"),
		JWTKeyID:      env("AUTH_JWT_KID", "k1"),
		AccessTTL:     10 * time.Minute,
		RefreshTTL:    60 * 24 * time.Hour,
		TokenIssuer:   "fyberflix-auth",
		TokenAudience: "fyberflix",
	}
	for name, v := range map[string]string{
		"DATABASE_URL": c.DatabaseURL, "FACE_URL": c.FaceURL,
		"FACE_SERVICE_TOKEN": c.FaceToken, "AUTH_JWT_SEED": c.JWTSeed,
	} {
		if v == "" {
			return c, fmt.Errorf("%s is required", name)
		}
	}
	return c, nil
}

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
