package config

import (
	"fmt"
	"os"
	"time"
)

type Config struct {
	HTTPAddr    string
	DatabaseURL string
	SessionTTL  time.Duration // whole signup session
	HoldTTL     time.Duration // how long offered numbers stay reserved
	MaxRefresh  int           // "show me 10 new numbers" limit per session
}

func Load() (Config, error) {
	c := Config{
		HTTPAddr:    env("HTTP_ADDR", ":8080"),
		DatabaseURL: os.Getenv("DATABASE_URL"),
		SessionTTL:  30 * time.Minute,
		HoldTTL:     15 * time.Minute,
		MaxRefresh:  5,
	}
	if c.DatabaseURL == "" {
		return c, fmt.Errorf("DATABASE_URL is required")
	}
	return c, nil
}

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
