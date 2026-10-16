// Package config reads the content service settings from environment variables.
package config

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	DatabaseURL string
	Addr        string

	AuthJWKSURL  string
	AuthIssuer   string
	AuthAudience string

	S3Endpoint        string // reachable from this container
	S3PublicEndpoint  string // reachable from users' devices
	S3Region          string
	S3AccessKey       string
	S3SecretKey       string
	OriginalsBucket   string
	MediaBucket       string
	MediaBaseURL      string
	MaxUploadBytes    int64
	UploadURLTTL      time.Duration
	WorkerConcurrency int
}

func get(k, def string) string {
	if v := strings.TrimSpace(os.Getenv(k)); v != "" {
		return v
	}
	return def
}

func Load() (Config, error) {
	c := Config{
		DatabaseURL:      get("DATABASE_URL", ""),
		Addr:             get("ADDR", ":8082"),
		AuthJWKSURL:      get("AUTH_JWKS_URL", "http://auth:8080/.well-known/jwks.json"),
		AuthIssuer:       get("AUTH_ISSUER", "fyberflix-auth"),
		AuthAudience:     get("AUTH_AUDIENCE", "fyberflix"),
		S3Endpoint:       strings.TrimRight(get("S3_ENDPOINT", ""), "/"),
		S3PublicEndpoint: strings.TrimRight(get("S3_PUBLIC_ENDPOINT", ""), "/"),
		S3Region:         get("S3_REGION", "us-east-1"),
		S3AccessKey:      get("S3_ACCESS_KEY", ""),
		S3SecretKey:      get("S3_SECRET_KEY", ""),
		OriginalsBucket:  get("S3_ORIGINALS_BUCKET", "fyber-originals"),
		MediaBucket:      get("S3_MEDIA_BUCKET", "fyber-media"),
		MediaBaseURL:     strings.TrimRight(get("MEDIA_BASE_URL", ""), "/"),
	}
	var err error
	if c.MaxUploadBytes, err = strconv.ParseInt(get("MAX_UPLOAD_BYTES", "536870912"), 10, 64); err != nil || c.MaxUploadBytes < 1 {
		return c, errors.New("MAX_UPLOAD_BYTES must be a positive integer")
	}
	if c.UploadURLTTL, err = time.ParseDuration(get("UPLOAD_URL_TTL", "30m")); err != nil {
		return c, fmt.Errorf("UPLOAD_URL_TTL: %w", err)
	}
	if c.WorkerConcurrency, err = strconv.Atoi(get("WORKER_CONCURRENCY", "1")); err != nil || c.WorkerConcurrency < 1 || c.WorkerConcurrency > 16 {
		return c, errors.New("WORKER_CONCURRENCY must be 1..16")
	}
	var missing []string
	for k, v := range map[string]string{"DATABASE_URL": c.DatabaseURL, "S3_ENDPOINT": c.S3Endpoint,
		"S3_PUBLIC_ENDPOINT": c.S3PublicEndpoint, "S3_ACCESS_KEY": c.S3AccessKey,
		"S3_SECRET_KEY": c.S3SecretKey, "MEDIA_BASE_URL": c.MediaBaseURL} {
		if v == "" {
			missing = append(missing, k)
		}
	}
	if len(missing) > 0 {
		return c, fmt.Errorf("missing required settings: %s", strings.Join(missing, ", "))
	}
	return c, nil
}
