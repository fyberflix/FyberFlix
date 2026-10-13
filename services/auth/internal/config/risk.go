package config

import (
	"errors"
	"os"
)

// Risk configures the optional risk-service. In production it is mandatory.
type Risk struct {
	URL   string
	Token string
}

func LoadRisk(appEnv string) (Risk, error) {
	r := Risk{URL: os.Getenv("RISK_URL"), Token: os.Getenv("RISK_SERVICE_TOKEN")}
	if r.URL == "" {
		if appEnv == "production" {
			return r, errors.New("RISK_URL is required when APP_ENV=production")
		}
		return r, nil // development: risk checks off
	}
	if len(r.Token) < 32 {
		return r, errors.New("RISK_SERVICE_TOKEN must be at least 32 characters")
	}
	return r, nil
}
