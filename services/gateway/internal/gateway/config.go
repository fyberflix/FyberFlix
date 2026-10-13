// Package gateway is FyberFlix's single public entry point. It is the ONLY service that may be
// reached from the internet; every backend trusts the X-Real-IP / X-Request-Id it sets.
package gateway

import (
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"os"
	"strconv"
	"strings"
)

type Config struct {
	Addr         string
	AuthURL      *url.URL
	WebURL       *url.URL // optional: serves FyberFlix.zeaipc.in/{name} pages
	Origins      map[string]bool
	TrustedProxy []netip.Prefix // load balancers whose X-Forwarded-For we believe
	StaffNets    []netip.Prefix // where /v1/staff/* may be called from
	RateRPS      float64
	RateBurst    int
	HSTS         bool
}

func LoadConfig() (Config, error) {
	c := Config{Addr: env("GATEWAY_ADDR", ":8080"), Origins: map[string]bool{}}
	var err error
	if c.AuthURL, err = parseURL("UPSTREAM_AUTH", true); err != nil {
		return c, err
	}
	if c.WebURL, err = parseURL("UPSTREAM_WEB", false); err != nil {
		return c, err
	}
	for _, o := range split(os.Getenv("ALLOWED_ORIGINS")) {
		u, err := url.Parse(o)
		if err != nil || u.Scheme == "" || u.Host == "" || u.Path != "" || o == "*" {
			return c, fmt.Errorf("ALLOWED_ORIGINS entry %q must be an exact origin like https://fyberflix.zeaipc.in", o)
		}
		c.Origins[o] = true
	}
	if c.TrustedProxy, err = prefixes("TRUSTED_PROXIES", ""); err != nil {
		return c, err
	}
	if c.StaffNets, err = prefixes("STAFF_CIDRS", "127.0.0.0/8,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,::1/128"); err != nil {
		return c, err
	}
	if c.RateRPS, err = strconv.ParseFloat(env("RATE_RPS", "20"), 64); err != nil || c.RateRPS <= 0 {
		return c, errors.New("RATE_RPS must be a positive number")
	}
	if c.RateBurst, err = strconv.Atoi(env("RATE_BURST", "40")); err != nil || c.RateBurst < 1 {
		return c, errors.New("RATE_BURST must be a positive integer")
	}
	c.HSTS = env("HSTS", "off") == "on"
	return c, nil
}

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func split(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func parseURL(key string, required bool) (*url.URL, error) {
	v := os.Getenv(key)
	if v == "" {
		if required {
			return nil, fmt.Errorf("%s is required", key)
		}
		return nil, nil
	}
	u, err := url.Parse(v)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, fmt.Errorf("%s must be an http(s) URL", key)
	}
	return u, nil
}

func prefixes(key, def string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, s := range split(env(key, def)) {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return nil, fmt.Errorf("%s: bad CIDR %q", key, s)
		}
		out = append(out, p.Masked())
	}
	return out, nil
}
