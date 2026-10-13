package gateway

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

type seen struct {
	mu   sync.Mutex
	last http.Header
	path string
	hits int
}

func upstream(t *testing.T, name string, s *seen) *url.URL {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		s.last, s.path = r.Header.Clone(), r.URL.Path
		s.hits++
		s.mu.Unlock()
		_, _ = io.Copy(io.Discard, r.Body)
		w.Header().Set("X-Upstream", name)
		_, _ = w.Write([]byte("ok"))
	}))
	t.Cleanup(srv.Close)
	u, _ := url.Parse(srv.URL)
	return u
}

func pfx(s ...string) []netip.Prefix {
	var out []netip.Prefix
	for _, x := range s {
		out = append(out, netip.MustParsePrefix(x))
	}
	return out
}

type rig struct {
	g         *Gateway
	auth, web *seen
}

func newRig(t *testing.T, mod func(*Config)) *rig {
	r := &rig{auth: &seen{}, web: &seen{}}
	cfg := Config{AuthURL: upstream(t, "auth", r.auth), WebURL: upstream(t, "web", r.web),
		Origins: map[string]bool{"https://fyberflix.zeaipc.in": true}, RateRPS: 1000, RateBurst: 1000,
		StaffNets: pfx("10.0.0.0/8")}
	if mod != nil {
		mod(&cfg)
	}
	r.g = New(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	return r
}

func (r *rig) do(method, path, remote string, hdr map[string]string, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.RemoteAddr = remote
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	r.g.Handler().ServeHTTP(w, req)
	return w
}

func TestRouting(t *testing.T) {
	r := newRig(t, nil)
	if w := r.do("GET", "/v1/profiles/arman", "1.2.3.4:5", nil, ""); w.Header().Get("X-Upstream") != "auth" {
		t.Fatalf("/v1 must go to auth: %d", w.Code)
	}
	if w := r.do("GET", "/.well-known/jwks.json", "1.2.3.4:5", nil, ""); w.Header().Get("X-Upstream") != "auth" {
		t.Fatal("jwks must go to auth")
	}
	if w := r.do("GET", "/Arman_Films", "1.2.3.4:5", nil, ""); w.Header().Get("X-Upstream") != "web" {
		t.Fatal("profile pages go to the web app")
	}
	if w := r.do("GET", "/healthz", "1.2.3.4:5", nil, ""); w.Code != 200 || r.auth.hits != 2 {
		t.Fatalf("healthz is answered locally: %d hits=%d", w.Code, r.auth.hits)
	}
	r2 := newRig(t, func(c *Config) { c.WebURL = nil })
	if w := r2.do("GET", "/anything", "1.2.3.4:5", nil, ""); w.Code != 404 {
		t.Fatalf("no web upstream -> 404, got %d", w.Code)
	}
}

func TestClientIdentityHeadersCannotBeSpoofed(t *testing.T) {
	r := newRig(t, nil)
	r.do("POST", "/v1/login/start", "203.0.113.9:4444", map[string]string{
		"X-Real-IP": "6.6.6.6", "X-Forwarded-For": "7.7.7.7", "X-Request-Id": "forged",
		"X-User-Id": "admin", "Forwarded": "for=8.8.8.8", "Authorization": "Bearer abc"}, `{}`)
	h := r.auth.last
	if h.Get("X-Real-IP") != "203.0.113.9" {
		t.Fatalf("X-Real-IP must be the TCP peer, got %q", h.Get("X-Real-IP"))
	}
	if h.Get("X-Forwarded-For") != "" && strings.Contains(h.Get("X-Forwarded-For"), "7.7.7.7") {
		t.Fatalf("client XFF must not reach the backend: %q", h.Get("X-Forwarded-For"))
	}
	if h.Get("X-Request-Id") == "forged" || h.Get("X-Request-Id") == "" || h.Get("X-User-Id") != "" || h.Get("Forwarded") != "" {
		t.Fatalf("spoofed headers leaked: %v", h)
	}
	if h.Get("Authorization") != "Bearer abc" {
		t.Fatal("Authorization must pass through")
	}
}

func TestTrustedProxyForwardedFor(t *testing.T) {
	r := newRig(t, func(c *Config) { c.TrustedProxy = pfx("10.1.0.0/16") })
	// via our load balancer: the right-most non-proxy address is the client
	r.do("GET", "/v1/me", "10.1.0.7:1", map[string]string{"X-Forwarded-For": "6.6.6.6, 198.51.100.4, 10.1.0.9"}, "")
	if got := r.auth.last.Get("X-Real-IP"); got != "198.51.100.4" {
		t.Fatalf("client behind LB: %q", got)
	}
	// a direct caller that is NOT a trusted proxy cannot set it
	r.do("GET", "/v1/me", "198.51.100.77:1", map[string]string{"X-Forwarded-For": "1.1.1.1"}, "")
	if got := r.auth.last.Get("X-Real-IP"); got != "198.51.100.77" {
		t.Fatalf("untrusted peer: %q", got)
	}
	// garbage in the header from a trusted proxy: fall back to the peer, never guess
	r.do("GET", "/v1/me", "10.1.0.7:1", map[string]string{"X-Forwarded-For": "not-an-ip"}, "")
	if got := r.auth.last.Get("X-Real-IP"); got != "10.1.0.7" {
		t.Fatalf("malformed XFF: %q", got)
	}
	// IPv4-mapped IPv6 peers are normalised
	r.do("GET", "/v1/me", "[::ffff:203.0.113.5]:9", nil, "")
	if got := r.auth.last.Get("X-Real-IP"); got != "203.0.113.5" {
		t.Fatalf("mapped address: %q", got)
	}
}

func TestStaffAPIIsInternalOnly(t *testing.T) {
	r := newRig(t, nil)
	w := r.do("GET", "/v1/staff/users/lookup?q=1", "203.0.113.9:1", nil, "")
	if w.Code != 404 || r.auth.hits != 0 {
		t.Fatalf("public caller must get 404 and never reach auth: %d hits=%d", w.Code, r.auth.hits)
	}
	// spoofing the header from the internet changes nothing
	if w = r.do("GET", "/v1/staff/users/lookup?q=1", "203.0.113.9:1", map[string]string{"X-Forwarded-For": "10.0.0.5"}, ""); w.Code != 404 {
		t.Fatalf("spoofed internal address: %d", w.Code)
	}
	if w = r.do("GET", "/v1/staff/users/lookup?q=1", "10.2.3.4:1", nil, ""); w.Code != 200 || r.auth.hits != 1 {
		t.Fatalf("internal caller: %d hits=%d", w.Code, r.auth.hits)
	}
}

func TestCORS(t *testing.T) {
	r := newRig(t, nil)
	ok := map[string]string{"Origin": "https://fyberflix.zeaipc.in"}
	w := r.do("GET", "/v1/me", "1.2.3.4:1", ok, "")
	if w.Header().Get("Access-Control-Allow-Origin") != "https://fyberflix.zeaipc.in" {
		t.Fatal("allowed origin must be echoed")
	}
	evil := map[string]string{"Origin": "https://evil.example"}
	if w = r.do("GET", "/v1/me", "1.2.3.4:1", evil, ""); w.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Fatal("unknown origin must get no CORS header")
	}
	pre := map[string]string{"Origin": "https://fyberflix.zeaipc.in", "Access-Control-Request-Method": "POST"}
	before := r.auth.hits
	if w = r.do("OPTIONS", "/v1/login/start", "1.2.3.4:1", pre, ""); w.Code != 204 ||
		!strings.Contains(w.Header().Get("Access-Control-Allow-Headers"), "Authorization") {
		t.Fatalf("preflight: %d %v", w.Code, w.Header())
	}
	pre["Origin"] = "https://evil.example"
	if w = r.do("OPTIONS", "/v1/login/start", "1.2.3.4:1", pre, ""); w.Code != 403 {
		t.Fatalf("evil preflight: %d", w.Code)
	}
	if r.auth.hits != before {
		t.Fatal("preflights must never reach the backend")
	}
}

func TestBodyLimits(t *testing.T) {
	r := newRig(t, nil)
	if w := r.do("POST", "/v1/login/start", "1.2.3.4:1", nil, strings.Repeat("a", 70<<10)); w.Code != 413 {
		t.Fatalf("big JSON body: %d", w.Code)
	}
	if w := r.do("POST", "/v1/login/face", "1.2.3.4:1", nil, strings.Repeat("a", 1<<20)); w.Code != 200 {
		t.Fatalf("1 MB of frames must be allowed: %d", w.Code)
	}
	if w := r.do("POST", "/v1/signup/face", "1.2.3.4:1", nil, strings.Repeat("a", 17<<20)); w.Code != 413 {
		t.Fatalf("17 MB of frames: %d", w.Code)
	}
}

func TestRateLimitPerIP(t *testing.T) {
	r := newRig(t, func(c *Config) { c.RateRPS, c.RateBurst = 1, 3 })
	for i := 0; i < 3; i++ {
		if w := r.do("GET", "/v1/me", "1.2.3.4:1", nil, ""); w.Code != 200 {
			t.Fatalf("request %d: %d", i, w.Code)
		}
	}
	if w := r.do("GET", "/v1/me", "1.2.3.4:1", nil, ""); w.Code != 429 || w.Header().Get("Retry-After") == "" {
		t.Fatalf("burst exceeded: %d", w.Code)
	}
	if w := r.do("GET", "/v1/me", "5.6.7.8:1", nil, ""); w.Code != 200 {
		t.Fatalf("other IPs are unaffected: %d", w.Code)
	}
	if w := r.do("GET", "/healthz", "1.2.3.4:1", nil, ""); w.Code != 200 {
		t.Fatalf("health checks are never limited: %d", w.Code)
	}
}

func TestSecurityHeadersAndUpstreamDown(t *testing.T) {
	r := newRig(t, func(c *Config) { c.HSTS = true })
	w := r.do("GET", "/v1/me", "1.2.3.4:1", nil, "")
	h := w.Header()
	if h.Get("X-Content-Type-Options") != "nosniff" || h.Get("Strict-Transport-Security") == "" ||
		h.Get("Cache-Control") != "no-store" || h.Get("X-Request-Id") == "" {
		t.Fatalf("headers: %v", h)
	}
	dead := newRig(t, func(c *Config) { c.AuthURL, _ = url.Parse("http://127.0.0.1:1") })
	if w = dead.do("GET", "/v1/me", "1.2.3.4:1", nil, ""); w.Code != 502 || strings.Contains(w.Body.String(), "127.0.0.1") {
		t.Fatalf("upstream down must be a clean 502: %d %s", w.Code, w.Body.String())
	}
}

func TestLimiterRefillsAndSweeps(t *testing.T) {
	l := newLimiter(2, 2)
	now := time.Now()
	if !l.allow("a", now) || !l.allow("a", now) || l.allow("a", now) {
		t.Fatal("burst of 2")
	}
	if !l.allow("a", now.Add(time.Second)) {
		t.Fatal("must refill")
	}
	l.allow("b", now)
	l.allow("c", now.Add(3*time.Minute)) // triggers a sweep
	if len(l.m) != 1 {
		t.Fatalf("idle entries must be swept, have %d", len(l.m))
	}
}
