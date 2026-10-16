package gateway

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/netip"
	"net/url"
	"strings"
	"time"
)

const (
	maxJSONBody = 64 << 10 // normal API calls
	maxFaceBody = 16 << 20 // up to 24 JPEG frames
)

type Gateway struct {
	cfg  Config
	log  *slog.Logger
	auth *httputil.ReverseProxy
	web  *httputil.ReverseProxy
    cont *httputil.ReverseProxy
	lim  *limiter
}

func New(cfg Config, log *slog.Logger) *Gateway {
	g := &Gateway{cfg: cfg, log: log, lim: newLimiter(cfg.RateRPS, cfg.RateBurst)}
	g.auth = g.proxy(cfg.AuthURL)
	if cfg.WebURL != nil {
		g.web = g.proxy(cfg.WebURL)
	}
	if cfg.ContentURL != nil {
		g.cont = g.proxy(cfg.ContentURL)
	}
	return g
}

type ctxKey int

const (
	ipKey ctxKey = iota
	idKey
)

func (g *Gateway) proxy(target *url.URL) *httputil.ReverseProxy {
	return &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(target)
			h := pr.Out.Header
			// Nothing the client sent about identity or origin is believed. Backends read only these two.
			for _, k := range []string{"X-Real-IP", "X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Proto",
				"Forwarded", "X-Request-Id", "X-User-Id", "X-Fyber-Number"} {
				h.Del(k)
			}
			h.Set("X-Real-IP", pr.In.Context().Value(ipKey).(string))
			h.Set("X-Request-Id", pr.In.Context().Value(idKey).(string))
		},
		Transport: &http.Transport{
			MaxIdleConnsPerHost: 100, IdleConnTimeout: 60 * time.Second,
			ResponseHeaderTimeout: 45 * time.Second, // face verification can be slow
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			g.log.Error("upstream error", "path", r.URL.Path, "req", r.Context().Value(idKey), "err", err)
			writeJSON(w, http.StatusBadGateway, `{"error":{"code":"bad_gateway","message":"service temporarily unavailable"}}`)
		},
		ModifyResponse: func(res *http.Response) error {
			if res.Header.Get("Cache-Control") == "" {
				res.Header.Set("Cache-Control", "no-store")
			}
			return nil
		},
	}
}

func (g *Gateway) Handler() http.Handler {
	return g.recoverer(g.requestMeta(g.secureHeaders(g.cors(g.rateLimit(http.HandlerFunc(g.route))))))
}

func (g *Gateway) route(w http.ResponseWriter, r *http.Request) {
	p := r.URL.Path
	switch {
	case p == "/healthz":
		w.WriteHeader(http.StatusOK)
	case g.cont != nil && isContentPath(p):
		g.limitBody(w, r)
		g.cont.ServeHTTP(w, r)
	case p == "/.well-known/jwks.json" || strings.HasPrefix(p, "/v1/"):
		if strings.HasPrefix(p, "/v1/staff/") && !inAny(g.ip(r), g.cfg.StaffNets) {
			notFound(w) // the staff API does not exist for the public internet
			return
		}
		g.limitBody(w, r)
		g.auth.ServeHTTP(w, r)
	case g.web != nil:
		g.web.ServeHTTP(w, r)
	default:
		notFound(w)
	}
}

// isContentPath lists the API paths owned by the content service. It must be checked BEFORE the
// generic /v1/ -> auth rule (note /v1/me/videos would otherwise go to auth).
func isContentPath(p string) bool {
	return p == "/v1/videos" || strings.HasPrefix(p, "/v1/videos/") || p == "/v1/me/videos" ||
		(strings.HasPrefix(p, "/v1/users/") && strings.HasSuffix(p, "/videos"))
}
func (g *Gateway) limitBody(w http.ResponseWriter, r *http.Request) {
	max := int64(maxJSONBody)
	if strings.HasSuffix(r.URL.Path, "/face") {
		max = maxFaceBody
	}
	if r.ContentLength > max {
		writeJSON(w, http.StatusRequestEntityTooLarge, `{"error":{"code":"too_large","message":"request body too large"}}`)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, max)
}

// ---------- middleware ----------

func (g *Gateway) recoverer(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if v := recover(); v != nil && v != http.ErrAbortHandler {
				g.log.Error("panic in gateway", "panic", v)
				writeJSON(w, http.StatusInternalServerError, `{"error":{"code":"internal","message":"something went wrong"}}`)
			}
		}()
		next.ServeHTTP(w, r)
	})
}

// requestMeta fixes the client IP and a request id once, for logging, limits and upstreams.
func (g *Gateway) requestMeta(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := g.clientIP(r)
		id := newID()
		w.Header().Set("X-Request-Id", id)
		ctx := context.WithValue(context.WithValue(r.Context(), ipKey, ip), idKey, id)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (g *Gateway) ip(r *http.Request) netip.Addr {
	a, _ := netip.ParseAddr(r.Context().Value(ipKey).(string))
	return a
}

func (g *Gateway) secureHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("X-Frame-Options", "DENY")
		if g.cfg.HSTS {
			h.Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		}
		next.ServeHTTP(w, r)
	})
}

func (g *Gateway) cors(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin == "" {
			next.ServeHTTP(w, r)
			return
		}
		w.Header().Add("Vary", "Origin")
		allowed := g.cfg.Origins[origin]
		if r.Method == http.MethodOptions && r.Header.Get("Access-Control-Request-Method") != "" {
			if !allowed {
				w.WriteHeader(http.StatusForbidden)
				return
			}
			h := w.Header()
			h.Set("Access-Control-Allow-Origin", origin)
			h.Set("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
			h.Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
			h.Set("Access-Control-Max-Age", "600")
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if allowed {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Expose-Headers", "X-Request-Id, Retry-After")
		}
		next.ServeHTTP(w, r)
	})
}

func (g *Gateway) rateLimit(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/healthz" && !g.lim.allow(r.Context().Value(ipKey).(string), time.Now()) {
			w.Header().Set("Retry-After", "1")
			writeJSON(w, http.StatusTooManyRequests, `{"error":{"code":"rate_limited","message":"too many requests"}}`)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// ---------- client ip ----------

// clientIP believes X-Forwarded-For only when the TCP peer is one of our own load balancers,
// and then takes the right-most entry that is not itself a trusted proxy.
func (g *Gateway) clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	peer, err := netip.ParseAddr(host)
	if err != nil {
		return "0.0.0.0"
	}
	peer = peer.Unmap()
	if !inAny(peer, g.cfg.TrustedProxy) {
		return peer.String()
	}
	parts := strings.Split(strings.Join(r.Header.Values("X-Forwarded-For"), ","), ",")
	for i := len(parts) - 1; i >= 0; i-- {
		a, err := netip.ParseAddr(strings.TrimSpace(parts[i]))
		if err != nil {
			return peer.String() // malformed header: do not guess
		}
		if a = a.Unmap(); !inAny(a, g.cfg.TrustedProxy) {
			return a.String()
		}
	}
	return peer.String()
}

func inAny(a netip.Addr, nets []netip.Prefix) bool {
	a = a.Unmap()
	for _, n := range nets {
		if n.Contains(a) {
			return true
		}
	}
	return false
}

// ---------- helpers ----------

func newID() string {
	b := make([]byte, 12)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func writeJSON(w http.ResponseWriter, code int, body string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_, _ = w.Write([]byte(body))
}

func notFound(w http.ResponseWriter) {
	writeJSON(w, http.StatusNotFound, `{"error":{"code":"not_found","message":"not found"}}`)
}
