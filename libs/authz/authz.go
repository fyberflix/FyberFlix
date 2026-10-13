// Package authz verifies FyberFlix access tokens (EdDSA JWT issued by auth-service) in any service.
// Keys come from auth-service's JWKS endpoint, are cached, and survive a short auth outage.
package authz

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

var b64 = base64.RawURLEncoding

var ErrInvalid = errors.New("invalid token")

type Claims struct {
	Iss string `json:"iss"`
	Aud string `json:"aud"`
	Sub string `json:"sub"` // user id
	SID string `json:"sid"` // device session id
	Num string `json:"num"` // FyberFlix number
	Iat int64  `json:"iat"`
	Exp int64  `json:"exp"`
}

type Config struct {
	JWKSURL  string
	Issuer   string
	Audience string
	// RefreshEvery is how long keys are trusted before a refetch (default 5 min).
	RefreshEvery time.Duration
	// HTTPClient is optional (default: 3s timeout).
	HTTPClient *http.Client
}

type Verifier struct {
	cfg  Config
	hc   *http.Client
	mu   sync.RWMutex
	keys map[string]ed25519.PublicKey
	at   time.Time // last successful fetch
	last time.Time // last fetch attempt (rate limits refetch on unknown kid)
	now  func() time.Time
}

func New(cfg Config) *Verifier {
	if cfg.RefreshEvery == 0 {
		cfg.RefreshEvery = 5 * time.Minute
	}
	hc := cfg.HTTPClient
	if hc == nil {
		hc = &http.Client{Timeout: 3 * time.Second}
	}
	return &Verifier{cfg: cfg, hc: hc, keys: map[string]ed25519.PublicKey{}, now: time.Now}
}

// Verify checks signature, issuer, audience and expiry. The header's alg is never trusted.
func (v *Verifier) Verify(ctx context.Context, tok string) (Claims, error) {
	var c Claims
	parts := strings.Split(tok, ".")
	if len(parts) != 3 || len(tok) > 2048 {
		return c, ErrInvalid
	}
	hb, err1 := b64.DecodeString(parts[0])
	sig, err2 := b64.DecodeString(parts[2])
	if err1 != nil || err2 != nil {
		return c, ErrInvalid
	}
	var h struct{ Alg, Kid string }
	if json.Unmarshal(hb, &h) != nil || h.Alg != "EdDSA" || h.Kid == "" {
		return c, ErrInvalid
	}
	key := v.key(ctx, h.Kid)
	if key == nil || !ed25519.Verify(key, []byte(parts[0]+"."+parts[1]), sig) {
		return c, ErrInvalid
	}
	cb, err := b64.DecodeString(parts[1])
	if err != nil || json.Unmarshal(cb, &c) != nil {
		return Claims{}, ErrInvalid
	}
	if c.Iss != v.cfg.Issuer || c.Aud != v.cfg.Audience || c.Sub == "" || v.now().Unix() >= c.Exp {
		return Claims{}, ErrInvalid
	}
	return c, nil
}

func (v *Verifier) key(ctx context.Context, kid string) ed25519.PublicKey {
	v.mu.RLock()
	k, fresh := v.keys[kid], v.now().Sub(v.at) < v.cfg.RefreshEvery
	v.mu.RUnlock()
	if k != nil && fresh {
		return k
	}
	// Stale, or an unknown kid (key rotation): refetch, but at most once every 30 s.
	v.refresh(ctx)
	v.mu.RLock()
	defer v.mu.RUnlock()
	return v.keys[kid] // a stale key is still used if auth-service is briefly down
}

func (v *Verifier) refresh(ctx context.Context) {
	v.mu.Lock()
	if v.now().Sub(v.last) < 30*time.Second {
		v.mu.Unlock()
		return
	}
	v.last = v.now()
	v.mu.Unlock()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, v.cfg.JWKSURL, nil)
	if err != nil {
		return
	}
	res, err := v.hc.Do(req)
	if err != nil {
		return
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return
	}
	var set struct {
		Keys []struct{ Kty, Crv, Kid, X string } `json:"keys"`
	}
	if json.NewDecoder(io.LimitReader(res.Body, 64<<10)).Decode(&set) != nil {
		return
	}
	next := map[string]ed25519.PublicKey{}
	for _, k := range set.Keys {
		if k.Kty != "OKP" || k.Crv != "Ed25519" || k.Kid == "" {
			continue
		}
		raw, err := b64.DecodeString(k.X)
		if err != nil || len(raw) != ed25519.PublicKeySize {
			continue
		}
		next[k.Kid] = ed25519.PublicKey(raw)
	}
	if len(next) == 0 {
		return // never replace good keys with an empty set
	}
	v.mu.Lock()
	v.keys, v.at = next, v.now()
	v.mu.Unlock()
}

// ---------- HTTP middleware ----------

type ctxKey struct{}

// FromContext returns the verified claims placed there by Require.
func FromContext(ctx context.Context) (Claims, bool) {
	c, ok := ctx.Value(ctxKey{}).(Claims)
	return c, ok
}

// Require rejects requests without a valid "Authorization: Bearer <access token>".
// It checks the token only; services that must react instantly to suspension still ask auth-service.
func (v *Verifier) Require(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		if !ok || t == "" {
			unauthorized(w)
			return
		}
		c, err := v.Verify(r.Context(), t)
		if err != nil {
			unauthorized(w)
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), ctxKey{}, c)))
	})
}

func unauthorized(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("WWW-Authenticate", `Bearer realm="fyberflix"`)
	w.WriteHeader(http.StatusUnauthorized)
	_, _ = w.Write([]byte(`{"error":{"code":"unauthorized","message":"valid access token required"}}`))
}
