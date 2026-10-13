package authz

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type issuer struct {
	kid  string
	priv ed25519.PrivateKey
}

func newIssuer(kid string, seed byte) issuer {
	s := make([]byte, 32)
	for i := range s {
		s[i] = seed
	}
	return issuer{kid, ed25519.NewKeyFromSeed(s)}
}

func (i issuer) mint(c Claims, alg string) string {
	h, _ := json.Marshal(map[string]string{"alg": alg, "typ": "JWT", "kid": i.kid})
	cl, _ := json.Marshal(c)
	in := b64.EncodeToString(h) + "." + b64.EncodeToString(cl)
	return in + "." + b64.EncodeToString(ed25519.Sign(i.priv, []byte(in)))
}

func (i issuer) jwk() map[string]string {
	return map[string]string{"kty": "OKP", "crv": "Ed25519", "alg": "EdDSA", "kid": i.kid,
		"x": b64.EncodeToString(i.priv.Public().(ed25519.PublicKey))}
}

func good() Claims {
	return Claims{Iss: "fyberflix-auth", Aud: "fyberflix", Sub: "user-1", SID: "s1", Num: "123456789",
		Iat: time.Now().Unix(), Exp: time.Now().Add(24 * time.Hour).Unix()}
}

type jwksServer struct {
	*httptest.Server
	keys []map[string]string
	hits atomic.Int32
	fail atomic.Bool
}

func newJWKS(keys ...issuer) *jwksServer {
	j := &jwksServer{}
	for _, k := range keys {
		j.keys = append(j.keys, k.jwk())
	}
	j.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		j.hits.Add(1)
		if j.fail.Load() {
			w.WriteHeader(500)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": j.keys})
	}))
	return j
}

func verifier(j *jwksServer) *Verifier {
	return New(Config{JWKSURL: j.URL, Issuer: "fyberflix-auth", Audience: "fyberflix"})
}

func TestVerify(t *testing.T) {
	k1 := newIssuer("k1", 1)
	j := newJWKS(k1)
	defer j.Close()
	v := verifier(j)
	ctx := context.Background()

	c, err := v.Verify(ctx, k1.mint(good(), "EdDSA"))
	if err != nil || c.Sub != "user-1" || c.Num != "123456789" {
		t.Fatalf("good token: %+v %v", c, err)
	}

	bad := map[string]string{}
	exp := good()
	exp.Exp = time.Now().Add(-time.Second).Unix()
	bad["expired"] = k1.mint(exp, "EdDSA")
	iss := good()
	iss.Iss = "evil"
	bad["issuer"] = k1.mint(iss, "EdDSA")
	aud := good()
	aud.Aud = "other"
	bad["audience"] = k1.mint(aud, "EdDSA")
	nosub := good()
	nosub.Sub = ""
	bad["no sub"] = k1.mint(nosub, "EdDSA")
	bad["alg none"] = k1.mint(good(), "none")
	bad["other key same kid"] = newIssuer("k1", 2).mint(good(), "EdDSA")
	bad["unknown kid"] = newIssuer("zz", 1).mint(good(), "EdDSA")
	bad["garbage"] = "a.b.c"
	bad["empty"] = ""
	bad["huge"] = strings.Repeat("a", 3000)
	tampered := strings.Split(k1.mint(good(), "EdDSA"), ".")
	tampered[1] = b64.EncodeToString([]byte(`{"iss":"fyberflix-auth","aud":"fyberflix","sub":"admin","exp":99999999999}`))
	bad["tampered"] = strings.Join(tampered, ".")
	for name, tok := range bad {
		if _, err := v.Verify(ctx, tok); err == nil {
			t.Errorf("%s must be rejected", name)
		}
	}
}

func TestKeyCachingRotationAndOutage(t *testing.T) {
	k1, k2 := newIssuer("k1", 1), newIssuer("k2", 2)
	j := newJWKS(k1)
	defer j.Close()
	v := verifier(j)
	now := time.Now()
	v.now = func() time.Time { return now }
	ctx := context.Background()

	for i := 0; i < 5; i++ {
		if _, err := v.Verify(ctx, k1.mint(good(), "EdDSA")); err != nil {
			t.Fatal(err)
		}
	}
	if j.hits.Load() != 1 {
		t.Fatalf("keys must be cached, fetched %d times", j.hits.Load())
	}

	// rotation: k2 appears; the unknown kid triggers one refetch (after the 30 s guard)
	j.keys = append(j.keys, k2.jwk())
	if _, err := v.Verify(ctx, k2.mint(good(), "EdDSA")); err == nil {
		t.Fatal("refetch within 30 s of the last one must not happen")
	}
	now = now.Add(31 * time.Second)
	if _, err := v.Verify(ctx, k2.mint(good(), "EdDSA")); err != nil {
		t.Fatalf("rotated key must be picked up: %v", err)
	}

	// auth-service outage: stale keys keep working, empty/bad answers never wipe them
	j.fail.Store(true)
	now = now.Add(10 * time.Minute)
	if _, err := v.Verify(ctx, k1.mint(good(), "EdDSA")); err != nil {
		t.Fatalf("stale keys must still verify during an outage: %v", err)
	}
	j.fail.Store(false)
	j.keys = nil
	now = now.Add(10 * time.Minute)
	if _, err := v.Verify(ctx, k1.mint(good(), "EdDSA")); err != nil {
		t.Fatalf("an empty key set must be ignored: %v", err)
	}
}

func TestRequireMiddleware(t *testing.T) {
	k1 := newIssuer("k1", 1)
	j := newJWKS(k1)
	defer j.Close()
	v := verifier(j)
	var seen Claims
	h := v.Require(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen, _ = FromContext(r.Context())
		w.WriteHeader(204)
	}))
	do := func(auth string) int {
		r := httptest.NewRequest("GET", "/x", nil)
		if auth != "" {
			r.Header.Set("Authorization", auth)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w.Code
	}
	if c := do(""); c != 401 {
		t.Fatalf("no header: %d", c)
	}
	if c := do("Bearer garbage"); c != 401 {
		t.Fatalf("garbage: %d", c)
	}
	if c := do("Basic abc"); c != 401 {
		t.Fatalf("wrong scheme: %d", c)
	}
	if c := do("Bearer " + k1.mint(good(), "EdDSA")); c != 204 || seen.Sub != "user-1" {
		t.Fatalf("valid: %d %+v", c, seen)
	}
	if _, ok := FromContext(context.Background()); ok {
		t.Fatal("no claims without middleware")
	}
}
