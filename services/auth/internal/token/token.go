// Package token mints and verifies access tokens (EdDSA JWT) and refresh tokens.
package token

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
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

type Signer struct {
	kid      string
	priv     ed25519.PrivateKey
	pub      ed25519.PublicKey
	issuer   string
	audience string
	ttl      time.Duration
}

// NewSigner takes a base64 (standard) 32-byte Ed25519 seed.
func NewSigner(seedB64, kid, issuer, audience string, ttl time.Duration) (*Signer, error) {
	seed, err := base64.StdEncoding.DecodeString(seedB64)
	if err != nil || len(seed) != ed25519.SeedSize {
		return nil, errors.New("AUTH_JWT_SEED must be base64 of 32 bytes")
	}
	if kid == "" {
		return nil, errors.New("AUTH_JWT_KID is required")
	}
	priv := ed25519.NewKeyFromSeed(seed)
	return &Signer{kid: kid, priv: priv, pub: priv.Public().(ed25519.PublicKey),
		issuer: issuer, audience: audience, ttl: ttl}, nil
}

func (s *Signer) Mint(userID, sessionID, number string, now time.Time) (string, time.Time, error) {
	exp := now.Add(s.ttl)
	hdr, _ := json.Marshal(map[string]string{"alg": "EdDSA", "typ": "JWT", "kid": s.kid})
	cl, err := json.Marshal(Claims{Iss: s.issuer, Aud: s.audience, Sub: userID, SID: sessionID,
		Num: number, Iat: now.Unix(), Exp: exp.Unix()})
	if err != nil {
		return "", time.Time{}, err
	}
	in := b64.EncodeToString(hdr) + "." + b64.EncodeToString(cl)
	return in + "." + b64.EncodeToString(ed25519.Sign(s.priv, []byte(in))), exp, nil
}

func (s *Signer) Verify(tok string, now time.Time) (Claims, error) {
	var c Claims
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		return c, ErrInvalid
	}
	hb, err1 := b64.DecodeString(parts[0])
	sig, err2 := b64.DecodeString(parts[2])
	if err1 != nil || err2 != nil {
		return c, ErrInvalid
	}
	var h struct{ Alg, Kid string }
	if err := json.Unmarshal(hb, &h); err != nil || h.Alg != "EdDSA" || h.Kid != s.kid {
		return c, ErrInvalid // never trust the header's alg
	}
	if !ed25519.Verify(s.pub, []byte(parts[0]+"."+parts[1]), sig) {
		return c, ErrInvalid
	}
	cb, err := b64.DecodeString(parts[1])
	if err != nil || json.Unmarshal(cb, &c) != nil {
		return c, ErrInvalid
	}
	if c.Iss != s.issuer || c.Aud != s.audience || c.Sub == "" || now.Unix() >= c.Exp {
		return Claims{}, ErrInvalid
	}
	return c, nil
}

// JWKS returns the public key set other services use to verify access tokens.
func (s *Signer) JWKS() []byte {
	b, _ := json.Marshal(map[string]any{"keys": []map[string]string{{
		"kty": "OKP", "crv": "Ed25519", "alg": "EdDSA", "use": "sig", "kid": s.kid,
		"x": b64.EncodeToString(s.pub)}}})
	return b
}

// ---- refresh tokens: "<session uuid>.<32 random bytes>"; only sha256 is stored ----

func NewRefresh(sessionID string) (tok string, hash []byte, err error) {
	r := make([]byte, 32)
	if _, err = rand.Read(r); err != nil {
		return "", nil, err
	}
	tok = sessionID + "." + b64.EncodeToString(r)
	h := sha256.Sum256([]byte(tok))
	return tok, h[:], nil
}

func ParseRefresh(tok string) (sessionID string, hash []byte, ok bool) {
	i := strings.IndexByte(tok, '.')
	if i != 36 || len(tok) > 120 || !IsUUID(tok[:36]) {
		return "", nil, false
	}
	h := sha256.Sum256([]byte(tok))
	return tok[:36], h[:], true
}

func Equal(a, b []byte) bool { return len(a) > 0 && subtle.ConstantTimeCompare(a, b) == 1 }

func NewUUID() string {
	var u [16]byte
	if _, err := rand.Read(u[:]); err != nil {
		panic(err)
	}
	u[6] = (u[6] & 0x0f) | 0x40
	u[8] = (u[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", u[0:4], u[4:6], u[6:8], u[8:10], u[10:])
}

func IsUUID(s string) bool {
	if len(s) != 36 {
		return false
	}
	for i := 0; i < 36; i++ {
		c := s[i]
		switch i {
		case 8, 13, 18, 23:
			if c != '-' {
				return false
			}
		default:
			if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
				return false
			}
		}
	}
	return true
}
