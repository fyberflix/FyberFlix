package token

import (
	"encoding/base64"
	"strings"
	"testing"
	"time"
)

func signer(t *testing.T) *Signer {
	seed := base64.StdEncoding.EncodeToString(make([]byte, 32))
	s, err := NewSigner(seed, "k1", "fyberflix-auth", "fyberflix", 10*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestAccessToken(t *testing.T) {
	s, now := signer(t), time.Now()
	tok, _, _ := s.Mint("user-1", "sess-1", "538201947", now)
	c, err := s.Verify(tok, now.Add(time.Minute))
	if err != nil || c.Sub != "user-1" || c.Num != "538201947" {
		t.Fatalf("verify: %v %+v", err, c)
	}
	if _, err := s.Verify(tok, now.Add(11*time.Minute)); err == nil {
		t.Fatal("expired token accepted")
	}
	p := strings.Split(tok, ".")
	evil := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","kid":"k1"}`))
	if _, err := s.Verify(evil+"."+p[1]+".", now); err == nil {
		t.Fatal("alg=none accepted")
	}
	other := base64.RawURLEncoding.EncodeToString([]byte(`{"iss":"fyberflix-auth","aud":"fyberflix","sub":"admin","exp":99999999999}`))
	if _, err := s.Verify(p[0]+"."+other+"."+p[2], now); err == nil {
		t.Fatal("tampered payload accepted")
	}
	if len(s.JWKS()) == 0 {
		t.Fatal("no jwks")
	}
}

func TestRefresh(t *testing.T) {
	sid := NewUUID()
	if !IsUUID(sid) {
		t.Fatal("bad uuid", sid)
	}
	tok, h, _ := NewRefresh(sid)
	gotSID, gotH, ok := ParseRefresh(tok)
	if !ok || gotSID != sid || !Equal(h, gotH) {
		t.Fatal("refresh roundtrip failed")
	}
	if _, _, ok := ParseRefresh("not-a-token"); ok {
		t.Fatal("garbage accepted")
	}
}
