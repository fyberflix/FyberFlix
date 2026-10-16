package httpapi

import (
	"bytes"
	"context"
	"encoding/base64"
	"io"
	"log/slog"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/fyberflix/fyberflix/services/auth/internal/riskclient"
	"github.com/fyberflix/fyberflix/services/auth/internal/token"
)

// fakeRisk behaves like the real rules: names containing "secure" need step_up, and the login_fail
// rate rule counts calls per subject (5th call -> deny).
type fakeRisk struct {
	mu       sync.Mutex
	counts   map[string]int
	down     bool
	degraded bool
	loginHit []string
}

func (f *fakeRisk) Evaluate(_ context.Context, spec string, ev map[string]any, subject string) (riskclient.Verdict, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.down {
		return riskclient.Verdict{}, riskclient.ErrUnavailable
	}
	if f.degraded {
		return riskclient.Verdict{Decision: riskclient.StepUp, Degraded: true}, nil
	}
	switch spec {
	case "auth_risk":
		name, _ := ev["signup"].(map[string]any)["cable_name"].(string)
		if strings.Contains(strings.ToLower(name), "secure") {
			return riskclient.Verdict{Decision: riskclient.StepUp, RuleIDs: []string{"name_phishing_words"}}, nil
		}
	case "login_fail":
		f.loginHit = append(f.loginHit, subject)
		f.counts[subject]++
		if f.counts[subject] >= 5 {
			return riskclient.Verdict{Decision: riskclient.Deny, RuleIDs: []string{"repeated_failed_logins"}}, nil
		}
	}
	return riskclient.Verdict{Decision: riskclient.Allow}, nil
}

type memBlocks struct {
	mu sync.Mutex
	m  map[string]time.Time
}

func (b *memBlocks) Block(_ context.Context, k string, until time.Time) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.m[k] = until
	return nil
}
func (b *memBlocks) Blocked(_ context.Context, k string) (bool, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.m[k].After(time.Now()), nil
}

type renv struct {
	*aenv
	risk   *fakeRisk
	blocks *memBlocks
}

func setupRisk(t *testing.T) *renv {
	seed := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32))
	signer, err := token.NewSigner(seed, "k1", "fyberflix-auth", "fyberflix", 10*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	st, face := newMem(), &fakeFace{enrolled: map[string]bool{}}
	acct, ml := newMemAcct(st), &fakeMail{}
	rk, bl := &fakeRisk{counts: map[string]int{}}, &memBlocks{m: map[string]time.Time{}}
	api := New(st, face, signer, Config{SessionTTL: time.Minute, HoldTTL: time.Minute,
		RefreshTTL: time.Hour, MaxRefresh: 5, PublicBaseURL: "https://FyberFlix.zeaipc.in"},
		slog.New(slog.NewTextHandler(io.Discard, nil))).
		WithAccount(acct, ml, AccountConfig{OTPPepper: bytes.Repeat([]byte{9}, 32)}).
		WithRisk(rk, bl)
	srv := httptest.NewServer(api.Handler())
	t.Cleanup(srv.Close)
	return &renv{&aenv{&env{t, srv, st, face}, acct, ml}, rk, bl}
}

func TestRiskRejectsPhishingLikeNames(t *testing.T) {
	e := setupRisk(t)
	c, m := e.js("POST", "/v1/signup/sessions", "", "")
	e.want(c, m, 201)
	sess := str(m, "session_token")
	e.js("POST", "/v1/signup/number", sess, `{"number":"`+m["number_offers"].([]any)[0].(string)+`"}`)

	c, m = e.js("POST", "/v1/signup/cable-name", sess, `{"name":"Secure_Wallet"}`)
	if c != 422 || str(m, "error", "code") != "name_not_allowed" {
		t.Fatalf("phishing-like name: %d %v", c, m)
	}
	if c, m = e.js("POST", "/v1/signup/cable-name", sess, `{"name":"Arman_Films"}`); c != 200 {
		t.Fatalf("normal name: %d %v", c, m)
	}

	// risk-service down or degraded must never block a normal user, or reject a name by itself
	for _, mode := range []string{"down", "degraded"} {
		e.risk.down, e.risk.degraded = mode == "down", mode == "degraded"
		if c, m = e.js("POST", "/v1/signup/cable-name", sess, `{"name":"Secure_Again"}`); c != 200 {
			t.Fatalf("%s: name must be accepted: %d %v", mode, c, m)
		}
	}
	e.risk.down, e.risk.degraded = false, false

	// renaming is checked too
	_, a1, _ := e.user("Normal_User")
	if c, m = e.js("POST", "/v1/me/cable-name", a1, `{"name":"Secure_Bank"}`); c != 422 || str(m, "error", "code") != "name_not_allowed" {
		t.Fatalf("rename: %d %v", c, m)
	}
}

func TestRepeatedFailedLoginsGetBlocked(t *testing.T) {
	e := setupRisk(t)
	number, _, id := e.user("Victim_User")

	tryBad := func() int {
		c, m := e.js("POST", "/v1/login/start", "", `{"identifier":"`+number+`"}`)
		if c != 200 {
			return c
		}
		c, _ = e.mp("/v1/login/face", str(m, "login_token"), nil, "bad-face")
		return c
	}
	for i := 0; i < 5; i++ {
		if c := tryBad(); c != 401 {
			t.Fatalf("attempt %d: %d", i+1, c)
		}
	}
	// the limit is reached: even the real owner from this IP is blocked for a while
	if c, m := e.js("POST", "/v1/login/start", "", `{"identifier":"`+number+`"}`); c != 429 || str(m, "error", "code") != "login_blocked" {
		t.Fatalf("must be blocked: %d %v", c, m)
	}
	if !e.acct.has("login.blocked", id) {
		t.Fatal("block not audited")
	}
	// both subjects were counted separately
	seen := map[string]int{}
	for _, s := range e.risk.loginHit {
		seen[s]++
	}
	if seen["ip:127.0.0.1"] != 5 || seen["user:"+id] != 5 {
		t.Fatalf("counted per subject: %v", seen)
	}
}

func TestSuccessfulAndSoftFailuresAreNotCounted(t *testing.T) {
	e := setupRisk(t)
	number, _, _ := e.user("Calm_User")
	for i := 0; i < 8; i++ { // eight successful logins must never trip the failure rule
		e.login(number)
	}
	if len(e.risk.loginHit) != 0 {
		t.Fatalf("successes were counted: %v", e.risk.loginHit)
	}
	for _, r := range []string{"challenge_invalid", "poor_quality", "bad_frame_count"} {
		if countsAsAttack(r) {
			t.Fatalf("%s must not count", r)
		}
	}
	if !countsAsAttack("no_match") || !countsAsAttack("liveness_failed") {
		t.Fatal("real failures must count")
	}
}
