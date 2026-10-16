package httpapi

import (
	"bytes"
	"context"
	"encoding/base64"
	"io"
	"log/slog"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/fyberflix/fyberflix/services/auth/internal/token"
)

type memRec struct {
	*memAcct
	otps map[string]*motp
	recs []*Recovery
	hash map[string][]byte // recovery id -> token hash
	by   map[string]string // recovery id -> approver
}

func newMemRec(a *memAcct) *memRec {
	return &memRec{memAcct: a, otps: map[string]*motp{}, hash: map[string][]byte{}, by: map[string]string{}}
}

func isOpen(r *Recovery) bool { return r.State == "waiting" || r.State == "approved" }

func (m *memRec) PutRecoveryOTP(_ context.Context, uid string, h []byte, exp time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.otps[uid] = &motp{hash: h, exp: exp}
	return nil
}
func (m *memRec) CheckRecoveryOTP(_ context.Context, uid string, max int, match func([]byte) bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	o := m.otps[uid]
	if o == nil || time.Now().After(o.exp) {
		return ErrOTPInvalid
	}
	if o.attempts >= max {
		return ErrOTPLocked
	}
	if !match(o.hash) {
		o.attempts++
		return ErrOTPInvalid
	}
	delete(m.otps, uid)
	return nil
}
func (m *memRec) CreateRecovery(_ context.Context, uid string, th []byte, ready, exp time.Time) (Recovery, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, r := range m.recs {
		if r.UserID == uid && isOpen(r) && time.Now().Before(r.ExpiresAt) {
			return Recovery{}, ErrRecoveryOpen
		}
	}
	r := &Recovery{ID: token.NewUUID(), UserID: uid, State: "waiting", ReadyAt: ready, ExpiresAt: exp}
	m.recs = append(m.recs, r)
	m.hash[r.ID] = th
	return *r, nil
}
func (m *memRec) RecoveryByToken(_ context.Context, th []byte) (Recovery, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, r := range m.recs {
		if bytes.Equal(m.hash[r.ID], th) {
			return *r, nil
		}
	}
	return Recovery{}, ErrNotFound
}
func (m *memRec) open(uid string) *Recovery {
	for _, r := range m.recs {
		if r.UserID == uid && isOpen(r) && time.Now().Before(r.ExpiresAt) {
			return r
		}
	}
	return nil
}
func (m *memRec) OpenRecovery(_ context.Context, uid string) (Recovery, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if r := m.open(uid); r != nil {
		return *r, nil
	}
	return Recovery{}, ErrNotFound
}
func (m *memRec) ApproveRecovery(_ context.Context, uid, by string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if r := m.open(uid); r != nil && r.State == "waiting" {
		r.State, m.by[r.ID] = "approved", by
		return nil
	}
	return ErrWrongState
}
func (m *memRec) CompleteRecovery(_ context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, r := range m.recs {
		if r.ID == id && r.State == "approved" {
			r.State = "completed"
			return nil
		}
	}
	return ErrWrongState
}
func (m *memRec) CancelOpenRecovery(_ context.Context, uid string) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if r := m.open(uid); r != nil {
		r.State = "cancelled"
		return true, nil
	}
	return false, nil
}
func (m *memRec) ListWaitingRecoveries(_ context.Context, _ int) ([]PendingRecovery, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []PendingRecovery
	for _, r := range m.recs {
		if r.State == "waiting" {
			u := m.users[r.UserID]
			out = append(out, PendingRecovery{UserID: r.UserID, Number: u.Number, CableName: u.CableName, ReadyAt: r.ReadyAt})
		}
	}
	return out, nil
}

type recEnv struct {
	*aenv
	rec *memRec
}

func setupRecovery(t *testing.T, wait time.Duration) *recEnv {
	seed := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32))
	signer, err := token.NewSigner(seed, "k1", "fyberflix-auth", "fyberflix", 10*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	st, face := newMem(), &fakeFace{enrolled: map[string]bool{}}
	acct, ml := newMemAcct(st), &fakeMail{}
	rec := newMemRec(acct)
	api := New(st, face, signer, Config{SessionTTL: time.Minute, HoldTTL: time.Minute,
		RefreshTTL: time.Hour, MaxRefresh: 5, PublicBaseURL: "https://FyberFlix.zeaipc.in"},
		slog.New(slog.NewTextHandler(io.Discard, nil))).
		WithAccount(acct, ml, AccountConfig{OTPPepper: bytes.Repeat([]byte{9}, 32), RecoveryWait: wait}).
		WithRecovery(rec)
	srv := httptest.NewServer(api.Handler())
	t.Cleanup(srv.Close)
	return &recEnv{&aenv{&env{t, srv, st, face}, acct, ml}, rec}
}

// verifiedEmail gives the user a verified email through the normal OTP flow.
func (e *recEnv) verifiedEmail(access, email string) {
	c, m := e.js("POST", "/v1/me/email", access, `{"email":"`+email+`"}`)
	e.want(c, m, 202)
	c, m = e.js("POST", "/v1/me/email/verify", access, `{"code":"`+e.mail.code+`"}`)
	e.want(c, m, 200)
}

// requestRecovery runs start + verify and returns the recovery token.
func (e *recEnv) requestRecovery(number string) string {
	c, m := e.js("POST", "/v1/recovery/start", "", `{"identifier":"`+number+`"}`)
	e.want(c, m, 202)
	c, m = e.js("POST", "/v1/recovery/verify", "", `{"identifier":"`+number+`","code":"`+e.mail.code+`"}`)
	e.want(c, m, 201)
	return str(m, "recovery_token")
}

func (e *recEnv) status(tok string) map[string]any {
	c, m := e.js("POST", "/v1/recovery/status", "", `{"recovery_token":"`+tok+`"}`)
	e.want(c, m, 200)
	return m
}

func (e *recEnv) lastNotice() string {
	if len(e.mail.notices) == 0 {
		return ""
	}
	return e.mail.notices[len(e.mail.notices)-1]
}

func (e *recEnv) users(id string) User {
	e.acct.mu.Lock()
	defer e.acct.mu.Unlock()
	return *e.acct.users[id]
}

func TestRecoveryHappyPath(t *testing.T) {
	e := setupRecovery(t, time.Hour)
	number, a1, id := e.user("Lost_Face")
	_, aa, adminID := e.user("Admin_Person")
	e.acct.roles[adminID] = []string{"admin"}
	e.verifiedEmail(a1, "owner@example.com")

	tok := e.requestRecovery(number)
	if !strings.Contains(e.lastNotice(), "owner@example.com|FyberFlix account recovery requested") ||
		!strings.Contains(e.lastNotice(), "log in with your face") {
		t.Fatalf("owner must be told: %q", e.lastNotice())
	}
	if !e.acct.has("recovery.requested", id) {
		t.Fatal("not audited")
	}
	if s := e.status(tok); str(s, "state") != "waiting" || s["can_start"] != false {
		t.Fatalf("status: %v", s)
	}

	// not usable while waiting, even though nobody approved yet or the wait is not over
	if c, _ := e.js("POST", "/v1/recovery/face/start", "", `{"recovery_token":"`+tok+`"}`); c != 409 {
		t.Fatalf("waiting: %d", c)
	}
	// a normal user and a support agent cannot approve; an admin can
	body := `{"reason":"ticket 5001 identity checked"}`
	if c, _ := e.js("POST", "/v1/staff/users/"+id+"/recovery/approve", a1, body); c != 403 {
		t.Fatalf("owner cannot approve own recovery: %d", c)
	}
	if c, m := e.js("POST", "/v1/staff/users/"+id+"/recovery/approve", aa, body); c != 204 {
		t.Fatalf("admin approve: %d %v", c, m)
	}
	if !strings.Contains(e.lastNotice(), "approved") || !e.acct.has("staff.recovery_approve", id) {
		t.Fatal("approval must be audited and emailed")
	}
	// approved but the waiting period is not over
	if s := e.status(tok); str(s, "state") != "approved" || s["can_start"] != false {
		t.Fatalf("status after approve: %v", s)
	}
	if c, _ := e.js("POST", "/v1/recovery/face/start", "", `{"recovery_token":"`+tok+`"}`); c != 409 {
		t.Fatalf("approved but early: %d", c)
	}

	// waiting period over
	e.rec.mu.Lock()
	e.rec.recs[0].ReadyAt = time.Now().Add(-time.Minute)
	e.rec.mu.Unlock()
	if s := e.status(tok); s["can_start"] != true {
		t.Fatalf("must be startable: %v", s)
	}
	c, m := e.js("POST", "/v1/recovery/face/start", "", `{"recovery_token":"`+tok+`"}`)
	e.want(c, m, 200)
	if str(m, "purpose") != "enroll" || len(m["steps"].([]any)) == 0 {
		t.Fatalf("face start: %v", m)
	}
	if e.face.enrolled[e.users(id).FaceRef] {
		t.Fatal("old face template must be erased before re-enrolment")
	}
	attempt := str(m, "attempt_token")

	// a bad capture burns the token but keeps the request approved: try again
	if c, _ = e.mp("/v1/recovery/face", attempt, nil, "poor"); c == 200 {
		t.Fatalf("bad frames must not recover: %d", c)
	}
	if s := e.status(tok); str(s, "state") != "approved" {
		t.Fatalf("request must stay approved after a failed capture: %v", s)
	}
	c, m = e.js("POST", "/v1/recovery/face/start", "", `{"recovery_token":"`+tok+`"}`)
	e.want(c, m, 200)
	if c, _ = e.mp("/v1/recovery/face", str(m, "attempt_token"), nil, "good-new-face"); c != 200 {
		t.Fatalf("recovery: %d", c)
	}
	if !e.face.enrolled[e.users(id).FaceRef] {
		t.Fatal("new face must be enrolled")
	}
	if s := e.status(tok); str(s, "state") != "completed" {
		t.Fatalf("status: %v", s)
	}
	if !e.acct.has("recovery.completed", id) || !strings.Contains(e.lastNotice(), "reset completed") {
		t.Fatal("completion must be audited and emailed")
	}
	// old devices are signed out, the new face logs in
	if list, _ := e.acct.ListSessions(context.Background(), id); len(list) != 0 {
		t.Fatalf("all sessions must be revoked: %v", list)
	}
	e.login(number)
	// the token cannot be used again
	if c, _ = e.js("POST", "/v1/recovery/face/start", "", `{"recovery_token":"`+tok+`"}`); c != 409 {
		t.Fatalf("reuse after completion: %d", c)
	}
}

func TestOwnerLoginCancelsRecovery(t *testing.T) {
	e := setupRecovery(t, time.Hour)
	number, a1, id := e.user("Real_Owner")
	e.verifiedEmail(a1, "owner@example.com")
	tok := e.requestRecovery(number)

	e.login(number) // the real owner shows up
	if s := e.status(tok); str(s, "state") != "cancelled" {
		t.Fatalf("must be cancelled: %v", s)
	}
	if !e.acct.has("recovery.cancelled_by_login", id) || !strings.Contains(e.lastNotice(), "cancelled") {
		t.Fatal("cancel must be audited and emailed")
	}
	// even an approved request dies the same way
	tok = e.requestRecovery(number)
	_, aa, adminID := e.user("Admin_Person")
	e.acct.roles[adminID] = []string{"admin"}
	e.js("POST", "/v1/staff/users/"+id+"/recovery/approve", aa, `{"reason":"ticket 5002 checked"}`)
	e.login(number)
	if s := e.status(tok); str(s, "state") != "cancelled" {
		t.Fatalf("approved request must be cancelled too: %v", s)
	}
}

func TestRecoveryStartIsNotAnEnumerationOracle(t *testing.T) {
	e := setupRecovery(t, time.Hour)
	number, _, _ := e.user("No_Email_User") // no verified email
	_, a2, _ := e.user("Has_Email_User")
	e.verifiedEmail(a2, "x@example.com")
	e.mail.code = ""

	var bodies []string
	for _, ident := range []string{number, "nobody_exists", "Has_Email_User"} {
		c, m := e.js("POST", "/v1/recovery/start", "", `{"identifier":"`+ident+`"}`)
		if c != 202 {
			t.Fatalf("%s: %d", ident, c)
		}
		bodies = append(bodies, str(m, "message"))
	}
	if bodies[0] != bodies[1] || bodies[1] != bodies[2] {
		t.Fatalf("answers must be identical: %v", bodies)
	}
	// only the account with a verified email actually got a code
	if e.mail.code == "" || e.mail.to != "x@example.com" {
		t.Fatalf("mail: %+v", e.mail)
	}
	if c, _ := e.js("POST", "/v1/recovery/start", "", `{"identifier":"a b"}`); c != 400 {
		t.Fatalf("malformed identifier: %d", c)
	}
	// a wrong or foreign code gets nothing
	if c, _ := e.js("POST", "/v1/recovery/verify", "", `{"identifier":"`+number+`","code":"123456"}`); c != 422 {
		t.Fatalf("no code was issued for this account: %d", c)
	}
}

func TestRecoveryOTPLockoutAndSingleOpenRequest(t *testing.T) {
	e := setupRecovery(t, time.Hour)
	number, a1, _ := e.user("Locked_Out")
	e.verifiedEmail(a1, "o@example.com")
	e.js("POST", "/v1/recovery/start", "", `{"identifier":"`+number+`"}`)
	good := e.mail.code
	for i := 0; i < 5; i++ {
		e.js("POST", "/v1/recovery/verify", "", `{"identifier":"`+number+`","code":"`+other(good)+`"}`)
	}
	if c, _ := e.js("POST", "/v1/recovery/verify", "", `{"identifier":"`+number+`","code":"`+good+`"}`); c != 429 {
		t.Fatalf("lockout: %d", c)
	}

	// a second request while one is open is refused
	e2 := setupRecovery(t, time.Hour)
	n2, b1, _ := e2.user("Only_One")
	e2.verifiedEmail(b1, "o@example.com")
	e2.requestRecovery(n2)
	e2.js("POST", "/v1/recovery/start", "", `{"identifier":"`+n2+`"}`)
	if c, _ := e2.js("POST", "/v1/recovery/verify", "", `{"identifier":"`+n2+`","code":"`+e2.mail.code+`"}`); c != 409 {
		t.Fatalf("second open request: %d", c)
	}
}

func TestRecoveryTokenAndStaffRules(t *testing.T) {
	e := setupRecovery(t, time.Hour)
	for _, bad := range []string{"", "short", strings.Repeat("a", 30)} {
		if c, _ := e.js("POST", "/v1/recovery/status", "", `{"recovery_token":"`+bad+`"}`); c != 401 {
			t.Fatalf("token %q: %d", bad, c)
		}
	}
	number, a1, _ := e.user("Waiting_User")
	_, as, sid := e.user("Support_Agent")
	e.acct.roles[sid] = []string{"support"}
	e.verifiedEmail(a1, "w@example.com")
	e.requestRecovery(number)

	// support may look at the queue (with a reason), only admins may approve
	if c, _ := e.js("GET", "/v1/staff/recovery/pending", as, ""); c != 400 {
		t.Fatalf("reason required: %d", c)
	}
	c, m := e.js("GET", "/v1/staff/recovery/pending?reason=ticket+5003+review", as, "")
	e.want(c, m, 200)
	list := m["pending"].([]any)
	if len(list) != 1 || list[0].(map[string]any)["fyberflix_number"] != number {
		t.Fatalf("queue: %v", m)
	}
	if c, _ := e.js("GET", "/v1/staff/recovery/pending?reason=ticket+5003+review", a1, ""); c != 403 {
		t.Fatalf("normal user: %d", c)
	}
	id := list[0].(map[string]any)["user_id"].(string)
	if c, _ := e.js("POST", "/v1/staff/users/"+id+"/recovery/approve", as, `{"reason":"ticket 5003 looks fine"}`); c != 403 {
		t.Fatalf("support must not approve: %d", c)
	}
}
