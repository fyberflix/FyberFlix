package httpapi

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"io"
	"log/slog"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/zeaipc/fyberflix/services/auth/internal/token"
)

// ---------------- in-memory AccountStore ----------------

type motp struct {
	email    string
	hash     []byte
	attempts int
	exp      time.Time
}

type memAcct struct {
	*mem
	otps      map[string]*motp
	emailOf   map[string]string // user -> verified email
	emailUser map[string]string // verified email -> user
	attempts  map[string]FaceAttempt
	roles     map[string][]string
	audits    []AuditEntry
	auditFail bool
	renamed   map[string]time.Time
	released  map[string]string // old key -> user who released it
}

func newMemAcct(m *mem) *memAcct {
	return &memAcct{mem: m, otps: map[string]*motp{}, emailOf: map[string]string{}, emailUser: map[string]string{},
		attempts: map[string]FaceAttempt{}, roles: map[string][]string{}, renamed: map[string]time.Time{},
		released: map[string]string{}}
}

// A name released by someone else stays reserved (mirrors the 90-day rule).
func (a *memAcct) CableNameTaken(ctx context.Context, key string) (bool, error) {
	a.mu.Lock()
	_, rel := a.released[key]
	a.mu.Unlock()
	if rel {
		return true, nil
	}
	return a.mem.CableNameTaken(ctx, key)
}

func (a *memAcct) PutEmailOTP(_ context.Context, uid, email string, h []byte, exp time.Time) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.otps[uid] = &motp{email: email, hash: h, exp: exp}
	return nil
}
func (a *memAcct) CheckEmailOTP(_ context.Context, uid string, max int, match func(string, []byte) bool) (string, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	o := a.otps[uid]
	if o == nil || time.Now().After(o.exp) {
		return "", ErrOTPInvalid
	}
	if o.attempts >= max {
		return "", ErrOTPLocked
	}
	o.attempts++
	if !match(o.email, o.hash) {
		return "", ErrOTPInvalid
	}
	if owner, ok := a.emailUser[o.email]; ok && owner != uid {
		return "", ErrEmailTaken
	}
	a.emailOf[uid], a.emailUser[o.email] = o.email, uid
	delete(a.otps, uid)
	return o.email, nil
}
func (a *memAcct) EmailInfo(_ context.Context, uid string) (string, bool, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	e, ok := a.emailOf[uid]
	return e, ok, nil
}
func (a *memAcct) RemoveEmail(_ context.Context, uid string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	delete(a.emailUser, a.emailOf[uid])
	delete(a.emailOf, uid)
	delete(a.otps, uid)
	return nil
}
func (a *memAcct) RenameCable(_ context.Context, uid, display string, cd time.Duration) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	u := a.users[uid]
	if u == nil || u.Status != "active" {
		return ErrNotFound
	}
	if t, ok := a.renamed[uid]; ok && time.Since(t) < cd {
		return ErrRenameCooldown
	}
	key := strings.ToLower(display)
	if owner, ok := a.byKey[key]; ok && owner != uid {
		return ErrNameTaken
	}
	if who, ok := a.released[key]; ok && who != uid {
		return ErrNameTaken
	}
	old := strings.ToLower(u.CableName)
	if old != key {
		delete(a.byKey, old)
		a.released[old] = uid
	}
	a.byKey[key], u.CableName = uid, display
	a.renamed[uid] = time.Now()
	return nil
}
func (a *memAcct) ListSessions(_ context.Context, uid string) ([]SessionInfo, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	var out []SessionInfo
	for id, s := range a.auth {
		if s.userID == uid && !s.revoked {
			out = append(out, SessionInfo{ID: id})
		}
	}
	return out, nil
}
func (a *memAcct) RevokeSessionByID(_ context.Context, uid, id string) (bool, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	s := a.auth[id]
	if s == nil || s.userID != uid || s.revoked {
		return false, nil
	}
	s.revoked = true
	return true, nil
}
func (a *memAcct) CreateFaceAttempt(_ context.Context, h []byte, uid, cid, purpose string, _ time.Time) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.attempts[string(h)] = FaceAttempt{uid, cid, purpose}
	return nil
}
func (a *memAcct) TakeFaceAttempt(_ context.Context, h []byte) (FaceAttempt, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	f, ok := a.attempts[string(h)]
	delete(a.attempts, string(h))
	if !ok {
		return f, ErrNoAttempt
	}
	return f, nil
}
func (a *memAcct) ScheduleDeletion(_ context.Context, uid string, _ time.Time) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	u := a.users[uid]
	if u == nil || u.Status != "active" {
		return ErrWrongState
	}
	u.Status = "deletion_pending"
	for _, s := range a.auth {
		if s.userID == uid {
			s.revoked = true
		}
	}
	return nil
}
func (a *memAcct) RestoreAccount(_ context.Context, uid string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	u := a.users[uid]
	if u == nil || u.Status != "deletion_pending" {
		return ErrWrongState
	}
	u.Status = "active"
	return nil
}
func (a *memAcct) Roles(_ context.Context, uid string) ([]string, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.roles[uid], nil
}
func (a *memAcct) SetStatus(_ context.Context, uid, from, to string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	u := a.users[uid]
	if u == nil || u.Status != from {
		return ErrWrongState
	}
	u.Status = to
	return nil
}
func (a *memAcct) Audit(_ context.Context, e AuditEntry) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.auditFail {
		return errors.New("audit store down")
	}
	e.At = time.Now()
	a.audits = append(a.audits, e)
	return nil
}
func (a *memAcct) ListAudit(_ context.Context, uid string, _ int) ([]AuditEntry, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	var out []AuditEntry
	for _, e := range a.audits {
		if e.TargetUser == uid {
			out = append(out, e)
		}
	}
	return out, nil
}
func (a *memAcct) has(action, target string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, e := range a.audits {
		if e.Action == action && e.TargetUser == target {
			return true
		}
	}
	return false
}

type fakeMail struct {
	to, code string
	fail     bool
}

func (f *fakeMail) SendOTP(_ context.Context, to, code string, _ time.Duration) error {
	if f.fail {
		return errors.New("smtp down")
	}
	f.to, f.code = to, code
	return nil
}

type aenv struct {
	*env
	acct *memAcct
	mail *fakeMail
}

func setupAcct(t *testing.T) *aenv {
	seed := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32))
	signer, err := token.NewSigner(seed, "k1", "fyberflix-auth", "fyberflix", 10*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	st, face := newMem(), &fakeFace{enrolled: map[string]bool{}}
	acct, ml := newMemAcct(st), &fakeMail{}
	api := New(st, face, signer, Config{SessionTTL: time.Minute, HoldTTL: time.Minute,
		RefreshTTL: time.Hour, MaxRefresh: 5, PublicBaseURL: "https://FyberFlix.zeaipc.in"},
		slog.New(slog.NewTextHandler(io.Discard, nil))).
		WithAccount(acct, ml, AccountConfig{OTPPepper: bytes.Repeat([]byte{9}, 32)})
	srv := httptest.NewServer(api.Handler())
	t.Cleanup(srv.Close)
	return &aenv{&env{t, srv, st, face}, acct, ml}
}

// user signs up and returns number, access token, user id.
func (e *aenv) user(name string) (number, access, id string) {
	number, tk := e.signup(name)
	access = str(tk, "access_token")
	c, m := e.js("GET", "/v1/me", access, "")
	e.want(c, m, 200)
	return number, access, str(m, "user", "id")
}

func (e *aenv) login(number string) string {
	c, m := e.js("POST", "/v1/login/start", "", `{"identifier":"`+number+`"}`)
	e.want(c, m, 200)
	c, m = e.mp("/v1/login/face", str(m, "login_token"), nil, "good-login")
	e.want(c, m, 200)
	return str(m, "tokens", "access_token")
}

func other(code string) string {
	if code == "111111" {
		return "222222"
	}
	return "111111"
}

// ---------------- tests ----------------

func TestEmailOTP(t *testing.T) {
	e := setupAcct(t)
	_, a1, _ := e.user("User_One")
	_, a2, _ := e.user("User_Two")
	_, a3, _ := e.user("User_Three") // separate user: bad input also counts toward the hourly limit

	if c, _ := e.js("POST", "/v1/me/email", "", `{"email":"a@b.com"}`); c != 401 {
		t.Fatalf("no token: %d", c)
	}
	for _, bad := range []string{`{"email":"nope"}`, `{"email":"a@b.com\r\nBcc: x@y.com"}`, `{"email":"a b@c.com"}`} {
		if c, _ := e.js("POST", "/v1/me/email", a3, bad); c != 422 {
			t.Fatalf("%s should be rejected: %d", bad, c)
		}
	}

	// happy path (email is lower-cased, masked in the reply)
	c, m := e.js("POST", "/v1/me/email", a1, `{"email":"Arman@Example.com"}`)
	e.want(c, m, 202)
	if e.mail.to != "arman@example.com" || len(e.mail.code) != 6 {
		t.Fatalf("mail: %+v", e.mail)
	}
	if c, _ = e.js("POST", "/v1/me/email/verify", a1, `{"code":"`+other(e.mail.code)+`"}`); c != 422 {
		t.Fatalf("wrong code: %d", c)
	}
	if c, _ = e.js("POST", "/v1/me/email/verify", a1, `{"code":"12ab"}`); c != 422 {
		t.Fatalf("malformed code: %d", c)
	}
	c, m = e.js("POST", "/v1/me/email/verify", a1, `{"code":"`+e.mail.code+`"}`)
	e.want(c, m, 200)
	if str(m, "email") != "a***@example.com" {
		t.Fatalf("not masked: %v", m)
	}
	if c, _ = e.js("POST", "/v1/me/email/verify", a1, `{"code":"`+e.mail.code+`"}`); c != 422 {
		t.Fatalf("code must be single use: %d", c)
	}

	// the same verified email cannot be claimed by a second account
	e.js("POST", "/v1/me/email", a2, `{"email":"arman@example.com"}`)
	if c, _ = e.js("POST", "/v1/me/email/verify", a2, `{"code":"`+e.mail.code+`"}`); c != 409 {
		t.Fatalf("email taken: %d", c)
	}

	// lockout after 5 wrong codes, even if the right one follows
	e.js("POST", "/v1/me/email", a1, `{"email":"second@example.com"}`)
	good := e.mail.code
	for i := 0; i < 5; i++ {
		e.js("POST", "/v1/me/email/verify", a1, `{"code":"`+other(good)+`"}`)
	}
	if c, _ = e.js("POST", "/v1/me/email/verify", a1, `{"code":"`+good+`"}`); c != 429 {
		t.Fatalf("lockout: %d", c)
	}

	// mail failure -> 502 and no success claim
	e.mail.fail = true
	if c, _ = e.js("POST", "/v1/me/email", a1, `{"email":"third@example.com"}`); c != 502 {
		t.Fatalf("mail failure: %d", c)
	}

	// remove
	if c, _ = e.js("DELETE", "/v1/me/email", a1, ""); c != 204 {
		t.Fatalf("remove: %d", c)
	}
}

func TestRenameCable(t *testing.T) {
	e := setupAcct(t)
	_, a1, _ := e.user("Arman_Films")
	_, a2, _ := e.user("Other_One")

	for _, bad := range []string{"ZEAIPC", "Z3A1PC", "ab", "123456789", "a b"} {
		if c, _ := e.js("POST", "/v1/me/cable-name", a1, `{"name":"`+bad+`"}`); c != 422 {
			t.Fatalf("%q should be rejected: %d", bad, c)
		}
	}
	if c, _ := e.js("POST", "/v1/me/cable-name", a1, `{"name":"Arman_Films"}`); c != 422 {
		t.Fatalf("same name: %d", c)
	}
	if c, _ := e.js("POST", "/v1/me/cable-name", a1, `{"name":"Other_One"}`); c != 409 {
		t.Fatalf("taken by active user: %d", c)
	}
	c, m := e.js("POST", "/v1/me/cable-name", a1, `{"name":"Arman_Studio"}`)
	e.want(c, m, 200)
	if str(m, "user", "profile_url") != "https://FyberFlix.zeaipc.in/Arman_Studio" {
		t.Fatalf("profile url: %v", m)
	}
	if c, _ = e.js("POST", "/v1/me/cable-name", a1, `{"name":"Arman_Again"}`); c != 429 {
		t.Fatalf("cooldown: %d", c)
	}
	// the old name is reserved: nobody else can take it
	if c, _ = e.js("POST", "/v1/me/cable-name", a2, `{"name":"Arman_Films"}`); c != 409 {
		t.Fatalf("released name must stay reserved: %d", c)
	}
}

func TestSessionsListAndRevoke(t *testing.T) {
	e := setupAcct(t)
	number, a1, _ := e.user("User_One")
	_, a2, _ := e.user("User_Two")
	a1b := e.login(number) // second device

	c, m := e.js("GET", "/v1/me/sessions", a1b, "")
	e.want(c, m, 200)
	list := m["sessions"].([]any)
	if len(list) != 2 {
		t.Fatalf("want 2 sessions: %v", m)
	}
	var cur, otherID string
	for _, x := range list {
		s := x.(map[string]any)
		if s["current"] == true {
			cur = s["id"].(string)
		} else {
			otherID = s["id"].(string)
		}
	}
	if cur == "" || otherID == "" {
		t.Fatalf("exactly one must be current: %v", list)
	}
	if c, _ = e.js("DELETE", "/v1/me/sessions/"+otherID, a2, ""); c != 404 {
		t.Fatalf("cannot revoke someone else's session: %d", c)
	}
	if c, _ = e.js("DELETE", "/v1/me/sessions/not-a-uuid", a1, ""); c != 400 {
		t.Fatalf("bad id: %d", c)
	}
	if c, _ = e.js("DELETE", "/v1/me/sessions/"+otherID, a1b, ""); c != 204 {
		t.Fatalf("revoke: %d", c)
	}
	if c, _ = e.js("DELETE", "/v1/me/sessions/"+otherID, a1b, ""); c != 404 {
		t.Fatalf("revoke twice: %d", c)
	}
}

func TestDeleteAndRestore(t *testing.T) {
	e := setupAcct(t)
	number, a1, id := e.user("Leaving_User")

	if c, _ := e.js("POST", "/v1/me/delete/start", a1, `{"confirm":"yes"}`); c != 422 {
		t.Fatalf("confirm required: %d", c)
	}
	c, m := e.js("POST", "/v1/me/delete/start", a1, `{"confirm":"DELETE"}`)
	e.want(c, m, 200)
	// wrong face: nothing happens and the attempt token is burnt
	tok := str(m, "attempt_token")
	if c, m = e.mp("/v1/account/face", tok, nil, "bad-face"); c != 401 {
		t.Fatalf("wrong face: %d %v", c, m)
	}
	if c, _ = e.mp("/v1/account/face", tok, nil, "good"); c != 401 {
		t.Fatalf("attempt token reuse: %d", c)
	}
	if c, _ = e.js("GET", "/v1/me/sessions", a1, ""); c != 200 {
		t.Fatalf("account must still be active: %d", c)
	}

	c, m = e.js("POST", "/v1/me/delete/start", a1, `{"confirm":"DELETE"}`)
	e.want(c, m, 200)
	c, m = e.mp("/v1/account/face", str(m, "attempt_token"), nil, "good")
	e.want(c, m, 200)
	if str(m, "status") != "deletion_pending" {
		t.Fatalf("not scheduled: %v", m)
	}
	// blocked everywhere while pending
	if c, _ = e.js("POST", "/v1/login/start", "", `{"identifier":"`+number+`"}`); c != 403 {
		t.Fatalf("login must be blocked: %d", c)
	}
	if c, _ = e.js("POST", "/v1/me/email", a1, `{"email":"a@b.com"}`); c != 403 {
		t.Fatalf("account actions must be blocked: %d", c)
	}
	if !e.acct.has("account.deletion_requested", id) {
		t.Fatal("deletion not audited")
	}

	// restore needs the face too
	c, m = e.js("POST", "/v1/restore/start", "", `{"identifier":"`+number+`"}`)
	e.want(c, m, 200)
	if c, _ = e.mp("/v1/account/face", str(m, "attempt_token"), nil, "bad-face"); c != 401 {
		t.Fatalf("restore wrong face: %d", c)
	}
	c, m = e.js("POST", "/v1/restore/start", "", `{"identifier":"`+number+`"}`)
	e.want(c, m, 200)
	c, m = e.mp("/v1/account/face", str(m, "attempt_token"), nil, "good")
	e.want(c, m, 200)
	if str(m, "user", "status") != "active" || str(m, "tokens", "access_token") == "" {
		t.Fatalf("restore: %v", m)
	}
	// an active account cannot be "restored"
	if c, _ = e.js("POST", "/v1/restore/start", "", `{"identifier":"`+number+`"}`); c != 403 {
		t.Fatalf("restore on active: %d", c)
	}
	if c, _ = e.js("POST", "/v1/restore/start", "", `{"identifier":"x y"}`); c != 400 {
		t.Fatalf("restore bad ident: %d", c)
	}
}

func TestStaff(t *testing.T) {
	e := setupAcct(t)
	_, as, sid := e.user("Support_Agent")
	_, aa, adminID := e.user("Admin_Person")
	tNum, at, tid := e.user("Normal_Person")
	e.acct.roles[sid] = []string{"support"}
	e.acct.roles[adminID] = []string{"admin"}

	q := func(path, reason string) string {
		return path + "?reason=" + url.QueryEscape(reason)
	}
	look := "/v1/staff/users/lookup?q=" + tNum + "&reason="

	if c, _ := e.js("GET", look+url.QueryEscape("ticket 4821"), at, ""); c != 403 {
		t.Fatalf("normal user must not reach staff: %d", c)
	}
	if c, _ := e.js("GET", look+url.QueryEscape("x"), as, ""); c != 400 {
		t.Fatalf("reason required: %d", c)
	}
	c, m := e.js("GET", look+url.QueryEscape("ticket 4821 locked out"), as, "")
	e.want(c, m, 200)
	if str(m, "id") != tid || str(m, "fyber_cable_name") != "Normal_Person" {
		t.Fatalf("lookup: %v", m)
	}
	if _, leaked := m["face_ref"]; leaked {
		t.Fatal("face data must never be shown to staff")
	}
	if !e.acct.has("staff.lookup", tid) {
		t.Fatal("lookup not audited")
	}

	// no audit record -> no data
	e.acct.auditFail = true
	if c, _ = e.js("GET", look+url.QueryEscape("ticket 4821 again"), as, ""); c != 500 {
		t.Fatalf("audit failure must block: %d", c)
	}
	e.acct.auditFail = false

	// support: revoke yes, suspend no
	body := `{"reason":"ticket 4821 stolen phone"}`
	if c, _ = e.js("POST", "/v1/staff/users/"+tid+"/revoke-sessions", as, body); c != 204 {
		t.Fatalf("support revoke: %d", c)
	}
	if c, _ = e.js("POST", "/v1/staff/users/"+tid+"/revoke-sessions", as, `{"reason":"x"}`); c != 400 {
		t.Fatalf("revoke without reason: %d", c)
	}
	if c, _ = e.js("POST", "/v1/staff/users/"+tid+"/suspend", as, body); c != 403 {
		t.Fatalf("support must not suspend: %d", c)
	}
	// admin: suspend works, self-action does not
	if c, _ = e.js("POST", "/v1/staff/users/"+adminID+"/suspend", aa, body); c != 403 {
		t.Fatalf("self-suspend: %d", c)
	}
	if c, _ = e.js("POST", "/v1/staff/users/"+tid+"/suspend", aa, body); c != 204 {
		t.Fatalf("admin suspend: %d", c)
	}
	if c, _ = e.js("POST", "/v1/login/start", "", `{"identifier":"`+tNum+`"}`); c != 403 {
		t.Fatalf("suspended user must not log in: %d", c)
	}
	if c, _ = e.js("POST", "/v1/staff/users/"+tid+"/unsuspend", aa, body); c != 204 {
		t.Fatalf("unsuspend: %d", c)
	}
	if c, _ = e.js("POST", "/v1/staff/users/"+tid+"/unsuspend", aa, body); c != 403 && c != 409 {
		t.Fatalf("unsuspend an active user must fail: %d", c)
	}

	// audit view: admin only, and itself audited
	if c, _ = e.js("GET", q("/v1/staff/users/"+tid+"/audit", "ticket 4821 review"), as, ""); c != 403 {
		t.Fatalf("support must not read audit: %d", c)
	}
	c, m = e.js("GET", q("/v1/staff/users/"+tid+"/audit", "ticket 4821 review"), aa, "")
	e.want(c, m, 200)
	if len(m["entries"].([]any)) < 3 || !e.acct.has("staff.audit_view", tid) {
		t.Fatalf("audit view: %v", m)
	}

	// a revoked role takes effect immediately
	delete(e.acct.roles, sid)
	if c, _ = e.js("GET", look+url.QueryEscape("ticket 4821 later"), as, ""); c != 403 {
		t.Fatalf("role revoke must apply at once: %d", c)
	}
}
func TestPublicProfile(t *testing.T) {
	e := setupAcct(t)
	number, _, id := e.user("Arman_Films")

	for _, ident := range []string{"Arman_Films", "arman_films", number, "@Arman_Films"} {
		c, m := e.js("GET", "/v1/profiles/"+ident, "", "")
		e.want(c, m, 200)
		if str(m, "id") != id || str(m, "fyber_cable_name") != "Arman_Films" || str(m, "fyberflix_number") != number {
			t.Fatalf("%s resolves differently: %v", ident, m)
		}
		for _, secret := range []string{"email", "face_ref", "status"} {
			if _, leaked := m[secret]; leaked {
				t.Fatalf("%s must not be public", secret)
			}
		}
	}
	// cable name and number lead to the same creator
	_, a := e.js("GET", "/v1/profiles/Arman_Films", "", "")
	_, b := e.js("GET", "/v1/profiles/"+number, "", "")
	if str(a, "id") != str(b, "id") {
		t.Fatal("name and number must resolve to the same user")
	}
	for _, bad := range []string{"nobody_here", "a%20b", "123456789", "ab"} {
		if c, _ := e.js("GET", "/v1/profiles/"+bad, "", ""); c != 404 {
			t.Fatalf("%q: want 404, got %d", bad, c)
		}
	}
	// suspended and deletion-pending accounts look like missing ones
	e.acct.users[id].Status = "suspended"
	if c, _ := e.js("GET", "/v1/profiles/Arman_Films", "", ""); c != 404 {
		t.Fatalf("suspended must be hidden: %d", c)
	}
	e.acct.users[id].Status = "deletion_pending"
	if c, _ := e.js("GET", "/v1/profiles/"+number, "", ""); c != 404 {
		t.Fatalf("pending deletion must be hidden: %d", c)
	}
}
