package httpapi

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/zeaipc/fyberflix/services/auth/internal/faceclient"
	"github.com/zeaipc/fyberflix/services/auth/internal/token"
)

// ---------------- in-memory Store (mirrors the SQL semantics) ----------------

type msess struct {
	state, number, name, faceRef, userID string
	consented                            bool
	refreshes                            int
}
type mauth struct {
	userID    string
	cur, prev []byte
	revoked   bool
}
type mem struct {
	mu       sync.Mutex
	sess     map[string]*msess
	numbers  map[string]string // number -> holder key | "assigned"
	users    map[string]*User
	byKey    map[string]string
	attempts map[string]LoginAttempt
	auth     map[string]*mauth
	hits     map[string]int
	maxHits  int
}

func newMem() *mem {
	return &mem{sess: map[string]*msess{}, numbers: map[string]string{}, users: map[string]*User{},
		byKey: map[string]string{}, attempts: map[string]LoginAttempt{}, auth: map[string]*mauth{},
		hits: map[string]int{}, maxHits: 1 << 30}
}
func k(h []byte) string { return string(h) }

func (m *mem) CreateSession(_ context.Context, h []byte, _, _ string, _ time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sess[k(h)] = &msess{state: "started", faceRef: token.NewUUID()}
	return nil
}
func (m *mem) get(h []byte) (*msess, error) {
	s := m.sess[k(h)]
	if s == nil {
		return nil, ErrNoSession
	}
	return s, nil
}
func (m *mem) RequireState(_ context.Context, h []byte, allowed ...string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, err := m.get(h)
	if err != nil {
		return err
	}
	for _, a := range allowed {
		if a == s.state {
			return nil
		}
	}
	return ErrWrongState
}
func (m *mem) GetSignup(_ context.Context, h []byte) (SignupSession, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, err := m.get(h)
	if err != nil {
		return SignupSession{}, err
	}
	return SignupSession{State: s.state, Number: s.number, CableName: s.name, FaceRef: s.faceRef, Consented: s.consented}, nil
}
func (m *mem) HoldNumbers(_ context.Context, h []byte, c []string, _ time.Time) ([]string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []string
	for _, n := range c {
		if _, taken := m.numbers[n]; !taken {
			m.numbers[n] = k(h)
			out = append(out, n)
		}
	}
	return out, nil
}
func (m *mem) ReleaseForRefresh(_ context.Context, h []byte, max int) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, _ := m.get(h)
	if s.refreshes >= max {
		return ErrRefreshLimit
	}
	s.refreshes++
	for n, who := range m.numbers {
		if who == k(h) {
			delete(m.numbers, n)
		}
	}
	return nil
}
func (m *mem) SelectNumber(_ context.Context, h []byte, n string, _ time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.numbers[n] != k(h) {
		return ErrNotHeld
	}
	for o, who := range m.numbers {
		if who == k(h) && o != n {
			delete(m.numbers, o)
		}
	}
	s, _ := m.get(h)
	s.number, s.state = n, "number_selected"
	return nil
}
func (m *mem) CableNameTaken(_ context.Context, key string) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	_, ok := m.byKey[key]
	return ok, nil
}
func (m *mem) SetCableName(_ context.Context, h []byte, d string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, _ := m.get(h)
	s.name, s.state = d, "name_chosen"
	return nil
}
func (m *mem) RecordConsent(_ context.Context, h []byte, _ string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, _ := m.get(h)
	if s.state != "name_chosen" {
		return ErrWrongState
	}
	s.consented = true
	return nil
}
func (m *mem) MarkFaceChecked(_ context.Context, h []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, _ := m.get(h)
	if s.state != "name_chosen" || !s.consented {
		return ErrWrongState
	}
	s.state = "face_checked"
	return nil
}
func (m *mem) CreateAccount(_ context.Context, h []byte) (User, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, _ := m.get(h)
	if s.state != "face_checked" {
		return User{}, ErrWrongState
	}
	key := strings.ToLower(s.name)
	if _, dup := m.byKey[key]; dup {
		return User{}, ErrNameTaken
	}
	u := &User{ID: token.NewUUID(), Number: s.number, CableName: s.name, Status: "pending", FaceRef: s.faceRef}
	m.users[u.ID], m.byKey[key], m.numbers[s.number] = u, u.ID, "assigned"
	s.state, s.userID = "account_created", u.ID
	return *u, nil
}
func (m *mem) ActivateAccount(_ context.Context, h []byte) (User, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, _ := m.get(h)
	if s.state != "account_created" {
		return User{}, ErrWrongState
	}
	m.users[s.userID].Status, s.state = "active", "completed"
	return *m.users[s.userID], nil
}
func (m *mem) FindUserByIdentifier(_ context.Context, id string) (User, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, u := range m.users {
		if u.Number == id || strings.EqualFold(u.CableName, id) {
			return *u, nil
		}
	}
	return User{}, ErrNotFound
}
func (m *mem) GetUser(_ context.Context, id string) (User, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if u := m.users[id]; u != nil {
		return *u, nil
	}
	return User{}, ErrNotFound
}
func (m *mem) CreateLoginAttempt(_ context.Context, h []byte, uid, cid string, _ time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.attempts[k(h)] = LoginAttempt{uid, cid}
	return nil
}
func (m *mem) TakeLoginAttempt(_ context.Context, h []byte) (LoginAttempt, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	a, ok := m.attempts[k(h)]
	delete(m.attempts, k(h))
	if !ok {
		return a, ErrNoAttempt
	}
	return a, nil
}
func (m *mem) CreateAuthSession(_ context.Context, id, uid string, h []byte, _, _ string, _ time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.auth[id] = &mauth{userID: uid, cur: h}
	return nil
}
func (m *mem) RotateRefresh(_ context.Context, sid string, presented, next []byte, _ time.Time) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	a := m.auth[sid]
	if a == nil || a.revoked {
		return "", ErrInvalidRefresh
	}
	switch {
	case token.Equal(a.cur, presented):
		a.prev, a.cur = a.cur, next
		return a.userID, nil
	case token.Equal(a.prev, presented):
		a.revoked = true
		return "", ErrRefreshReuse
	}
	return "", ErrInvalidRefresh
}
func (m *mem) RevokeSession(_ context.Context, sid string, presented []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if a := m.auth[sid]; a != nil && (token.Equal(a.cur, presented) || token.Equal(a.prev, presented)) {
		a.revoked = true
	}
	return nil
}
func (m *mem) RevokeAllSessions(_ context.Context, uid string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, a := range m.auth {
		if a.userID == uid {
			a.revoked = true
		}
	}
	return nil
}
func (m *mem) Hit(_ context.Context, key string, _ time.Duration) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.hits[key]++
	return m.hits[key], nil
}

// ---------------- fake face-service: frames starting "good" match, "bad" don't ----------------

type fakeFace struct {
	enrolled map[string]bool
	down     bool
}

func (f *fakeFace) Challenge(_ context.Context, ref, purpose string) (faceclient.Challenge, error) {
	if f.down {
		return faceclient.Challenge{}, faceclient.ErrUnavailable
	}
	return faceclient.Challenge{ID: "ch:" + purpose + ":" + ref, Steps: []string{"center", "turn_left", "center", "turn_right"}, ExpiresIn: 120}, nil
}
func (f *fakeFace) result(frames [][]byte) faceclient.Outcome {
	if len(frames) > 0 && bytes.Contains(frames[0], []byte("good")) {
		return faceclient.Outcome{OK: true}
	}
	return faceclient.Outcome{Reason: "no_match"}
}
func (f *fakeFace) Enroll(_ context.Context, ref, cid string, fr [][]byte) (faceclient.Outcome, error) {
	if cid != "ch:enroll:"+ref {
		return faceclient.Outcome{Reason: "challenge_invalid"}, nil
	}
	o := f.result(fr)
	if o.OK {
		f.enrolled[ref] = true
	}
	return o, nil
}
func (f *fakeFace) Verify(_ context.Context, ref, cid string, fr [][]byte) (faceclient.Outcome, error) {
	if cid != "ch:verify:"+ref || !f.enrolled[ref] {
		return faceclient.Outcome{Reason: "challenge_invalid"}, nil
	}
	return f.result(fr), nil
}

// ---------------- helpers ----------------

type env struct {
	t    *testing.T
	srv  *httptest.Server
	st   *mem
	face *fakeFace
}

func setup(t *testing.T) *env {
	seed := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32))
	signer, err := token.NewSigner(seed, "k1", "fyberflix-auth", "fyberflix", 10*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	st, face := newMem(), &fakeFace{enrolled: map[string]bool{}}
	api := New(st, face, signer, Config{SessionTTL: time.Minute, HoldTTL: time.Minute,
		RefreshTTL: time.Hour, MaxRefresh: 5, PublicBaseURL: "https://FyberFlix.zeaipc.in"},
		slog.New(slog.NewTextHandler(io.Discard, nil)))
	srv := httptest.NewServer(api.Handler())
	t.Cleanup(srv.Close)
	return &env{t, srv, st, face}
}

func (e *env) do(method, path, tok, ctype string, body io.Reader) (int, map[string]any) {
	req, _ := http.NewRequest(method, e.srv.URL+path, body)
	if tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	if ctype != "" {
		req.Header.Set("Content-Type", ctype)
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer res.Body.Close()
	var m map[string]any
	_ = json.NewDecoder(res.Body).Decode(&m)
	return res.StatusCode, m
}
func (e *env) js(method, path, tok, body string) (int, map[string]any) {
	return e.do(method, path, tok, "application/json", strings.NewReader(body))
}
func (e *env) mp(path, tok string, fields map[string]string, frames ...string) (int, map[string]any) {
	var b bytes.Buffer
	w := multipart.NewWriter(&b)
	for k, v := range fields {
		w.WriteField(k, v)
	}
	for i, f := range frames {
		fw, _ := w.CreateFormFile("frames", "f"+string(rune('a'+i))+".jpg")
		fw.Write(append([]byte{0xFF, 0xD8, 0xFF}, f...))
	}
	w.Close()
	return e.do("POST", path, tok, w.FormDataContentType(), &b)
}
func (e *env) want(got int, m map[string]any, want int) map[string]any {
	e.t.Helper()
	if got != want {
		e.t.Fatalf("status %d (want %d): %v", got, want, m)
	}
	return m
}
func str(m map[string]any, path ...string) string {
	var cur any = m
	for _, p := range path {
		cur = cur.(map[string]any)[p]
	}
	s, _ := cur.(string)
	return s
}

// signup runs the whole happy path and returns (user number, tokens map).
func (e *env) signup(name string) (string, map[string]any) {
	c, m := e.js("POST", "/v1/signup/sessions", "", "")
	e.want(c, m, 201)
	sess := str(m, "session_token")
	number := m["number_offers"].([]any)[2].(string)
	c, m = e.js("POST", "/v1/signup/number", sess, `{"number":"`+number+`"}`)
	e.want(c, m, 200)
	c, m = e.js("POST", "/v1/signup/cable-name", sess, `{"name":"`+name+`"}`)
	e.want(c, m, 200)
	c, m = e.js("POST", "/v1/signup/consent", sess, `{"biometric_consent":true,"terms_version":"2026-10"}`)
	e.want(c, m, 200)
	c, m = e.js("POST", "/v1/signup/face/challenge", sess, "")
	e.want(c, m, 200)
	if str(m, "purpose") != "enroll" {
		e.t.Fatal("first challenge must be enroll")
	}
	c, m = e.mp("/v1/signup/face", sess, map[string]string{"challenge_id": str(m, "challenge_id")}, "good1", "good2")
	e.want(c, m, 200)
	c, m = e.js("POST", "/v1/signup/account", sess, "")
	e.want(c, m, 201)
	if str(m, "user", "fyberflix_number") != number || str(m, "user", "status") != "pending" {
		e.t.Fatalf("bad user: %v", m)
	}
	c, m = e.js("POST", "/v1/signup/face/challenge", sess, "")
	e.want(c, m, 200)
	if str(m, "purpose") != "verify" {
		e.t.Fatal("second challenge must be verify")
	}
	c, m = e.mp("/v1/signup/face", sess, map[string]string{"challenge_id": str(m, "challenge_id")}, "good1")
	e.want(c, m, 200)
	if str(m, "state") != "completed" || str(m, "user", "status") != "active" {
		e.t.Fatalf("not completed: %v", m)
	}
	return number, m["tokens"].(map[string]any)
}

// ---------------- tests ----------------

func TestFullSignupLoginAndTokens(t *testing.T) {
	e := setup(t)
	number, tokens := e.signup("Arman_Films")

	c, m := e.js("GET", "/v1/me", str(tokens, "access_token"), "")
	e.want(c, m, 200)
	if str(m, "user", "fyberflix_number") != number || str(m, "user", "profile_url") != "https://FyberFlix.zeaipc.in/Arman_Films" {
		t.Fatalf("me: %v", m)
	}
	if c, _ := e.js("GET", "/v1/me", "garbage", ""); c != 401 {
		t.Fatalf("garbage token: %d", c)
	}
	if c, _ := e.js("GET", "/v1/me", "", ""); c != 401 {
		t.Fatalf("no token: %d", c)
	}

	// refresh rotates; reusing the OLD token revokes the whole session
	old := str(tokens, "refresh_token")
	c, m = e.js("POST", "/v1/token/refresh", "", `{"refresh_token":"`+old+`"}`)
	e.want(c, m, 200)
	fresh := str(m, "refresh_token")
	if c, m = e.js("POST", "/v1/token/refresh", "", `{"refresh_token":"`+old+`"}`); c != 401 || str(m, "error", "code") != "session_revoked" {
		t.Fatalf("reuse not detected: %d %v", c, m)
	}
	if c, _ = e.js("POST", "/v1/token/refresh", "", `{"refresh_token":"`+fresh+`"}`); c != 401 {
		t.Fatalf("session must stay revoked, got %d", c)
	}

	// login by number, then by cable name (case-insensitive)
	for _, ident := range []string{number, "arman_films"} {
		c, m = e.js("POST", "/v1/login/start", "", `{"identifier":"`+ident+`"}`)
		e.want(c, m, 200)
		lt := str(m, "login_token")
		c, m = e.mp("/v1/login/face", lt, nil, "good-login")
		e.want(c, m, 200)
		if str(m, "user", "fyberflix_number") != number || str(m, "tokens", "access_token") == "" {
			t.Fatalf("login: %v", m)
		}
		if c, _ = e.mp("/v1/login/face", lt, nil, "good-login"); c != 401 { // login token is single use
			t.Fatalf("login token reuse: %d", c)
		}
	}

	// wrong face -> generic 401
	c, m = e.js("POST", "/v1/login/start", "", `{"identifier":"`+number+`"}`)
	e.want(c, m, 200)
	if c, m = e.mp("/v1/login/face", str(m, "login_token"), nil, "bad-face"); c != 401 || str(m, "error", "code") != "face_verification_failed" {
		t.Fatalf("wrong face: %d %v", c, m)
	}

	// unknown account, malformed identifier
	if c, _ = e.js("POST", "/v1/login/start", "", `{"identifier":"nobody_here"}`); c != 404 {
		t.Fatalf("unknown: %d", c)
	}
	if c, _ = e.js("POST", "/v1/login/start", "", `{"identifier":"a b"}`); c != 400 {
		t.Fatalf("malformed: %d", c)
	}

	// logout-all kills every device
	c, m = e.js("POST", "/v1/login/start", "", `{"identifier":"`+number+`"}`)
	e.want(c, m, 200)
	c, m = e.mp("/v1/login/face", str(m, "login_token"), nil, "good")
	e.want(c, m, 200)
	tk := m["tokens"].(map[string]any)
	if c, _ = e.js("POST", "/v1/logout-all", str(tk, "access_token"), ""); c != 204 {
		t.Fatalf("logout-all: %d", c)
	}
	if c, _ = e.js("POST", "/v1/token/refresh", "", `{"refresh_token":"`+str(tk, "refresh_token")+`"}`); c != 401 {
		t.Fatalf("refresh after logout-all: %d", c)
	}
}

func TestSignupGuards(t *testing.T) {
	e := setup(t)
	c, m := e.js("POST", "/v1/signup/sessions", "", "")
	e.want(c, m, 201)
	sess := str(m, "session_token")
	n := m["number_offers"].([]any)[0].(string)

	if c, _ = e.js("POST", "/v1/signup/number", sess, `{"number":"123123123"}`); c != 409 {
		t.Fatalf("unoffered number: %d", c)
	}
	if c, _ = e.js("POST", "/v1/signup/number", sess, `{"number":"12ab"}`); c != 400 {
		t.Fatalf("malformed number: %d", c)
	}
	e.js("POST", "/v1/signup/number", sess, `{"number":"`+n+`"}`)
	if c, _ = e.js("POST", "/v1/signup/number-offers/refresh", sess, ""); c != 409 {
		t.Fatalf("refresh after selection: %d", c)
	}
	for _, bad := range []string{"ZEAIPC", "Z3A1PC", "zikriyon_os", "a b"} {
		if c, _ = e.js("POST", "/v1/signup/cable-name", sess, `{"name":"`+bad+`"}`); c != 422 {
			t.Fatalf("%q should be rejected: %d", bad, c)
		}
	}
	e.js("POST", "/v1/signup/cable-name", sess, `{"name":"Good_Name"}`)

	// face before consent is blocked
	if c, _ = e.js("POST", "/v1/signup/face/challenge", sess, ""); c != 403 {
		t.Fatalf("challenge without consent: %d", c)
	}
	if c, _ = e.js("POST", "/v1/signup/consent", sess, `{"biometric_consent":false,"terms_version":"1"}`); c != 422 {
		t.Fatalf("consent=false must be rejected: %d", c)
	}
	// account before face is blocked
	if c, _ = e.js("POST", "/v1/signup/account", sess, ""); c != 409 {
		t.Fatalf("account without face: %d", c)
	}
	e.js("POST", "/v1/signup/consent", sess, `{"biometric_consent":true,"terms_version":"1"}`)
	// non-JPEG frame, wrong challenge, failed liveness/match
	c, m = e.js("POST", "/v1/signup/face/challenge", sess, "")
	cid := str(m, "challenge_id")
	var b bytes.Buffer
	w := multipart.NewWriter(&b)
	w.WriteField("challenge_id", cid)
	fw, _ := w.CreateFormFile("frames", "x.png")
	fw.Write([]byte("\x89PNG...."))
	w.Close()
	if c, _ = e.do("POST", "/v1/signup/face", sess, w.FormDataContentType(), &b); c != 400 {
		t.Fatalf("png frame: %d", c)
	}
	if c, m = e.mp("/v1/signup/face", sess, map[string]string{"challenge_id": "wrong"}, "good"); c != 409 {
		t.Fatalf("wrong challenge: %d %v", c, m)
	}
	if c, m = e.mp("/v1/signup/face", sess, map[string]string{"challenge_id": cid}, "bad"); c != 401 {
		t.Fatalf("bad face: %d %v", c, m)
	}

	// face service down -> 503, not 500
	e.face.down = true
	if c, _ = e.js("POST", "/v1/signup/face/challenge", sess, ""); c != 503 {
		t.Fatalf("face down: %d", c)
	}
}

func TestNameRaceAndLimits(t *testing.T) {
	e := setup(t)
	e.signup("Taken_Name")
	// second person picks the same name (any case): checked early AND at account creation
	c, m := e.js("POST", "/v1/signup/sessions", "", "")
	e.want(c, m, 201)
	sess := str(m, "session_token")
	n := m["number_offers"].([]any)[0].(string)
	e.js("POST", "/v1/signup/number", sess, `{"number":"`+n+`"}`)
	if c, _ = e.js("POST", "/v1/signup/cable-name", sess, `{"name":"TAKEN_NAME"}`); c != 409 {
		t.Fatalf("duplicate name: %d", c)
	}

	e.st.mu.Lock()
	e.st.hits["signup:ip:127.0.0.1"] = 20 // next hit is #21
	e.st.mu.Unlock()
	if c, _ = e.js("POST", "/v1/signup/sessions", "", ""); c != 429 {
		t.Fatalf("rate limit: %d", c)
	}
}

func TestJWKS(t *testing.T) {
	e := setup(t)
	c, m := e.js("GET", "/.well-known/jwks.json", "", "")
	e.want(c, m, 200)
	if len(m["keys"].([]any)) != 1 {
		t.Fatalf("jwks: %v", m)
	}
}
