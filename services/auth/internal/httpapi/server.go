// Package httpapi exposes auth-service's public HTTP API.
package httpapi

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/zeaipc/fyberflix/services/auth/internal/faceclient"
	"github.com/zeaipc/fyberflix/services/auth/internal/token"
)

var (
	ErrNoSession      = errors.New("signup session not found or expired")
	ErrWrongState     = errors.New("action not allowed in the current signup state")
	ErrNotHeld        = errors.New("number is not currently offered to this session")
	ErrRefreshLimit   = errors.New("number refresh limit reached")
	ErrNotFound       = errors.New("not found")
	ErrNameTaken      = errors.New("this Fyber Cable name is already taken")
	ErrInvalidRefresh = errors.New("invalid refresh token")
	ErrRefreshReuse   = errors.New("refresh token reuse detected")
	ErrNoAttempt      = errors.New("login attempt not found or expired")
)

type User struct {
	ID, Number, CableName, Status, FaceRef string
	CreatedAt                              time.Time
}

type SignupSession struct {
	State, Number, CableName, FaceRef string
	Consented                         bool
}

type LoginAttempt struct{ UserID, FaceChallengeID string }

// Face is the subset of face-service the HTTP layer needs.
type Face interface {
	Challenge(ctx context.Context, ref, purpose string) (faceclient.Challenge, error)
	Enroll(ctx context.Context, ref, challengeID string, frames [][]byte) (faceclient.Outcome, error)
	Verify(ctx context.Context, ref, challengeID string, frames [][]byte) (faceclient.Outcome, error)
}

// Store is everything the HTTP layer needs from persistence.
type Store interface {
	// --- signup session ---
	CreateSession(ctx context.Context, tokenHash []byte, ip, ua string, expires time.Time) error
	RequireState(ctx context.Context, tokenHash []byte, allowed ...string) error // ErrNoSession | ErrWrongState
	GetSignup(ctx context.Context, tokenHash []byte) (SignupSession, error)
	HoldNumbers(ctx context.Context, tokenHash []byte, candidates []string, until time.Time) ([]string, error)
	ReleaseForRefresh(ctx context.Context, tokenHash []byte, maxRefresh int) error
	SelectNumber(ctx context.Context, tokenHash []byte, number string, until time.Time) error
	CableNameTaken(ctx context.Context, key string) (bool, error)
	SetCableName(ctx context.Context, tokenHash []byte, display string) error
	RecordConsent(ctx context.Context, tokenHash []byte, version string) error
	MarkFaceChecked(ctx context.Context, tokenHash []byte) error
	CreateAccount(ctx context.Context, tokenHash []byte) (User, error)   // face_checked -> account_created (user pending)
	ActivateAccount(ctx context.Context, tokenHash []byte) (User, error) // account_created -> completed (user active)

	// --- login & device sessions ---
	FindUserByIdentifier(ctx context.Context, ident string) (User, error) // 9-digit number or cable name
	GetUser(ctx context.Context, id string) (User, error)
	CreateLoginAttempt(ctx context.Context, tokenHash []byte, userID, faceChallengeID string, expires time.Time) error
	TakeLoginAttempt(ctx context.Context, tokenHash []byte) (LoginAttempt, error) // single use
	CreateAuthSession(ctx context.Context, id, userID string, refreshHash []byte, ip, ua string, expires time.Time) error
	RotateRefresh(ctx context.Context, sessionID string, presented, next []byte, expires time.Time) (userID string, err error)
	RevokeSession(ctx context.Context, sessionID string, presented []byte) error
	RevokeAllSessions(ctx context.Context, userID string) error

	// --- abuse control ---
	Hit(ctx context.Context, key string, window time.Duration) (int, error)
}

type Config struct {
	SessionTTL, HoldTTL, RefreshTTL time.Duration
	MaxRefresh                      int
	PublicBaseURL                   string
}

type Server struct {
	st   Store
	face Face
	tok  *token.Signer
	cfg  Config
	log  *slog.Logger
}

func New(st Store, face Face, tok *token.Signer, cfg Config, log *slog.Logger) *Server {
	return &Server{st: st, face: face, tok: tok, cfg: cfg, log: log}
}

func (s *Server) Handler() http.Handler {
	m := http.NewServeMux()
	m.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	m.HandleFunc("GET /.well-known/jwks.json", s.jwks)

	m.HandleFunc("POST /v1/signup/sessions", s.createSession)
	m.HandleFunc("POST /v1/signup/number-offers/refresh", s.refreshOffers)
	m.HandleFunc("POST /v1/signup/number", s.selectNumber)
	m.HandleFunc("GET /v1/signup/cable-name/check", s.checkName)
	m.HandleFunc("POST /v1/signup/cable-name", s.setName)
	m.HandleFunc("POST /v1/signup/consent", s.consent)
	m.HandleFunc("POST /v1/signup/face/challenge", s.faceChallenge)
	m.HandleFunc("POST /v1/signup/face", s.faceSubmit)
	m.HandleFunc("POST /v1/signup/account", s.createAccount)

	m.HandleFunc("POST /v1/login/start", s.loginStart)
	m.HandleFunc("POST /v1/login/face", s.loginFace)

	m.HandleFunc("POST /v1/token/refresh", s.refresh)
	m.HandleFunc("POST /v1/logout", s.logout)
	m.HandleFunc("POST /v1/logout-all", s.logoutAll)
	m.HandleFunc("GET /v1/me", s.me)
	return secure(m)
}

// ---------- shared helpers ----------

func (s *Server) session(w http.ResponseWriter, r *http.Request, allowed ...string) ([]byte, bool) {
	tok, ok := bearer(r)
	if !ok {
		writeErr(w, http.StatusUnauthorized, "no_session", "missing signup session token")
		return nil, false
	}
	hash := hashToken(tok)
	if err := s.st.RequireState(r.Context(), hash, allowed...); err != nil {
		s.fail(w, err)
		return nil, false
	}
	return hash, true
}

// limit enforces a fixed-window counter. It fails open if the counter store errors,
// because locking everyone out is worse; the error is logged.
func (s *Server) limit(w http.ResponseWriter, r *http.Request, key string, max int, window time.Duration) bool {
	n, err := s.st.Hit(r.Context(), key, window)
	if err != nil {
		s.log.Error("rate limiter error", "err", err)
		return true
	}
	if n > max {
		w.Header().Set("Retry-After", strconv.Itoa(int(window.Seconds())))
		writeErr(w, http.StatusTooManyRequests, "rate_limited", "too many attempts, try again later")
		return false
	}
	return true
}

func (s *Server) fail(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, ErrNoSession):
		writeErr(w, http.StatusUnauthorized, "no_session", err.Error())
	case errors.Is(err, ErrWrongState):
		writeErr(w, http.StatusConflict, "wrong_state", err.Error())
	case errors.Is(err, ErrNotHeld):
		writeErr(w, http.StatusConflict, "number_not_offered", err.Error())
	case errors.Is(err, ErrRefreshLimit):
		writeErr(w, http.StatusTooManyRequests, "refresh_limit", err.Error())
	case errors.Is(err, ErrNameTaken):
		writeErr(w, http.StatusConflict, "name_taken", err.Error())
	case errors.Is(err, ErrNotFound):
		writeErr(w, http.StatusNotFound, "not_found", "account not found")
	case errors.Is(err, ErrInvalidRefresh):
		writeErr(w, http.StatusUnauthorized, "invalid_refresh", "invalid refresh token")
	case errors.Is(err, ErrRefreshReuse):
		writeErr(w, http.StatusUnauthorized, "session_revoked", "this session was revoked, please log in again")
	case errors.Is(err, faceclient.ErrUnavailable):
		s.log.Error("face service unavailable", "err", err)
		writeErr(w, http.StatusServiceUnavailable, "face_unavailable", "face verification is temporarily unavailable")
	default:
		s.log.Error("internal error", "err", err)
		writeErr(w, http.StatusInternalServerError, "internal", "something went wrong")
	}
}

func bearer(r *http.Request) (string, bool) {
	t, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	return t, ok && t != ""
}

func randomToken() (string, []byte, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", nil, err
	}
	t := base64.RawURLEncoding.EncodeToString(raw)
	return t, hashToken(t), nil
}

func hashToken(t string) []byte { h := sha256.Sum256([]byte(t)); return h[:] }

func clientIP(r *http.Request) string {
	// Behind the gateway, trust only the gateway-set header; never raw X-Forwarded-For from clients.
	if v := r.Header.Get("X-Real-IP"); v != "" {
		return v
	}
	h, _, _ := net.SplitHostPort(r.RemoteAddr)
	return h
}

func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, 4<<10)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_json", "invalid request body")
		return false
	}
	return true
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, code int, c, msg string) {
	writeJSON(w, code, map[string]any{"error": map[string]string{"code": c, "message": msg}})
}

func secure(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Cache-Control", "no-store")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
		next.ServeHTTP(w, r)
	})
}
