// Package httpapi exposes the signup-session endpoints of auth-service.
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
	"strings"
	"time"

	"github.com/zeaipc/fyberflix/services/auth/internal/identity"
)

var (
	ErrNoSession    = errors.New("signup session not found or expired")
	ErrWrongState   = errors.New("action not allowed in the current signup state")
	ErrNotHeld      = errors.New("number is not currently offered to this session")
	ErrRefreshLimit = errors.New("number refresh limit reached")
)

// Store is everything the HTTP layer needs from persistence.
type Store interface {
	CreateSession(ctx context.Context, tokenHash []byte, ip, ua string, expires time.Time) error
	// RequireState returns ErrNoSession (missing/expired) or ErrWrongState.
	RequireState(ctx context.Context, tokenHash []byte, allowed ...string) error
	// HoldNumbers reserves free numbers from candidates; returns those actually held.
	HoldNumbers(ctx context.Context, tokenHash []byte, candidates []string, until time.Time) ([]string, error)
	// ReleaseForRefresh frees this session's holds and counts a refresh (ErrRefreshLimit when exhausted).
	ReleaseForRefresh(ctx context.Context, tokenHash []byte, maxRefresh int) error
	SelectNumber(ctx context.Context, tokenHash []byte, number string, until time.Time) error
	CableNameTaken(ctx context.Context, key string) (bool, error)
	SetCableName(ctx context.Context, tokenHash []byte, display string) error
}

type Config struct {
	SessionTTL, HoldTTL time.Duration
	MaxRefresh          int
}

type Server struct {
	st  Store
	cfg Config
	log *slog.Logger
}

func New(st Store, cfg Config, log *slog.Logger) *Server { return &Server{st: st, cfg: cfg, log: log} }

func (s *Server) Handler() http.Handler {
	m := http.NewServeMux()
	m.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	m.HandleFunc("POST /v1/signup/sessions", s.createSession)
	m.HandleFunc("POST /v1/signup/number-offers/refresh", s.refreshOffers)
	m.HandleFunc("POST /v1/signup/number", s.selectNumber)
	m.HandleFunc("GET /v1/signup/cable-name/check", s.checkName)
	m.HandleFunc("POST /v1/signup/cable-name", s.setName)
	return secure(m)
}

func (s *Server) createSession(w http.ResponseWriter, r *http.Request) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		s.fail(w, err)
		return
	}
	token := base64.RawURLEncoding.EncodeToString(raw)
	hash := hashToken(token)
	expires := time.Now().Add(s.cfg.SessionTTL)
	if err := s.st.CreateSession(r.Context(), hash, clientIP(r), r.UserAgent(), expires); err != nil {
		s.fail(w, err)
		return
	}
	offers, err := s.offer(r.Context(), hash)
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{
		"session_token": token, "expires_at": expires, "number_offers": offers,
	})
}

func (s *Server) refreshOffers(w http.ResponseWriter, r *http.Request) {
	hash, ok := s.session(w, r, "started")
	if !ok {
		return
	}
	if err := s.st.ReleaseForRefresh(r.Context(), hash, s.cfg.MaxRefresh); err != nil {
		s.fail(w, err)
		return
	}
	offers, err := s.offer(r.Context(), hash)
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"number_offers": offers})
}

func (s *Server) selectNumber(w http.ResponseWriter, r *http.Request) {
	hash, ok := s.session(w, r, "started")
	if !ok {
		return
	}
	var in struct {
		Number string `json:"number"`
	}
	if !decode(w, r, &in) {
		return
	}
	if len(in.Number) != 9 {
		writeErr(w, http.StatusBadRequest, "invalid_number", "number must be 9 digits")
		return
	}
	if err := s.st.SelectNumber(r.Context(), hash, in.Number, time.Now().Add(s.cfg.SessionTTL)); err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"selected_number": in.Number, "state": "number_selected"})
}

func (s *Server) checkName(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.session(w, r, "number_selected", "name_chosen"); !ok {
		return
	}
	_, key, err := identity.ParseCableName(r.URL.Query().Get("name"))
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"available": false, "reason": err.Error()})
		return
	}
	taken, err := s.st.CableNameTaken(r.Context(), key)
	if err != nil {
		s.fail(w, err)
		return
	}
	resp := map[string]any{"available": !taken}
	if taken {
		resp["reason"] = "this Fyber Cable name is already taken"
	}
	writeJSON(w, http.StatusOK, resp)
}

// setName records the choice. It does NOT reserve it: the UNIQUE constraint on
// users.fyber_cable_key at account creation is the real guarantee.
func (s *Server) setName(w http.ResponseWriter, r *http.Request) {
	hash, ok := s.session(w, r, "number_selected", "name_chosen")
	if !ok {
		return
	}
	var in struct {
		Name string `json:"name"`
	}
	if !decode(w, r, &in) {
		return
	}
	display, key, err := identity.ParseCableName(in.Name)
	if err != nil {
		writeErr(w, http.StatusUnprocessableEntity, "invalid_name", err.Error())
		return
	}
	if taken, err := s.st.CableNameTaken(r.Context(), key); err != nil {
		s.fail(w, err)
		return
	} else if taken {
		writeErr(w, http.StatusConflict, "name_taken", "this Fyber Cable name is already taken")
		return
	}
	if err := s.st.SetCableName(r.Context(), hash, display); err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"fyber_cable_name": display, "state": "name_chosen",
		"profile_url": "https://FyberFlix.zeaipc.in/" + display})
}

// offer holds 10 free numbers for this session (retrying on collisions).
func (s *Server) offer(ctx context.Context, hash []byte) ([]string, error) {
	var held []string
	until := time.Now().Add(s.cfg.HoldTTL)
	for attempt := 0; attempt < 6 && len(held) < identity.OfferCount(); attempt++ {
		cands, err := identity.Candidates(identity.OfferCount() - len(held))
		if err != nil {
			return nil, err
		}
		got, err := s.st.HoldNumbers(ctx, hash, cands, until)
		if err != nil {
			return nil, err
		}
		held = append(held, got...)
	}
	if len(held) < identity.OfferCount() {
		return nil, errors.New("could not allocate number offers")
	}
	return held, nil
}

func (s *Server) session(w http.ResponseWriter, r *http.Request, allowed ...string) ([]byte, bool) {
	tok, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok || tok == "" {
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
	default:
		s.log.Error("internal error", "err", err)
		writeErr(w, http.StatusInternalServerError, "internal", "something went wrong")
	}
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
