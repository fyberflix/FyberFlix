package httpapi

import (
	"context"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/zeaipc/fyberflix/services/auth/internal/identity"
	"github.com/zeaipc/fyberflix/services/auth/internal/token"
)

var identRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{1,28}[A-Za-z0-9]$`)

// loginStart: identifier = Fyber Cable name or 9-digit FyberFlix number. Face is the credential.
func (s *Server) loginStart(w http.ResponseWriter, r *http.Request) {
	if !s.limit(w, r, "login:ip:"+clientIP(r), 30, 10*time.Minute) {
		return
	}
	// loginStart: pehle IP limit ke turant baad
	if s.loginBlocked(w, r, "ip:"+clientIP(r)) {
		return
	}
	var in struct {
		Identifier string `json:"identifier"`
	}
	if !decode(w, r, &in) {
		return
	}
	ident := strings.TrimPrefix(strings.TrimSpace(in.Identifier), "@")
	if !identity.IsNumber(ident) && !identRe.MatchString(ident) {
		writeErr(w, http.StatusBadRequest, "invalid_identifier", "enter your Fyber Cable name or FyberFlix number")
		return
	}
	if !s.limit(w, r, "login:id:"+strings.ToLower(ident), 10, 10*time.Minute) {
		return
	}
	u, err := s.st.FindUserByIdentifier(r.Context(), ident)
	if err != nil {
		s.fail(w, err)
		return
	}
	if u.Status != "active" {
		writeErr(w, http.StatusForbidden, "account_unavailable", "this account cannot log in right now")
		return
	}
	// loginStart: "account_unavailable" check ke baad, s.face.Challenge se pehle
	if s.loginBlocked(w, r, "user:"+u.ID) {
		return
	}
	ch, err := s.face.Challenge(r.Context(), u.FaceRef, "verify")
	if err != nil {
		s.fail(w, err)
		return
	}
	tok, hash, err := randomToken()
	if err != nil {
		s.fail(w, err)
		return
	}
	if err := s.st.CreateLoginAttempt(r.Context(), hash, u.ID, ch.ID, time.Now().Add(3*time.Minute)); err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"login_token": tok, "steps": ch.Steps, "expires_in": ch.ExpiresIn})
}

// loginFace: Authorization: Bearer <login_token>, multipart frames[]. One try per login_token.
func (s *Server) loginFace(w http.ResponseWriter, r *http.Request) {
	tok, ok := bearer(r)
	if !ok {
		writeErr(w, http.StatusUnauthorized, "invalid_login_token", "start login again")
		return
	}
	att, err := s.st.TakeLoginAttempt(r.Context(), hashToken(tok))
	if err != nil {
		writeErr(w, http.StatusUnauthorized, "invalid_login_token", "start login again")
		return
	}
	f, err := readForm(w, r)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad_form", "send multipart JPEG frames")
		return
	}
	u, err := s.st.GetUser(r.Context(), att.UserID)
	if err != nil || u.Status != "active" {
		writeErr(w, http.StatusUnauthorized, "face_verification_failed", "face verification failed")
		return
	}
	out, err := s.face.Verify(r.Context(), u.FaceRef, att.FaceChallengeID, f.frames)
	if err != nil {
		s.fail(w, err)
		return
	}
		// loginFace: face fail hone wali branch
	if !out.OK {
		if countsAsAttack(out.Reason) {
			s.recordLoginFailure(r, u.ID)
		}
		s.faceReject(w, "verify", out.Reason)
		return
	tokens, err := s.issue(r.Context(), u, clientIP(r), r.UserAgent())
	if err != nil {
		s.fail(w, err)
		return
	}
	s.cancelRecoveryOnLogin(r, u) // the real owner is here: any pending face-reset request is void
	writeJSON(w, http.StatusOK, map[string]any{"user": s.userView(u), "tokens": tokens})
}

// ---------- tokens ----------

func (s *Server) issue(ctx context.Context, u User, ip, ua string) (map[string]any, error) {
	sid := token.NewUUID()
	rt, rh, err := token.NewRefresh(sid)
	if err != nil {
		return nil, err
	}
	rexp := time.Now().Add(s.cfg.RefreshTTL)
	if err := s.st.CreateAuthSession(ctx, sid, u.ID, rh, ip, ua, rexp); err != nil {
		return nil, err
	}
	at, aexp, err := s.tok.Mint(u.ID, sid, u.Number, time.Now())
	if err != nil {
		return nil, err
	}
	return map[string]any{"token_type": "Bearer", "access_token": at, "access_expires_at": aexp,
		"refresh_token": rt, "refresh_expires_at": rexp}, nil
}

func (s *Server) userView(u User) map[string]any {
	return map[string]any{
		"id": u.ID, "fyberflix_number": u.Number, "fyber_cable_name": u.CableName, "status": u.Status,
		"profile_url":        s.cfg.PublicBaseURL + "/" + u.CableName,
		"profile_url_number": s.cfg.PublicBaseURL + "/" + u.Number,
	}
}

func (s *Server) access(w http.ResponseWriter, r *http.Request) (token.Claims, bool) {
	t, ok := bearer(r)
	if ok {
		if c, err := s.tok.Verify(t, time.Now()); err == nil {
			return c, true
		}
	}
	writeErr(w, http.StatusUnauthorized, "invalid_token", "missing or invalid access token")
	return token.Claims{}, false
}

func (s *Server) jwks(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=300")
	_, _ = w.Write(s.tok.JWKS())
}

func (s *Server) refresh(w http.ResponseWriter, r *http.Request) {
	var in struct {
		RefreshToken string `json:"refresh_token"`
	}
	if !decode(w, r, &in) {
		return
	}
	sid, presented, ok := token.ParseRefresh(in.RefreshToken)
	if !ok {
		s.fail(w, ErrInvalidRefresh)
		return
	}
	next, nextHash, err := token.NewRefresh(sid)
	if err != nil {
		s.fail(w, err)
		return
	}
	rexp := time.Now().Add(s.cfg.RefreshTTL)
	userID, err := s.st.RotateRefresh(r.Context(), sid, presented, nextHash, rexp)
	if err != nil {
		s.fail(w, err)
		return
	}
	u, err := s.st.GetUser(r.Context(), userID)
	if err != nil || u.Status != "active" {
		s.fail(w, ErrInvalidRefresh)
		return
	}
	at, aexp, err := s.tok.Mint(u.ID, sid, u.Number, time.Now())
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"token_type": "Bearer", "access_token": at,
		"access_expires_at": aexp, "refresh_token": next, "refresh_expires_at": rexp})
}

// logout revokes ONE device session; it needs that session's refresh token.
func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	var in struct {
		RefreshToken string `json:"refresh_token"`
	}
	if !decode(w, r, &in) {
		return
	}
	if sid, h, ok := token.ParseRefresh(in.RefreshToken); ok {
		if err := s.st.RevokeSession(r.Context(), sid, h); err != nil {
			s.fail(w, err)
			return
		}
	}
	w.WriteHeader(http.StatusNoContent)
}

// logoutAll revokes every device. Existing access tokens stay valid until they expire (<= 10 min).
func (s *Server) logoutAll(w http.ResponseWriter, r *http.Request) {
	c, ok := s.access(w, r)
	if !ok {
		return
	}
	if err := s.st.RevokeAllSessions(r.Context(), c.Sub); err != nil {
		s.fail(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) me(w http.ResponseWriter, r *http.Request) {
	c, ok := s.access(w, r)
	if !ok {
		return
	}
	u, err := s.st.GetUser(r.Context(), c.Sub)
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"user": s.userView(u)})
}
