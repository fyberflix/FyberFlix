package httpapi

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/mail"
	"regexp"
	"strings"
	"time"

	"github.com/fyberflix/fyberflix/services/auth/internal/identity"
	"github.com/fyberflix/fyberflix/services/auth/internal/token"
)

var (
	ErrOTPInvalid     = errors.New("invalid or expired code")
	ErrOTPLocked      = errors.New("too many wrong codes, request a new one")
	ErrEmailTaken     = errors.New("this email is already verified on another account")
	ErrRenameCooldown = errors.New("you can change your Fyber Cable name once every 30 days")
	ErrForbidden      = errors.New("forbidden")
)

type Mailer interface {
	SendOTP(ctx context.Context, to, code string, ttl time.Duration) error
// Mailer interface mein
	SendNotice(ctx context.Context, to, subject, body string) error
}

type SessionInfo struct {
	ID, UserAgent, IP     string
	CreatedAt, LastUsedAt time.Time
}

type AuditEntry struct {
	At                                     time.Time
	ActorType, ActorID, Action, TargetUser string
	IP                                     string
	Detail                                 map[string]any
}

type FaceAttempt struct{ UserID, FaceChallengeID, Purpose string }

// AccountStore: email OTP, profile management, deletion, staff and audit.
type AccountStore interface {
	// email
	PutEmailOTP(ctx context.Context, userID, email string, codeHash []byte, expires time.Time) error
	// CheckEmailOTP counts the attempt, calls match, and on success marks the email verified.
	CheckEmailOTP(ctx context.Context, userID string, maxAttempts int, match func(email string, storedHash []byte) bool) (email string, err error)
	EmailInfo(ctx context.Context, userID string) (email string, verified bool, err error)
	RemoveEmail(ctx context.Context, userID string) error
	// profile
	RenameCable(ctx context.Context, userID, display string, cooldown time.Duration) error
	ListSessions(ctx context.Context, userID string) ([]SessionInfo, error)
	RevokeSessionByID(ctx context.Context, userID, sessionID string) (bool, error)
	// deletion / restore (face step-up)
	CreateFaceAttempt(ctx context.Context, tokenHash []byte, userID, challengeID, purpose string, exp time.Time) error
	TakeFaceAttempt(ctx context.Context, tokenHash []byte) (FaceAttempt, error)
	ScheduleDeletion(ctx context.Context, userID string, at time.Time) error // active -> deletion_pending, revokes sessions
	RestoreAccount(ctx context.Context, userID string) error                 // deletion_pending -> active
	// staff + audit
	Roles(ctx context.Context, userID string) ([]string, error)
	SetStatus(ctx context.Context, userID, from, to string) error
	Audit(ctx context.Context, e AuditEntry) error
	ListAudit(ctx context.Context, userID string, limit int) ([]AuditEntry, error)
}

type AccountConfig struct {
	OTPPepper      []byte
	OTPTTL         time.Duration
	OTPMaxAttempts int
	DeleteGrace    time.Duration
	RenameCooldown time.Duration
// AccountConfig mein RenameCooldown ke baad
	RecoveryWait   time.Duration // delay before an approved recovery becomes usable (default 7 days)
	RecoveryTTL    time.Duration // how long an open recovery request lives (default 30 days)
}

// WithAccount enables the account-management and staff endpoints.
func (s *Server) WithAccount(a AccountStore, m Mailer, c AccountConfig) *Server {
	if c.OTPTTL == 0 {
		c.OTPTTL = 10 * time.Minute
	}
	if c.OTPMaxAttempts == 0 {
		c.OTPMaxAttempts = 5
	}
	if c.DeleteGrace == 0 {
		c.DeleteGrace = 30 * 24 * time.Hour
	}
	if c.RenameCooldown == 0 {
		c.RenameCooldown = 30 * 24 * time.Hour
	}
	if c.RecoveryWait == 0 {
		c.RecoveryWait = 7 * 24 * time.Hour
	}
	if c.RecoveryTTL == 0 {
		c.RecoveryTTL = 30 * 24 * time.Hour
	}
	s.acct, s.mailer, s.acfg = a, m, c
	return s
}

func (s *Server) accountRoutes(m *http.ServeMux) {
	if s.acct == nil {
		return
	}
	m.HandleFunc("POST /v1/me/email", s.emailStart)
	m.HandleFunc("POST /v1/me/email/verify", s.emailVerify)
	m.HandleFunc("DELETE /v1/me/email", s.emailRemove)
	m.HandleFunc("POST /v1/me/cable-name", s.renameCable)
	m.HandleFunc("GET /v1/me/sessions", s.listSessions)
	m.HandleFunc("DELETE /v1/me/sessions/{id}", s.revokeMySession)
	m.HandleFunc("POST /v1/me/delete/start", s.deleteStart)
	m.HandleFunc("POST /v1/restore/start", s.restoreStart)
	m.HandleFunc("POST /v1/account/face", s.accountFace)

	m.HandleFunc("GET /v1/staff/users/lookup", s.staffLookup)
	m.HandleFunc("GET /v1/staff/users/{id}/sessions", s.staffSessions)
	m.HandleFunc("POST /v1/staff/users/{id}/revoke-sessions", s.staffRevoke)
	m.HandleFunc("POST /v1/staff/users/{id}/suspend", s.staffSuspend)
	m.HandleFunc("POST /v1/staff/users/{id}/unsuspend", s.staffUnsuspend)
	m.HandleFunc("GET /v1/staff/users/{id}/audit", s.staffAudit)
}

// ---------- helpers ----------

func (s *Server) failAcct(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, ErrOTPInvalid):
		writeErr(w, http.StatusUnprocessableEntity, "otp_invalid", err.Error())
	case errors.Is(err, ErrOTPLocked):
		writeErr(w, http.StatusTooManyRequests, "otp_locked", err.Error())
	case errors.Is(err, ErrEmailTaken):
		writeErr(w, http.StatusConflict, "email_taken", err.Error())
	case errors.Is(err, ErrRenameCooldown):
		writeErr(w, http.StatusTooManyRequests, "rename_cooldown", err.Error())
	case errors.Is(err, ErrForbidden):
		writeErr(w, http.StatusForbidden, "forbidden", "not allowed")
	default:
		s.fail(w, err)
	}
}

// activeUser = valid access token AND the account is currently active (not suspended/deleted).
func (s *Server) activeUser(w http.ResponseWriter, r *http.Request) (User, token.Claims, bool) {
	c, ok := s.access(w, r)
	if !ok {
		return User{}, c, false
	}
	u, err := s.st.GetUser(r.Context(), c.Sub)
	if err != nil || u.Status != "active" {
		writeErr(w, http.StatusForbidden, "account_unavailable", "this account cannot do that right now")
		return User{}, c, false
	}
	return u, c, true
}

func (s *Server) auditStrict(r *http.Request, actorType, actorID, action, target string, detail map[string]any) error {
	return s.acct.Audit(r.Context(), AuditEntry{ActorType: actorType, ActorID: actorID, Action: action,
		TargetUser: target, IP: clientIP(r), Detail: detail})
}

// audit is best-effort (own-account events); staff actions use auditStrict.
func (s *Server) audit(r *http.Request, actorType, actorID, action, target string, detail map[string]any) {
	if err := s.auditStrict(r, actorType, actorID, action, target, detail); err != nil {
		s.log.Error("audit write failed", "action", action, "err", err)
	}
}

func parseEmail(raw string) (string, bool) {
	e := strings.TrimSpace(raw)
	if len(e) < 6 || len(e) > 254 || strings.ContainsAny(e, "\r\n\t ,;<>\"") {
		return "", false
	}
	a, err := mail.ParseAddress(e)
	if err != nil || a.Address != e {
		return "", false
	}
	at := strings.LastIndexByte(e, '@')
	if at < 1 || !strings.Contains(e[at+1:], ".") {
		return "", false
	}
	return strings.ToLower(e), true
}

func maskEmail(e string) string {
	at := strings.LastIndexByte(e, '@')
	if at < 1 {
		return ""
	}
	return e[:1] + "***" + e[at:]
}

func newOTP() (string, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(1_000_000))
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%06d", n.Int64()), nil
}

func otpHash(pepper []byte, userID, email, code string) []byte {
	m := hmac.New(sha256.New, pepper)
	m.Write([]byte(userID + "|" + email + "|" + code))
	return m.Sum(nil)
}

var otpRe = regexp.MustCompile(`^[0-9]{6}$`)

func parseIdent(raw string) (string, bool) {
	id := strings.TrimPrefix(strings.TrimSpace(raw), "@")
	return id, identity.IsNumber(id) || identRe.MatchString(id)
}

// ---------- email (optional) ----------

func (s *Server) emailStart(w http.ResponseWriter, r *http.Request) {
	u, _, ok := s.activeUser(w, r)
	if !ok {
		return
	}
	if !s.limit(w, r, "email:user:"+u.ID, 3, time.Hour) || !s.limit(w, r, "email:ip:"+clientIP(r), 10, time.Hour) {
		return
	}
	var in struct {
		Email string `json:"email"`
	}
	if !decode(w, r, &in) {
		return
	}
	email, ok := parseEmail(in.Email)
	if !ok {
		writeErr(w, http.StatusUnprocessableEntity, "invalid_email", "enter a valid email address")
		return
	}
	code, err := newOTP()
	if err != nil {
		s.fail(w, err)
		return
	}
	exp := time.Now().Add(s.acfg.OTPTTL)
	if err := s.acct.PutEmailOTP(r.Context(), u.ID, email, otpHash(s.acfg.OTPPepper, u.ID, email, code), exp); err != nil {
		s.fail(w, err)
		return
	}
	if err := s.mailer.SendOTP(r.Context(), email, code, s.acfg.OTPTTL); err != nil {
		s.log.Error("send otp failed", "err", err)
		writeErr(w, http.StatusBadGateway, "mail_unavailable", "could not send the email, try again later")
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]any{"sent": true, "expires_in": int(s.acfg.OTPTTL.Seconds())})
}

func (s *Server) emailVerify(w http.ResponseWriter, r *http.Request) {
	u, _, ok := s.activeUser(w, r)
	if !ok {
		return
	}
	if !s.limit(w, r, "otp:user:"+u.ID, 10, time.Hour) {
		return
	}
	var in struct {
		Code string `json:"code"`
	}
	if !decode(w, r, &in) {
		return
	}
	if !otpRe.MatchString(in.Code) {
		s.failAcct(w, ErrOTPInvalid)
		return
	}
	email, err := s.acct.CheckEmailOTP(r.Context(), u.ID, s.acfg.OTPMaxAttempts,
		func(email string, stored []byte) bool {
			return hmac.Equal(stored, otpHash(s.acfg.OTPPepper, u.ID, email, in.Code))
		})
	if err != nil {
		s.failAcct(w, err)
		return
	}
	s.audit(r, "user", u.ID, "email.verified", u.ID, map[string]any{"email": maskEmail(email)})
	writeJSON(w, http.StatusOK, map[string]any{"email_verified": true, "email": maskEmail(email)})
}

func (s *Server) emailRemove(w http.ResponseWriter, r *http.Request) {
	u, _, ok := s.activeUser(w, r)
	if !ok {
		return
	}
	if err := s.acct.RemoveEmail(r.Context(), u.ID); err != nil {
		s.fail(w, err)
		return
	}
	s.audit(r, "user", u.ID, "email.removed", u.ID, nil)
	w.WriteHeader(http.StatusNoContent)
}

// ---------- manage ----------

func (s *Server) renameCable(w http.ResponseWriter, r *http.Request) {
	u, _, ok := s.activeUser(w, r)
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
	if strings.EqualFold(display, u.CableName) && display == u.CableName {
		writeErr(w, http.StatusUnprocessableEntity, "invalid_name", "that is already your name")
		return
	}
	_ = key
	if ok, rules := s.nameAllowed(r.Context(), []byte(u.ID), display); !ok {
		s.log.Info("cable name rejected by risk", "rules", rules)
		writeErr(w, http.StatusUnprocessableEntity, "name_not_allowed",
			"this name looks like it could be used to impersonate or trick people, please choose another")
		return
	}
	if err := s.acct.RenameCable(r.Context(), u.ID, display, s.acfg.RenameCooldown); err != nil {
		s.failAcct(w, err)
		return
	}
	s.audit(r, "user", u.ID, "cable_name.changed", u.ID, map[string]any{"from": u.CableName, "to": display})
	u.CableName = display
	writeJSON(w, http.StatusOK, map[string]any{"user": s.userView(u)})
}

func (s *Server) listSessions(w http.ResponseWriter, r *http.Request) {
	u, c, ok := s.activeUser(w, r)
	if !ok {
		return
	}
	list, err := s.acct.ListSessions(r.Context(), u.ID)
	if err != nil {
		s.fail(w, err)
		return
	}
	out := make([]map[string]any, 0, len(list))
	for _, x := range list {
		out = append(out, map[string]any{"id": x.ID, "user_agent": x.UserAgent, "ip": x.IP,
			"created_at": x.CreatedAt, "last_used_at": x.LastUsedAt, "current": x.ID == c.SID})
	}
	writeJSON(w, http.StatusOK, map[string]any{"sessions": out})
}

func (s *Server) revokeMySession(w http.ResponseWriter, r *http.Request) {
	u, _, ok := s.activeUser(w, r)
	if !ok {
		return
	}
	id := r.PathValue("id")
	if !token.IsUUID(id) {
		writeErr(w, http.StatusBadRequest, "invalid_id", "invalid session id")
		return
	}
	found, err := s.acct.RevokeSessionByID(r.Context(), u.ID, id)
	if err != nil {
		s.fail(w, err)
		return
	}
	if !found {
		writeErr(w, http.StatusNotFound, "not_found", "session not found")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ---------- delete / restore (both need a fresh face check) ----------

func (s *Server) deleteStart(w http.ResponseWriter, r *http.Request) {
	u, _, ok := s.activeUser(w, r)
	if !ok {
		return
	}
	if !s.limit(w, r, "delete:user:"+u.ID, 5, time.Hour) {
		return
	}
	var in struct {
		Confirm string `json:"confirm"`
	}
	if !decode(w, r, &in) {
		return
	}
	if in.Confirm != "DELETE" {
		writeErr(w, http.StatusUnprocessableEntity, "confirm_required", `send {"confirm":"DELETE"} to continue`)
		return
	}
	s.startFaceAttempt(w, r, u, "delete")
}

func (s *Server) restoreStart(w http.ResponseWriter, r *http.Request) {
	if !s.limit(w, r, "restore:ip:"+clientIP(r), 10, time.Hour) {
		return
	}
	var in struct {
		Identifier string `json:"identifier"`
	}
	if !decode(w, r, &in) {
		return
	}
	ident, ok := parseIdent(in.Identifier)
	if !ok {
		writeErr(w, http.StatusBadRequest, "invalid_identifier", "enter your Fyber Cable name or FyberFlix number")
		return
	}
	u, err := s.st.FindUserByIdentifier(r.Context(), ident)
	if err != nil {
		s.fail(w, err)
		return
	}
	if u.Status != "deletion_pending" {
		writeErr(w, http.StatusForbidden, "account_unavailable", "this account is not waiting for deletion")
		return
	}
	s.startFaceAttempt(w, r, u, "restore")
}

func (s *Server) startFaceAttempt(w http.ResponseWriter, r *http.Request, u User, purpose string) {
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
	if err := s.acct.CreateFaceAttempt(r.Context(), hash, u.ID, ch.ID, purpose, time.Now().Add(3*time.Minute)); err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"attempt_token": tok, "purpose": purpose, "steps": ch.Steps, "expires_in": ch.ExpiresIn})
}

// accountFace: Authorization: Bearer <attempt_token>, multipart frames[]. One try per token.
func (s *Server) accountFace(w http.ResponseWriter, r *http.Request) {
	tok, ok := bearer(r)
	if !ok {
		writeErr(w, http.StatusUnauthorized, "invalid_attempt_token", "start again")
		return
	}
	att, err := s.acct.TakeFaceAttempt(r.Context(), hashToken(tok))
	if err != nil {
		writeErr(w, http.StatusUnauthorized, "invalid_attempt_token", "start again")
		return
	}
	f, err := readForm(w, r)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad_form", "send multipart JPEG frames")
		return
	}
	u, err := s.st.GetUser(r.Context(), att.UserID)
	wantStatus := map[string]string{"delete": "active", "restore": "deletion_pending"}[att.Purpose]
	if err != nil || wantStatus == "" || u.Status != wantStatus {
		writeErr(w, http.StatusConflict, "wrong_state", "this action is no longer possible")
		return
	}
	out, err := s.face.Verify(r.Context(), u.FaceRef, att.FaceChallengeID, f.frames)
	if err != nil {
		s.fail(w, err)
		return
	}
	if !out.OK {
		s.faceReject(w, "verify", out.Reason)
		return
	}
	switch att.Purpose {
	case "delete":
		at := time.Now().Add(s.acfg.DeleteGrace)
		if err := s.acct.ScheduleDeletion(r.Context(), u.ID, at); err != nil {
			s.failAcct(w, err)
			return
		}
		s.audit(r, "user", u.ID, "account.deletion_requested", u.ID, map[string]any{"scheduled_at": at})
		writeJSON(w, http.StatusOK, map[string]any{"status": "deletion_pending", "deletion_scheduled_at": at,
			"message": "Your account will be permanently deleted at that time. Log in with restore before then to cancel."})
	case "restore":
		if err := s.acct.RestoreAccount(r.Context(), u.ID); err != nil {
			s.failAcct(w, err)
			return
		}
		s.audit(r, "user", u.ID, "account.restored", u.ID, nil)
		u.Status = "active"
		tokens, err := s.issue(r.Context(), u, clientIP(r), r.UserAgent())
		if err != nil {
			s.fail(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"user": s.userView(u), "tokens": tokens})
	}
}
