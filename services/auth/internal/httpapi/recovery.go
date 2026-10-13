package httpapi

import (
	"context"
	"crypto/hmac"
	"errors"
	"net/http"
	"strings"
	"time"
)

// Account recovery for people whose face no longer matches. Deliberately slow and noisy:
//
//	email OTP (verified email only) -> 7-day wait -> admin approval -> face re-enrolment
//
// The owner is emailed at every step and cancels a request just by logging in with their face.

var ErrRecoveryOpen = errors.New("a recovery request is already in progress")

type Recovery struct {
	ID, UserID, State string
	ReadyAt           time.Time
	ExpiresAt         time.Time
}

type PendingRecovery struct {
	UserID, Number, CableName string
	ReadyAt, CreatedAt        time.Time
}

type RecoveryStore interface {
	PutRecoveryOTP(ctx context.Context, userID string, codeHash []byte, exp time.Time) error
	// CheckRecoveryOTP counts the attempt, then calls match; ErrOTPInvalid / ErrOTPLocked on failure.
	CheckRecoveryOTP(ctx context.Context, userID string, maxAttempts int, match func(stored []byte) bool) error
	CreateRecovery(ctx context.Context, userID string, tokenHash []byte, readyAt, expiresAt time.Time) (Recovery, error) // ErrRecoveryOpen
	RecoveryByToken(ctx context.Context, tokenHash []byte) (Recovery, error)                                            // ErrNotFound
	OpenRecovery(ctx context.Context, userID string) (Recovery, error)                                                  // ErrNotFound
	ApproveRecovery(ctx context.Context, userID, approverID string) error                                               // waiting -> approved, else ErrWrongState
	CompleteRecovery(ctx context.Context, id string) error                                                              // approved -> completed, else ErrWrongState
	CancelOpenRecovery(ctx context.Context, userID string) (bool, error)
	ListWaitingRecoveries(ctx context.Context, limit int) ([]PendingRecovery, error)
}

// WithRecovery enables the recovery endpoints (needs WithAccount too).
func (s *Server) WithRecovery(rs RecoveryStore) *Server {
	s.rec = rs
	return s
}

func (s *Server) recoveryRoutes(m *http.ServeMux) {
	if s.rec == nil || s.acct == nil {
		return
	}
	m.HandleFunc("POST /v1/recovery/start", s.recoveryStart)
	m.HandleFunc("POST /v1/recovery/verify", s.recoveryVerify)
	m.HandleFunc("POST /v1/recovery/status", s.recoveryStatus)
	m.HandleFunc("POST /v1/recovery/face/start", s.recoveryFaceStart)
	m.HandleFunc("POST /v1/recovery/face", s.recoveryFace)
	m.HandleFunc("POST /v1/staff/users/{id}/recovery/approve", s.staffApproveRecovery)
	m.HandleFunc("GET /v1/staff/recovery/pending", s.staffPendingRecoveries)
}

func recoveryHash(s *Server, userID, code string) []byte {
	return otpHash(s.acfg.OTPPepper, userID, "recovery", code)
}

// notice emails the verified address of an account; failures are logged, never fatal.
func (s *Server) notice(ctx context.Context, userID, subject, body string) {
	email, verified, err := s.acct.EmailInfo(ctx, userID)
	if err != nil || !verified || email == "" {
		return
	}
	if err := s.mailer.SendNotice(ctx, email, subject, body); err != nil {
		s.log.Error("send notice failed", "subject", subject, "err", err)
	}
}

func openState(rc Recovery, now time.Time) string {
	if (rc.State == "waiting" || rc.State == "approved") && !now.Before(rc.ExpiresAt) {
		return "expired"
	}
	return rc.State
}

func (s *Server) ready(rc Recovery, now time.Time) bool {
	return openState(rc, now) == "approved" && !now.Before(rc.ReadyAt)
}

// ---------- 1. ask for a code ----------

func (s *Server) recoveryStart(w http.ResponseWriter, r *http.Request) {
	if !s.limit(w, r, "recovery:ip:"+clientIP(r), 5, time.Hour) {
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
	if !s.limit(w, r, "recovery:id:"+strings.ToLower(ident), 3, time.Hour) {
		return
	}
	// The answer is identical whether or not recovery is possible: no account enumeration.
	generic := func() {
		writeJSON(w, http.StatusAccepted, map[string]any{"sent": true,
			"message": "If this account can be recovered, a code was sent to its verified email."})
	}
	u, err := s.st.FindUserByIdentifier(r.Context(), ident)
	if err != nil || u.Status != "active" {
		generic()
		return
	}
	if _, verified, err := s.acct.EmailInfo(r.Context(), u.ID); err != nil || !verified {
		generic()
		return
	}
	code, err := newOTP()
	if err != nil {
		s.fail(w, err)
		return
	}
	if err := s.rec.PutRecoveryOTP(r.Context(), u.ID, recoveryHash(s, u.ID, code), time.Now().Add(s.acfg.OTPTTL)); err != nil {
		s.fail(w, err)
		return
	}
	email, _, _ := s.acct.EmailInfo(r.Context(), u.ID)
	if err := s.mailer.SendOTP(r.Context(), email, code, s.acfg.OTPTTL); err != nil {
		s.log.Error("send recovery otp failed", "err", err)
	}
	generic()
}

// ---------- 2. prove the email, open the request ----------

func (s *Server) recoveryVerify(w http.ResponseWriter, r *http.Request) {
	if !s.limit(w, r, "recoveryv:ip:"+clientIP(r), 10, time.Hour) {
		return
	}
	var in struct {
		Identifier string `json:"identifier"`
		Code       string `json:"code"`
	}
	if !decode(w, r, &in) {
		return
	}
	ident, ok := parseIdent(in.Identifier)
	if !ok || !otpRe.MatchString(in.Code) {
		s.failAcct(w, ErrOTPInvalid)
		return
	}
	if !s.limit(w, r, "recoveryv:id:"+strings.ToLower(ident), 10, time.Hour) {
		return
	}
	u, err := s.st.FindUserByIdentifier(r.Context(), ident)
	if err != nil || u.Status != "active" {
		s.failAcct(w, ErrOTPInvalid)
		return
	}
	err = s.rec.CheckRecoveryOTP(r.Context(), u.ID, s.acfg.OTPMaxAttempts, func(stored []byte) bool {
		return hmac.Equal(stored, recoveryHash(s, u.ID, in.Code))
	})
	if err != nil {
		s.failAcct(w, err)
		return
	}
	tok, hash, err := randomToken()
	if err != nil {
		s.fail(w, err)
		return
	}
	now := time.Now()
	rc, err := s.rec.CreateRecovery(r.Context(), u.ID, hash, now.Add(s.acfg.RecoveryWait), now.Add(s.acfg.RecoveryTTL))
	if errors.Is(err, ErrRecoveryOpen) {
		writeErr(w, http.StatusConflict, "recovery_open", "a recovery request is already in progress for this account")
		return
	}
	if err != nil {
		s.fail(w, err)
		return
	}
	s.audit(r, "user", u.ID, "recovery.requested", u.ID, map[string]any{"ready_at": rc.ReadyAt})
	s.notice(r.Context(), u.ID, "FyberFlix account recovery requested",
		"Someone asked to reset the face on your FyberFlix account.\n\n"+
			"Nothing changes before "+rc.ReadyAt.UTC().Format("2 Jan 2006 15:04 UTC")+", and it also needs approval from our team.\n"+
			"If this was NOT you, just log in with your face: that cancels the request immediately.")
	writeJSON(w, http.StatusCreated, map[string]any{"recovery_token": tok, "state": "waiting",
		"ready_at": rc.ReadyAt, "expires_at": rc.ExpiresAt})
}

// ---------- 3. progress ----------

func (s *Server) recoveryByBody(w http.ResponseWriter, r *http.Request) (Recovery, string, bool) {
	var in struct {
		Token string `json:"recovery_token"`
	}
	if !decode(w, r, &in) {
		return Recovery{}, "", false
	}
	if len(in.Token) < 20 || len(in.Token) > 100 {
		writeErr(w, http.StatusUnauthorized, "invalid_recovery_token", "unknown recovery request")
		return Recovery{}, "", false
	}
	rc, err := s.rec.RecoveryByToken(r.Context(), hashToken(in.Token))
	if err != nil {
		writeErr(w, http.StatusUnauthorized, "invalid_recovery_token", "unknown recovery request")
		return Recovery{}, "", false
	}
	return rc, in.Token, true
}

func (s *Server) recoveryStatus(w http.ResponseWriter, r *http.Request) {
	if !s.limit(w, r, "recoverys:ip:"+clientIP(r), 60, time.Hour) {
		return
	}
	rc, _, ok := s.recoveryByBody(w, r)
	if !ok {
		return
	}
	now := time.Now()
	writeJSON(w, http.StatusOK, map[string]any{"state": openState(rc, now), "ready_at": rc.ReadyAt,
		"can_start": s.ready(rc, now)})
}

// ---------- 4. new face ----------

func (s *Server) recoveryFaceStart(w http.ResponseWriter, r *http.Request) {
	if !s.limit(w, r, "recoveryf:ip:"+clientIP(r), 10, time.Hour) {
		return
	}
	rc, _, ok := s.recoveryByBody(w, r)
	if !ok {
		return
	}
	if !s.ready(rc, time.Now()) {
		writeErr(w, http.StatusConflict, "not_ready", "this recovery request is not approved yet or still in its waiting period")
		return
	}
	u, err := s.st.GetUser(r.Context(), rc.UserID)
	if err != nil || u.Status != "active" {
		writeErr(w, http.StatusConflict, "wrong_state", "this action is no longer possible")
		return
	}
	// The old template is erased first; the request stays approved, so a failed attempt can be repeated.
	if err := s.face.Delete(r.Context(), u.FaceRef); err != nil {
		s.fail(w, err)
		return
	}
	ch, err := s.face.Challenge(r.Context(), u.FaceRef, "enroll")
	if err != nil {
		s.fail(w, err)
		return
	}
	tok, hash, err := randomToken()
	if err != nil {
		s.fail(w, err)
		return
	}
	if err := s.acct.CreateFaceAttempt(r.Context(), hash, u.ID, ch.ID, "recover", time.Now().Add(5*time.Minute)); err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"attempt_token": tok, "purpose": "enroll",
		"steps": ch.Steps, "expires_in": ch.ExpiresIn})
}

// recoveryFace: Authorization: Bearer <attempt_token>, multipart frames[]. One try per token.
func (s *Server) recoveryFace(w http.ResponseWriter, r *http.Request) {
	tok, ok := bearer(r)
	if !ok {
		writeErr(w, http.StatusUnauthorized, "invalid_attempt_token", "start again")
		return
	}
	att, err := s.acct.TakeFaceAttempt(r.Context(), hashToken(tok))
	if err != nil || att.Purpose != "recover" {
		writeErr(w, http.StatusUnauthorized, "invalid_attempt_token", "start again")
		return
	}
	f, err := readForm(w, r)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad_form", "send multipart JPEG frames")
		return
	}
	u, err := s.st.GetUser(r.Context(), att.UserID)
	rc, rerr := s.rec.OpenRecovery(r.Context(), att.UserID)
	if err != nil || u.Status != "active" || rerr != nil || !s.ready(rc, time.Now()) {
		writeErr(w, http.StatusConflict, "wrong_state", "this action is no longer possible")
		return
	}
	out, err := s.face.Enroll(r.Context(), u.FaceRef, att.FaceChallengeID, f.frames)
	if err != nil {
		s.fail(w, err)
		return
	}
	if !out.OK {
		s.faceReject(w, "enroll", out.Reason)
		return
	}
	if err := s.rec.CompleteRecovery(r.Context(), rc.ID); err != nil {
		s.failAcct(w, err)
		return
	}
	// Every old device is signed out; the owner logs in again with the new face.
	if err := s.st.RevokeAllSessions(r.Context(), u.ID); err != nil {
		s.log.Error("revoke sessions after recovery failed", "err", err)
	}
	s.audit(r, "user", u.ID, "recovery.completed", u.ID, nil)
	s.notice(r.Context(), u.ID, "FyberFlix face reset completed",
		"The face on your FyberFlix account was reset and all devices were signed out.\n"+
			"If this was not you, contact support immediately with your FyberFlix number.")
	writeJSON(w, http.StatusOK, map[string]any{"recovered": true, "next": "log in with your new face"})
}

// ---------- the owner shows up: cancel any open request ----------

func (s *Server) cancelRecoveryOnLogin(r *http.Request, u User) {
	if s.rec == nil || s.acct == nil {
		return
	}
	cancelled, err := s.rec.CancelOpenRecovery(r.Context(), u.ID)
	if err != nil {
		s.log.Error("cancel recovery on login failed", "err", err)
		return
	}
	if cancelled {
		s.audit(r, "user", u.ID, "recovery.cancelled_by_login", u.ID, nil)
		s.notice(r.Context(), u.ID, "FyberFlix recovery request cancelled",
			"You logged in with your face, so the pending face-reset request on your account was cancelled.")
	}
}

// ---------- staff ----------

func (s *Server) staffApproveRecovery(w http.ResponseWriter, r *http.Request) {
	s.staffAction(w, r, []string{"admin"}, "staff.recovery_approve", func(actor, t User) error {
		if err := s.rec.ApproveRecovery(r.Context(), t.ID, actor.ID); err != nil {
			return err
		}
		s.notice(r.Context(), t.ID, "FyberFlix face reset approved",
			"Our team approved the face-reset request on your account. It becomes usable after its waiting period.\n"+
				"If this was NOT you, log in with your face now: that cancels it.")
		return nil
	})
}

func (s *Server) staffPendingRecoveries(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.staffAuth(w, r, "support", "admin")
	if !ok {
		return
	}
	reason := r.URL.Query().Get("reason")
	if !validReason(reason) {
		writeErr(w, http.StatusBadRequest, "reason_required", "a written reason (8-200 chars, e.g. ticket id) is required")
		return
	}
	if err := s.auditStrict(r, "staff", actor.ID, "staff.recovery_list", "", map[string]any{"reason": reason}); err != nil {
		s.fail(w, err)
		return
	}
	list, err := s.rec.ListWaitingRecoveries(r.Context(), 100)
	if err != nil {
		s.fail(w, err)
		return
	}
	out := make([]map[string]any, 0, len(list))
	for _, x := range list {
		out = append(out, map[string]any{"user_id": x.UserID, "fyberflix_number": x.Number,
			"fyber_cable_name": x.CableName, "ready_at": x.ReadyAt, "requested_at": x.CreatedAt})
	}
	writeJSON(w, http.StatusOK, map[string]any{"pending": out})
}
