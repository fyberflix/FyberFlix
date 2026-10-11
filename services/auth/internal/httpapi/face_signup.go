package httpapi

import (
	"net/http"
)

// consent records explicit biometric consent (DPDP Act). Face steps are blocked without it.
func (s *Server) consent(w http.ResponseWriter, r *http.Request) {
	hash, ok := s.session(w, r, "name_chosen")
	if !ok {
		return
	}
	var in struct {
		BiometricConsent bool   `json:"biometric_consent"`
		TermsVersion     string `json:"terms_version"`
	}
	if !decode(w, r, &in) {
		return
	}
	if !in.BiometricConsent || in.TermsVersion == "" || len(in.TermsVersion) > 32 {
		writeErr(w, http.StatusUnprocessableEntity, "consent_required",
			"explicit biometric consent and the terms version are required")
		return
	}
	if err := s.st.RecordConsent(r.Context(), hash, in.TermsVersion); err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"consented": true})
}

// faceChallenge: enroll challenge before the account exists, verify challenge after.
func (s *Server) faceChallenge(w http.ResponseWriter, r *http.Request) {
	hash, ok := s.session(w, r, "name_chosen", "account_created")
	if !ok {
		return
	}
	ss, err := s.st.GetSignup(r.Context(), hash)
	if err != nil {
		s.fail(w, err)
		return
	}
	purpose := "verify"
	if ss.State == "name_chosen" {
		if !ss.Consented {
			writeErr(w, http.StatusForbidden, "consent_required", "biometric consent is required first")
			return
		}
		purpose = "enroll"
	}
	ch, err := s.face.Challenge(r.Context(), ss.FaceRef, purpose)
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"challenge_id": ch.ID, "steps": ch.Steps, "expires_in": ch.ExpiresIn, "purpose": purpose})
}

// faceSubmit: multipart {challenge_id, frames[]}.
// name_chosen     -> enroll the first face (state face_checked)
// account_created -> verify the face again; success activates the account and logs the user in
func (s *Server) faceSubmit(w http.ResponseWriter, r *http.Request) {
	hash, ok := s.session(w, r, "name_chosen", "account_created")
	if !ok {
		return
	}
	ss, err := s.st.GetSignup(r.Context(), hash)
	if err != nil {
		s.fail(w, err)
		return
	}
	f, err := readForm(w, r)
	if err != nil || f.fields["challenge_id"] == "" {
		writeErr(w, http.StatusBadRequest, "bad_form", "send multipart: challenge_id + JPEG frames")
		return
	}
	cid := f.fields["challenge_id"]

	if ss.State == "name_chosen" {
		if !ss.Consented {
			writeErr(w, http.StatusForbidden, "consent_required", "biometric consent is required first")
			return
		}
		out, err := s.face.Enroll(r.Context(), ss.FaceRef, cid, f.frames)
		if err != nil {
			s.fail(w, err)
			return
		}
		if !out.OK {
			s.faceReject(w, "enroll", out.Reason)
			return
		}
		if err := s.st.MarkFaceChecked(r.Context(), hash); err != nil {
			s.fail(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"state": "face_checked", "next": "create_account"})
		return
	}

	out, err := s.face.Verify(r.Context(), ss.FaceRef, cid, f.frames)
	if err != nil {
		s.fail(w, err)
		return
	}
	if !out.OK {
		s.faceReject(w, "verify", out.Reason)
		return
	}
	u, err := s.st.ActivateAccount(r.Context(), hash)
	if err != nil {
		s.fail(w, err)
		return
	}
	tokens, err := s.issue(r.Context(), u, clientIP(r), r.UserAgent())
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"state": "completed", "user": s.userView(u), "tokens": tokens})
}

// createAccount: face is checked, so create the account (status pending until face re-verification).
func (s *Server) createAccount(w http.ResponseWriter, r *http.Request) {
	hash, ok := s.session(w, r, "face_checked")
	if !ok {
		return
	}
	u, err := s.st.CreateAccount(r.Context(), hash)
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{
		"state": "account_created", "next": "verify_face", "user": s.userView(u)})
}

// faceReject turns face-service reason codes into client-safe errors. After the
// first face check we are deliberately vague so attackers learn nothing about why they failed.
func (s *Server) faceReject(w http.ResponseWriter, purpose, reason string) {
	switch {
	case reason == "challenge_invalid":
		writeErr(w, http.StatusConflict, "challenge_invalid", "this face check expired, start a new one")
	case reason == "bad_frame_count" || reason == "poor_quality":
		writeErr(w, http.StatusUnprocessableEntity, "poor_quality", "face the camera in good light and hold still")
	case reason == "locked":
		writeErr(w, http.StatusTooManyRequests, "face_locked", "too many failed attempts, try again later")
	case reason == "already_enrolled":
		writeErr(w, http.StatusConflict, "already_enrolled", "a face is already registered for this signup")
	case reason == "liveness_failed" && purpose == "enroll":
		writeErr(w, http.StatusUnprocessableEntity, "liveness_failed", "follow the on-screen head movements")
	default:
		writeErr(w, http.StatusUnauthorized, "face_verification_failed", "face verification failed")
	}
}
