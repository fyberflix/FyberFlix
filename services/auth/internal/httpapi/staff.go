package httpapi

import (
	"net/http"
	"strings"
	"time"

	"github.com/zeaipc/fyberflix/services/auth/internal/token"
)

// Staff tooling: look up a user by FyberFlix number / Fyber Cable name and act on their
// ACCOUNT STATE. There is deliberately no impersonation ("login as user") and staff can
// never see face data. Every access needs a written reason and is audit-logged first.

func validReason(r string) bool {
	r = strings.TrimSpace(r)
	if len(r) < 8 || len(r) > 200 {
		return false
	}
	for _, c := range r {
		if c < 0x20 {
			return false
		}
	}
	return true
}

// staffAuth checks the access token, the account state AND the role in the database
// (not in the token), so revoking a role takes effect immediately.
func (s *Server) staffAuth(w http.ResponseWriter, r *http.Request, allowed ...string) (User, bool) {
	u, _, ok := s.activeUser(w, r)
	if !ok {
		return User{}, false
	}
	roles, err := s.acct.Roles(r.Context(), u.ID)
	if err != nil {
		s.fail(w, err)
		return User{}, false
	}
	for _, have := range roles {
		for _, want := range allowed {
			if have == want {
				if !s.limit(w, r, "staff:"+u.ID, 120, time.Hour) {
					return User{}, false
				}
				return u, true
			}
		}
	}
	writeErr(w, http.StatusForbidden, "forbidden", "staff access required")
	return User{}, false
}

// target parses {id}, loads the user and verifies the written reason.
func (s *Server) staffTarget(w http.ResponseWriter, r *http.Request, reason string) (User, bool) {
	id := r.PathValue("id")
	if !token.IsUUID(id) {
		writeErr(w, http.StatusBadRequest, "invalid_id", "invalid user id")
		return User{}, false
	}
	if !validReason(reason) {
		writeErr(w, http.StatusBadRequest, "reason_required", "a written reason (8-200 chars, e.g. ticket id) is required")
		return User{}, false
	}
	t, err := s.st.GetUser(r.Context(), id)
	if err != nil {
		s.fail(w, err)
		return User{}, false
	}
	return t, true
}

func (s *Server) staffLookup(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.staffAuth(w, r, "support", "admin")
	if !ok {
		return
	}
	reason := r.URL.Query().Get("reason")
	ident, okq := parseIdent(r.URL.Query().Get("q"))
	if !okq {
		writeErr(w, http.StatusBadRequest, "invalid_identifier", "q must be a FyberFlix number or Fyber Cable name")
		return
	}
	if !validReason(reason) {
		writeErr(w, http.StatusBadRequest, "reason_required", "a written reason (8-200 chars, e.g. ticket id) is required")
		return
	}
	t, err := s.st.FindUserByIdentifier(r.Context(), ident)
	if err != nil {
		s.audit(r, "staff", actor.ID, "staff.lookup_miss", "", map[string]any{"q": ident, "reason": reason})
		s.fail(w, err)
		return
	}
	if err := s.auditStrict(r, "staff", actor.ID, "staff.lookup", t.ID, map[string]any{"reason": reason}); err != nil {
		s.fail(w, err) // no audit record -> no data
		return
	}
	email, verified, _ := s.acct.EmailInfo(r.Context(), t.ID)
	sessions, _ := s.acct.ListSessions(r.Context(), t.ID)
	writeJSON(w, http.StatusOK, map[string]any{
		"id": t.ID, "fyberflix_number": t.Number, "fyber_cable_name": t.CableName, "status": t.Status,
		"created_at": t.CreatedAt, "email_verified": verified, "email_masked": maskEmail(email),
		"active_sessions": len(sessions)})
}

func (s *Server) staffSessions(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.staffAuth(w, r, "support", "admin")
	if !ok {
		return
	}
	reason := r.URL.Query().Get("reason")
	t, ok := s.staffTarget(w, r, reason)
	if !ok {
		return
	}
	if err := s.auditStrict(r, "staff", actor.ID, "staff.sessions_view", t.ID, map[string]any{"reason": reason}); err != nil {
		s.fail(w, err)
		return
	}
	list, err := s.acct.ListSessions(r.Context(), t.ID)
	if err != nil {
		s.fail(w, err)
		return
	}
	out := make([]map[string]any, 0, len(list))
	for _, x := range list {
		out = append(out, map[string]any{"id": x.ID, "user_agent": x.UserAgent, "ip": x.IP,
			"created_at": x.CreatedAt, "last_used_at": x.LastUsedAt})
	}
	writeJSON(w, http.StatusOK, map[string]any{"sessions": out})
}

func (s *Server) staffAction(w http.ResponseWriter, r *http.Request, roles []string, action string, do func(actor, target User) error) {
	actor, ok := s.staffAuth(w, r, roles...)
	if !ok {
		return
	}
	var in struct {
		Reason string `json:"reason"`
	}
	if !decode(w, r, &in) {
		return
	}
	t, ok := s.staffTarget(w, r, in.Reason)
	if !ok {
		return
	}
	if t.ID == actor.ID {
		s.failAcct(w, ErrForbidden) // staff cannot act on their own account
		return
	}
	if err := s.auditStrict(r, "staff", actor.ID, action, t.ID, map[string]any{"reason": in.Reason}); err != nil {
		s.fail(w, err) // audit first: no record -> no action
		return
	}
	if err := do(actor, t); err != nil {
		s.failAcct(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) staffRevoke(w http.ResponseWriter, r *http.Request) {
	s.staffAction(w, r, []string{"support", "admin"}, "staff.revoke_sessions", func(_, t User) error {
		return s.st.RevokeAllSessions(r.Context(), t.ID)
	})
}

func (s *Server) staffSuspend(w http.ResponseWriter, r *http.Request) {
	s.staffAction(w, r, []string{"admin"}, "staff.suspend", func(_, t User) error {
		if err := s.acct.SetStatus(r.Context(), t.ID, "active", "suspended"); err != nil {
			return err
		}
		return s.st.RevokeAllSessions(r.Context(), t.ID)
	})
}

func (s *Server) staffUnsuspend(w http.ResponseWriter, r *http.Request) {
	s.staffAction(w, r, []string{"admin"}, "staff.unsuspend", func(_, t User) error {
		return s.acct.SetStatus(r.Context(), t.ID, "suspended", "active")
	})
}

func (s *Server) staffAudit(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.staffAuth(w, r, "admin")
	if !ok {
		return
	}
	reason := r.URL.Query().Get("reason")
	t, ok := s.staffTarget(w, r, reason)
	if !ok {
		return
	}
	if err := s.auditStrict(r, "staff", actor.ID, "staff.audit_view", t.ID, map[string]any{"reason": reason}); err != nil {
		s.fail(w, err)
		return
	}
	list, err := s.acct.ListAudit(r.Context(), t.ID, 100)
	if err != nil {
		s.fail(w, err)
		return
	}
	out := make([]map[string]any, 0, len(list))
	for _, e := range list {
		out = append(out, map[string]any{"at": e.At, "actor_type": e.ActorType, "actor_id": e.ActorID,
			"action": e.Action, "ip": e.IP, "detail": e.Detail})
	}
	writeJSON(w, http.StatusOK, map[string]any{"entries": out})
}
