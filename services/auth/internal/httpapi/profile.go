package httpapi

import (
	"net/http"
	"time"
)

// publicProfile resolves FyberFlix.zeaipc.in/{cable name} and /{FyberFlix number} to the same
// creator. Only active accounts exist publicly; suspended and deletion-pending accounts look
// exactly like missing ones. No email, no face data, no status.
func (s *Server) publicProfile(w http.ResponseWriter, r *http.Request) {
	if !s.limit(w, r, "profile:ip:"+clientIP(r), 300, 10*time.Minute) {
		return
	}
	ident, ok := parseIdent(r.PathValue("ident"))
	if !ok {
		writeErr(w, http.StatusNotFound, "not_found", "profile not found")
		return
	}
	u, err := s.st.FindUserByIdentifier(r.Context(), ident)
	if err != nil || u.Status != "active" {
		writeErr(w, http.StatusNotFound, "not_found", "profile not found")
		return
	}
	w.Header().Set("Cache-Control", "public, max-age=60")
	writeJSON(w, http.StatusOK, map[string]any{
		"id": u.ID, "fyber_cable_name": u.CableName, "fyberflix_number": u.Number,
		"profile_url":        s.cfg.PublicBaseURL + "/" + u.CableName,
		"profile_url_number": s.cfg.PublicBaseURL + "/" + u.Number,
		"member_since":       u.CreatedAt.UTC().Format("2006-01"),
	})
}
