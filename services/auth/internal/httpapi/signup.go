package httpapi

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/fyberflix/fyberflix/services/auth/internal/identity"
)

func (s *Server) createSession(w http.ResponseWriter, r *http.Request) {
	if !s.limit(w, r, "signup:ip:"+clientIP(r), 20, time.Hour) {
		return
	}
	token, hash, err := randomToken()
	if err != nil {
		s.fail(w, err)
		return
	}
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
	if !identity.IsNumber(in.Number) {
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
		resp["reason"] = ErrNameTaken.Error()
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
	if ok, rules := s.nameAllowed(r.Context(), hash, display); !ok {
		s.log.Info("cable name rejected by risk", "rules", rules)
		writeErr(w, http.StatusUnprocessableEntity, "name_not_allowed",
			"this name looks like it could be used to impersonate or trick people, please choose another")
		return
	}
	if taken, err := s.st.CableNameTaken(r.Context(), key); err != nil {
		s.fail(w, err)
		return
	} else if taken {
		s.fail(w, ErrNameTaken)
		return
	}
	if err := s.st.SetCableName(r.Context(), hash, display); err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"fyber_cable_name": display, "state": "name_chosen",
		"profile_url": s.cfg.PublicBaseURL + "/" + display})
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
