package httpapi

import (
	"context"
	"encoding/hex"
	"net/http"
	"strconv"
	"time"

	"github.com/zeaipc/fyberflix/services/auth/internal/riskclient"
)

// Risk is zikriyon-prism behind risk-service. It is advisory: if it is down, auth keeps working
// (face verification + the database rate limits still protect the account).
type Risk interface {
	Evaluate(ctx context.Context, spec string, event map[string]any, subject string) (riskclient.Verdict, error)
}

// Blocklist holds temporary blocks created by risk verdicts, keyed like "ip:1.2.3.4" / "user:<id>".
type Blocklist interface {
	Block(ctx context.Context, key string, until time.Time) error
	Blocked(ctx context.Context, key string) (bool, error)
}

const loginBlockFor = 15 * time.Minute

// WithRisk enables risk checks on signup names and failed-login blocking.
func (s *Server) WithRisk(r Risk, b Blocklist) *Server {
	s.risk, s.blocks = r, b
	return s
}

func (s *Server) riskOn() bool { return s.risk != nil && s.blocks != nil }

// nameAllowed asks Prism about a Fyber Cable name. Only a clean, non-degraded verdict can reject it.
func (s *Server) nameAllowed(ctx context.Context, sessionHash []byte, display string) (bool, []string) {
	if !s.riskOn() {
		return true, nil
	}
	subject := "signup:" + hex.EncodeToString(sessionHash)[:16]
	v, err := s.risk.Evaluate(ctx, "auth_risk", map[string]any{"signup": map[string]any{"cable_name": display}}, subject)
	if err != nil {
		s.log.Warn("risk unavailable; allowing name", "err", err)
		return true, nil
	}
	if v.Degraded {
		s.log.Warn("risk degraded; allowing name")
		return true, nil
	}
	return v.Decision == riskclient.Allow, v.RuleIDs
}

// loginBlocked reports (and answers) a temporary block for this IP or account.
func (s *Server) loginBlocked(w http.ResponseWriter, r *http.Request, keys ...string) bool {
	if !s.riskOn() {
		return false
	}
	for _, k := range keys {
		blocked, err := s.blocks.Blocked(r.Context(), k)
		if err != nil {
			s.log.Error("blocklist read failed", "err", err)
			continue // fail open
		}
		if blocked {
			w.Header().Set("Retry-After", strconv.Itoa(int(loginBlockFor.Seconds())))
			writeErr(w, http.StatusTooManyRequests, "login_blocked", "too many failed attempts, try again later")
			return true
		}
	}
	return false
}

// recordLoginFailure feeds Prism's rate rule (it must be called ONLY on failures: the rule counts
// calls) for the IP and the account separately, and blocks whichever one reaches the limit.
func (s *Server) recordLoginFailure(r *http.Request, userID string) {
	if !s.riskOn() {
		return
	}
	ev := map[string]any{"auth": map[string]any{"failed_login_count": 1}}
	for _, key := range []string{"ip:" + clientIP(r), "user:" + userID} {
		v, err := s.risk.Evaluate(r.Context(), "login_fail", ev, key)
		if err != nil || v.Degraded || v.Decision != riskclient.Deny {
			if err != nil {
				s.log.Warn("risk unavailable on login failure", "err", err)
			}
			continue
		}
		if err := s.blocks.Block(r.Context(), key, time.Now().Add(loginBlockFor)); err != nil {
			s.log.Error("could not store block", "key", key, "err", err)
			continue
		}
		if s.acct != nil {
			s.audit(r, "system", "risk", "login.blocked", userID, map[string]any{"subject": key, "rules": v.RuleIDs})
		}
	}
}

// countsAsAttack: poor lighting or an expired challenge is not an attack.
func countsAsAttack(reason string) bool {
	switch reason {
	case "challenge_invalid", "poor_quality", "bad_frame_count":
		return false
	}
	return true
}
