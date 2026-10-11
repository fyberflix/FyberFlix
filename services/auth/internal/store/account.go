package store

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/zeaipc/fyberflix/services/auth/internal/httpapi"
	"github.com/zeaipc/fyberflix/services/auth/internal/identity"
	"github.com/zeaipc/fyberflix/services/auth/internal/token"
)

const userCols = `id::text, fyberflix_number, fyber_cable_name, status, face_ref::text, created_at`

func scanUser(row pgx.Row) (httpapi.User, error) {
	var u httpapi.User
	err := row.Scan(&u.ID, &u.Number, &u.CableName, &u.Status, &u.FaceRef, &u.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return u, httpapi.ErrNotFound
	}
	return u, err
}

func (p *PG) GetSignup(ctx context.Context, h []byte) (httpapi.SignupSession, error) {
	var s httpapi.SignupSession
	err := p.pool.QueryRow(ctx,
		`SELECT state, COALESCE(selected_number,''), COALESCE(fyber_cable_name,''),
		        face_ref::text, consented_at IS NOT NULL
		   FROM signup_sessions WHERE token_hash=$1 AND expires_at>now()`, h).
		Scan(&s.State, &s.Number, &s.CableName, &s.FaceRef, &s.Consented)
	if errors.Is(err, pgx.ErrNoRows) {
		return s, httpapi.ErrNoSession
	}
	return s, err
}

func (p *PG) RecordConsent(ctx context.Context, h []byte, version string) error {
	tag, err := p.pool.Exec(ctx,
		`UPDATE signup_sessions SET consented_at=now(), consent_version=$2
		  WHERE token_hash=$1 AND state='name_chosen' AND expires_at>now()`, h, version)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return httpapi.ErrWrongState
	}
	return nil
}

func (p *PG) MarkFaceChecked(ctx context.Context, h []byte) error {
	tag, err := p.pool.Exec(ctx,
		`UPDATE signup_sessions SET state='face_checked'
		  WHERE token_hash=$1 AND state='name_chosen' AND consented_at IS NOT NULL AND expires_at>now()`, h)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return httpapi.ErrWrongState
	}
	return nil
}

// CreateAccount turns a face-checked signup into a user (status 'pending') in ONE transaction:
// the held number becomes 'assigned' and the unique indexes decide any name race.
func (p *PG) CreateAccount(ctx context.Context, h []byte) (httpapi.User, error) {
	var u httpapi.User
	err := pgx.BeginFunc(ctx, p.pool, func(tx pgx.Tx) error {
		var state, number, name, faceRef string
		err := tx.QueryRow(ctx,
			`SELECT state, COALESCE(selected_number,''), COALESCE(fyber_cable_name,''), face_ref::text
			   FROM signup_sessions WHERE token_hash=$1 AND expires_at>now() FOR UPDATE`, h).
			Scan(&state, &number, &name, &faceRef)
		if errors.Is(err, pgx.ErrNoRows) {
			return httpapi.ErrNoSession
		}
		if err != nil {
			return err
		}
		if state != "face_checked" || number == "" || name == "" {
			return httpapi.ErrWrongState
		}
		// Re-validate the name: rules may have changed since it was chosen.
		display, _, perr := identity.ParseCableName(name)
		if perr != nil {
			return httpapi.ErrWrongState
		}
		tag, err := tx.Exec(ctx,
			`UPDATE number_registry SET state='assigned', held_by=NULL, held_until=NULL
			  WHERE number=$1 AND held_by=$2 AND state='held' AND held_until>now()`, number, h)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return httpapi.ErrNotHeld
		}
		u, err = scanUser(tx.QueryRow(ctx,
			`INSERT INTO users (fyberflix_number, fyber_cable_name, fyber_cable_key, face_ref)
			 VALUES ($1, $2, lower($2), $3::uuid)
			 RETURNING `+userCols, number, display, faceRef))
		if err != nil {
			var pe *pgconn.PgError
			if errors.As(err, &pe) && pe.Code == "23505" && strings.Contains(pe.ConstraintName, "fyber_cable_key") {
				return httpapi.ErrNameTaken
			}
			return err
		}
		_, err = tx.Exec(ctx,
			`UPDATE signup_sessions SET state='account_created', user_id=$2::uuid WHERE token_hash=$1`, h, u.ID)
		return err
	})
	return u, err
}

// ActivateAccount runs after the second face check passed.
func (p *PG) ActivateAccount(ctx context.Context, h []byte) (httpapi.User, error) {
	var u httpapi.User
	err := pgx.BeginFunc(ctx, p.pool, func(tx pgx.Tx) error {
		var state, userID string
		err := tx.QueryRow(ctx,
			`SELECT state, COALESCE(user_id::text,'') FROM signup_sessions
			  WHERE token_hash=$1 AND expires_at>now() FOR UPDATE`, h).Scan(&state, &userID)
		if errors.Is(err, pgx.ErrNoRows) {
			return httpapi.ErrNoSession
		}
		if err != nil {
			return err
		}
		if state != "account_created" || userID == "" {
			return httpapi.ErrWrongState
		}
		u, err = scanUser(tx.QueryRow(ctx,
			`UPDATE users SET status='active' WHERE id=$1::uuid AND status='pending' RETURNING `+userCols, userID))
		if err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `UPDATE signup_sessions SET state='completed' WHERE token_hash=$1`, h)
		return err
	})
	return u, err
}

func (p *PG) FindUserByIdentifier(ctx context.Context, ident string) (httpapi.User, error) {
	if identity.IsNumber(ident) { // branch in Go: one query per type keeps parameter types unambiguous
		return scanUser(p.pool.QueryRow(ctx,
			`SELECT `+userCols+` FROM users WHERE fyberflix_number=$1`, ident))
	}
	return scanUser(p.pool.QueryRow(ctx,
		`SELECT `+userCols+` FROM users WHERE fyber_cable_key=$1`, strings.ToLower(ident)))
}

func (p *PG) GetUser(ctx context.Context, id string) (httpapi.User, error) {
	if !token.IsUUID(id) {
		return httpapi.User{}, httpapi.ErrNotFound
	}
	return scanUser(p.pool.QueryRow(ctx, `SELECT `+userCols+` FROM users WHERE id=$1::uuid`, id))
}

func (p *PG) CreateLoginAttempt(ctx context.Context, h []byte, userID, challengeID string, exp time.Time) error {
	_, err := p.pool.Exec(ctx,
		`INSERT INTO login_attempts (token_hash, user_id, face_challenge_id, expires_at)
		 VALUES ($1,$2::uuid,$3,$4)`, h, userID, challengeID, exp)
	return err
}

func (p *PG) TakeLoginAttempt(ctx context.Context, h []byte) (httpapi.LoginAttempt, error) {
	var a httpapi.LoginAttempt
	var exp time.Time
	err := p.pool.QueryRow(ctx,
		`DELETE FROM login_attempts WHERE token_hash=$1
		 RETURNING user_id::text, face_challenge_id, expires_at`, h).Scan(&a.UserID, &a.FaceChallengeID, &exp)
	if errors.Is(err, pgx.ErrNoRows) || (err == nil && time.Now().After(exp)) {
		return a, httpapi.ErrNoAttempt
	}
	return a, err
}

func (p *PG) CreateAuthSession(ctx context.Context, id, userID string, hash []byte, ip, ua string, exp time.Time) error {
	if len(ua) > 300 {
		ua = ua[:300]
	}
	_, err := p.pool.Exec(ctx,
		`INSERT INTO sessions (id, user_id, current_refresh_hash, client_ip, user_agent, expires_at)
		 VALUES ($1::uuid,$2::uuid,$3,NULLIF($4,'')::inet,$5,$6)`, id, userID, hash, ip, ua, exp)
	return err
}

// RotateRefresh swaps the refresh token. Presenting the PREVIOUS token again means it was
// copied by someone: the whole session is revoked (and that revocation must be committed,
// so it is reported after the transaction instead of rolling back with an error).
func (p *PG) RotateRefresh(ctx context.Context, sid string, presented, next []byte, exp time.Time) (string, error) {
	var userID string
	reuse := false
	err := pgx.BeginFunc(ctx, p.pool, func(tx pgx.Tx) error {
		var cur, prev []byte
		var sessExp time.Time
		var revoked *time.Time
		err := tx.QueryRow(ctx,
			`SELECT user_id::text, current_refresh_hash, prev_refresh_hash, expires_at, revoked_at
			   FROM sessions WHERE id=$1::uuid FOR UPDATE`, sid).Scan(&userID, &cur, &prev, &sessExp, &revoked)
		if errors.Is(err, pgx.ErrNoRows) {
			return httpapi.ErrInvalidRefresh
		}
		if err != nil {
			return err
		}
		if revoked != nil || time.Now().After(sessExp) {
			return httpapi.ErrInvalidRefresh
		}
		switch {
		case token.Equal(cur, presented):
			_, err = tx.Exec(ctx,
				`UPDATE sessions SET prev_refresh_hash=current_refresh_hash, current_refresh_hash=$2,
				        expires_at=$3, last_used_at=now() WHERE id=$1::uuid`, sid, next, exp)
			return err
		case token.Equal(prev, presented):
			reuse = true
			_, err = tx.Exec(ctx, `UPDATE sessions SET revoked_at=now() WHERE id=$1::uuid`, sid)
			return err
		default:
			return httpapi.ErrInvalidRefresh
		}
	})
	if err != nil {
		return "", err
	}
	if reuse {
		return "", httpapi.ErrRefreshReuse
	}
	return userID, nil
}

func (p *PG) RevokeSession(ctx context.Context, sid string, presented []byte) error {
	_, err := p.pool.Exec(ctx,
		`UPDATE sessions SET revoked_at=now()
		  WHERE id=$1::uuid AND revoked_at IS NULL
		    AND (current_refresh_hash=$2 OR prev_refresh_hash=$2)`, sid, presented)
	return err
}

func (p *PG) RevokeAllSessions(ctx context.Context, userID string) error {
	_, err := p.pool.Exec(ctx,
		`UPDATE sessions SET revoked_at=now() WHERE user_id=$1::uuid AND revoked_at IS NULL`, userID)
	return err
}

// Hit counts one event in a fixed window shared by all replicas.
func (p *PG) Hit(ctx context.Context, key string, window time.Duration) (int, error) {
	var n int
	err := p.pool.QueryRow(ctx,
		`INSERT INTO rate_limits (key, window_start, hits) VALUES ($1,$2,1)
		 ON CONFLICT (key, window_start) DO UPDATE SET hits = rate_limits.hits + 1
		 RETURNING hits`, key, time.Now().UTC().Truncate(window)).Scan(&n)
	return n, err
}
