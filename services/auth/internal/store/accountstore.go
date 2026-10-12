package store

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/zeaipc/fyberflix/services/auth/internal/httpapi"
	"github.com/zeaipc/fyberflix/services/auth/internal/janitor"
	"github.com/zeaipc/fyberflix/services/auth/internal/token"
)

var (
	_ httpapi.AccountStore = (*PG)(nil)
	_ janitor.Store        = (*PG)(nil)
)

func isUnique(err error, constraintPart string) bool {
	var pe *pgconn.PgError
	return errors.As(err, &pe) && pe.Code == "23505" && strings.Contains(pe.ConstraintName, constraintPart)
}

// ---------- email OTP ----------

func (p *PG) PutEmailOTP(ctx context.Context, userID, email string, codeHash []byte, expires time.Time) error {
	_, err := p.pool.Exec(ctx,
		`INSERT INTO email_otps (user_id, email, code_hash, attempts, expires_at)
		 VALUES ($1::uuid,$2,$3,0,$4)
		 ON CONFLICT (user_id) DO UPDATE
		   SET email=EXCLUDED.email, code_hash=EXCLUDED.code_hash, attempts=0,
		       expires_at=EXCLUDED.expires_at, created_at=now()`, userID, email, codeHash, expires)
	return err
}

// CheckEmailOTP counts the attempt BEFORE comparing and commits that count even when the code is
// wrong (the failure is returned after the transaction, not as a rollback-causing error).
func (p *PG) CheckEmailOTP(ctx context.Context, userID string, maxAttempts int,
	match func(email string, storedHash []byte) bool) (string, error) {
	var email string
	var outcome error
	err := pgx.BeginFunc(ctx, p.pool, func(tx pgx.Tx) error {
		var hash []byte
		var attempts int
		var exp time.Time
		err := tx.QueryRow(ctx,
			`SELECT email, code_hash, attempts, expires_at FROM email_otps
			  WHERE user_id=$1::uuid FOR UPDATE`, userID).Scan(&email, &hash, &attempts, &exp)
		if errors.Is(err, pgx.ErrNoRows) {
			outcome = httpapi.ErrOTPInvalid
			return nil
		}
		if err != nil {
			return err
		}
		if time.Now().After(exp) {
			_, err = tx.Exec(ctx, `DELETE FROM email_otps WHERE user_id=$1::uuid`, userID)
			outcome = httpapi.ErrOTPInvalid
			return err
		}
		if attempts >= maxAttempts {
			outcome = httpapi.ErrOTPLocked
			return nil
		}
		if _, err = tx.Exec(ctx,
			`UPDATE email_otps SET attempts=attempts+1 WHERE user_id=$1::uuid`, userID); err != nil {
			return err
		}
		if !match(email, hash) {
			outcome = httpapi.ErrOTPInvalid
			return nil
		}
		if _, err = tx.Exec(ctx,
			`UPDATE users SET email=$2, email_verified_at=now() WHERE id=$1::uuid`, userID, email); err != nil {
			if isUnique(err, "email_verified") {
				return httpapi.ErrEmailTaken
			}
			return err
		}
		_, err = tx.Exec(ctx, `DELETE FROM email_otps WHERE user_id=$1::uuid`, userID)
		return err
	})
	if err != nil {
		return "", err
	}
	if outcome != nil {
		return "", outcome
	}
	return email, nil
}

func (p *PG) EmailInfo(ctx context.Context, userID string) (string, bool, error) {
	var email *string
	var verified bool
	err := p.pool.QueryRow(ctx,
		`SELECT email, email_verified_at IS NOT NULL FROM users WHERE id=$1::uuid`, userID).Scan(&email, &verified)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", false, httpapi.ErrNotFound
	}
	if email == nil {
		return "", false, err
	}
	return *email, verified, err
}

func (p *PG) RemoveEmail(ctx context.Context, userID string) error {
	return pgx.BeginFunc(ctx, p.pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx,
			`UPDATE users SET email=NULL, email_verified_at=NULL WHERE id=$1::uuid`, userID); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `DELETE FROM email_otps WHERE user_id=$1::uuid`, userID)
		return err
	})
}

// ---------- profile ----------

// RenameCable changes the display name (and key) once per cooldown. The old key is recorded so it
// stays reserved for 90 days; the unique index + trigger decide any race.
func (p *PG) RenameCable(ctx context.Context, userID, display string, cooldown time.Duration) error {
	return pgx.BeginFunc(ctx, p.pool, func(tx pgx.Tx) error {
		var oldKey string
		var changed *time.Time
		err := tx.QueryRow(ctx,
			`SELECT fyber_cable_key, cable_name_changed_at FROM users
			  WHERE id=$1::uuid AND status='active' FOR UPDATE`, userID).Scan(&oldKey, &changed)
		if errors.Is(err, pgx.ErrNoRows) {
			return httpapi.ErrNotFound
		}
		if err != nil {
			return err
		}
		if changed != nil && time.Since(*changed) < cooldown {
			return httpapi.ErrRenameCooldown
		}
		newKey := strings.ToLower(display)
		if newKey != oldKey { // only a case change: no history entry needed
			if _, err = tx.Exec(ctx,
				`INSERT INTO cable_name_history (key, user_id) VALUES ($1,$2::uuid)
				 ON CONFLICT (key) DO UPDATE SET user_id=EXCLUDED.user_id, released_at=now()`,
				oldKey, userID); err != nil {
				return err
			}
		}
		_, err = tx.Exec(ctx,
			`UPDATE users SET fyber_cable_name=$2, fyber_cable_key=$3, cable_name_changed_at=now()
			  WHERE id=$1::uuid`, userID, display, newKey)
		if err != nil {
			if isUnique(err, "fyber_cable_key") {
				return httpapi.ErrNameTaken
			}
			return err
		}
		return nil
	})
}

func (p *PG) ListSessions(ctx context.Context, userID string) ([]httpapi.SessionInfo, error) {
	rows, err := p.pool.Query(ctx,
		`SELECT id::text, COALESCE(user_agent,''), COALESCE(host(client_ip),''), created_at, last_used_at
		   FROM sessions WHERE user_id=$1::uuid AND revoked_at IS NULL AND expires_at>now()
		  ORDER BY last_used_at DESC LIMIT 50`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []httpapi.SessionInfo
	for rows.Next() {
		var s httpapi.SessionInfo
		if err := rows.Scan(&s.ID, &s.UserAgent, &s.IP, &s.CreatedAt, &s.LastUsedAt); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

func (p *PG) RevokeSessionByID(ctx context.Context, userID, sessionID string) (bool, error) {
	if !token.IsUUID(sessionID) {
		return false, nil
	}
	tag, err := p.pool.Exec(ctx,
		`UPDATE sessions SET revoked_at=now()
		  WHERE id=$1::uuid AND user_id=$2::uuid AND revoked_at IS NULL`, sessionID, userID)
	return tag.RowsAffected() == 1, err
}

// ---------- deletion / restore ----------

func (p *PG) CreateFaceAttempt(ctx context.Context, h []byte, userID, challengeID, purpose string, exp time.Time) error {
	_, err := p.pool.Exec(ctx,
		`INSERT INTO face_attempts (token_hash, user_id, face_challenge_id, purpose, expires_at)
		 VALUES ($1,$2::uuid,$3,$4,$5)`, h, userID, challengeID, purpose, exp)
	return err
}

func (p *PG) TakeFaceAttempt(ctx context.Context, h []byte) (httpapi.FaceAttempt, error) {
	var a httpapi.FaceAttempt
	var exp time.Time
	err := p.pool.QueryRow(ctx,
		`DELETE FROM face_attempts WHERE token_hash=$1
		 RETURNING user_id::text, face_challenge_id, purpose, expires_at`, h).
		Scan(&a.UserID, &a.FaceChallengeID, &a.Purpose, &exp)
	if errors.Is(err, pgx.ErrNoRows) || (err == nil && time.Now().After(exp)) {
		return a, httpapi.ErrNoAttempt
	}
	return a, err
}

func (p *PG) ScheduleDeletion(ctx context.Context, userID string, at time.Time) error {
	return pgx.BeginFunc(ctx, p.pool, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx,
			`UPDATE users SET status='deletion_pending', deletion_scheduled_at=$2
			  WHERE id=$1::uuid AND status='active'`, userID, at)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return httpapi.ErrWrongState
		}
		_, err = tx.Exec(ctx,
			`UPDATE sessions SET revoked_at=now() WHERE user_id=$1::uuid AND revoked_at IS NULL`, userID)
		return err
	})
}

func (p *PG) RestoreAccount(ctx context.Context, userID string) error {
	tag, err := p.pool.Exec(ctx,
		`UPDATE users SET status='active', deletion_scheduled_at=NULL
		  WHERE id=$1::uuid AND status='deletion_pending'`, userID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return httpapi.ErrWrongState
	}
	return nil
}

// ---------- staff + audit ----------

func (p *PG) Roles(ctx context.Context, userID string) ([]string, error) {
	if !token.IsUUID(userID) {
		return nil, nil
	}
	rows, err := p.pool.Query(ctx, `SELECT role FROM staff_roles WHERE user_id=$1::uuid`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var r string
		if err := rows.Scan(&r); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (p *PG) SetStatus(ctx context.Context, userID, from, to string) error {
	return pgx.BeginFunc(ctx, p.pool, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx,
			`UPDATE users SET status=$3 WHERE id=$1::uuid AND status=$2`, userID, from, to)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return httpapi.ErrWrongState
		}
		if to == "suspended" {
			_, err = tx.Exec(ctx,
				`UPDATE sessions SET revoked_at=now() WHERE user_id=$1::uuid AND revoked_at IS NULL`, userID)
		}
		return err
	})
}

func (p *PG) Audit(ctx context.Context, e httpapi.AuditEntry) error {
	detail := "{}"
	if len(e.Detail) > 0 {
		b, err := json.Marshal(e.Detail)
		if err != nil {
			return err
		}
		detail = string(b)
	}
	var target any
	if token.IsUUID(e.TargetUser) {
		target = e.TargetUser
	}
	_, err := p.pool.Exec(ctx,
		`INSERT INTO audit_log (actor_type, actor_id, action, target_user, ip, detail)
		 VALUES ($1,$2,$3,$4::uuid,NULLIF($5,'')::inet,$6::jsonb)`,
		e.ActorType, e.ActorID, e.Action, target, e.IP, detail)
	return err
}

func (p *PG) ListAudit(ctx context.Context, userID string, limit int) ([]httpapi.AuditEntry, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	rows, err := p.pool.Query(ctx,
		`SELECT at, actor_type, actor_id, action, COALESCE(target_user::text,''),
		        COALESCE(host(ip),''), detail::text
		   FROM audit_log WHERE target_user=$1::uuid ORDER BY at DESC, id DESC LIMIT $2`, userID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []httpapi.AuditEntry
	for rows.Next() {
		var e httpapi.AuditEntry
		var detail string
		if err := rows.Scan(&e.At, &e.ActorType, &e.ActorID, &e.Action, &e.TargetUser, &e.IP, &detail); err != nil {
			return nil, err
		}
		_ = json.Unmarshal([]byte(detail), &e.Detail)
		out = append(out, e)
	}
	return out, rows.Err()
}

// ---------- janitor ----------

func (p *PG) CleanupExpired(ctx context.Context) error {
	stmts := []string{
		`DELETE FROM login_attempts WHERE expires_at < now()`,
		`DELETE FROM face_attempts WHERE expires_at < now()`,
		`DELETE FROM email_otps WHERE expires_at < now() - interval '1 hour'`,
		`DELETE FROM rate_limits WHERE window_start < now() - interval '2 days'`,
		`DELETE FROM sessions WHERE expires_at < now() - interval '30 days'
		    OR revoked_at < now() - interval '30 days'`,
		`DELETE FROM signup_sessions WHERE expires_at < now() - interval '1 day' AND user_id IS NOT NULL`,
		// held numbers whose signup vanished or whose hold ran out
		`DELETE FROM number_registry WHERE state='held' AND held_until < now()`,
	}
	for _, s := range stmts {
		if _, err := p.pool.Exec(ctx, s); err != nil {
			return err
		}
	}
	return nil
}

// StaleSignups: expired signups that never became an account. Signups that already created a user
// are left alone (the user row owns the face template now).
func (p *PG) StaleSignups(ctx context.Context, limit int) ([]janitor.StaleSignup, error) {
	rows, err := p.pool.Query(ctx,
		`SELECT token_hash, face_ref::text, state IN ('face_checked','account_created','face_reverified','completed')
		   FROM signup_sessions
		  WHERE expires_at < now() - interval '10 minutes' AND user_id IS NULL
		  ORDER BY expires_at LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []janitor.StaleSignup
	for rows.Next() {
		var s janitor.StaleSignup
		if err := rows.Scan(&s.TokenHash, &s.FaceRef, &s.Enrolled); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

func (p *PG) DeleteStaleSignup(ctx context.Context, s janitor.StaleSignup) error {
	return pgx.BeginFunc(ctx, p.pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx,
			`DELETE FROM number_registry WHERE held_by=$1 AND state='held'`, s.TokenHash); err != nil {
			return err
		}
		_, err := tx.Exec(ctx,
			`DELETE FROM signup_sessions WHERE token_hash=$1 AND user_id IS NULL`, s.TokenHash)
		return err
	})
}

func (p *PG) DueDeletions(ctx context.Context, limit int) ([]janitor.DueUser, error) {
	rows, err := p.pool.Query(ctx,
		`SELECT id::text, face_ref::text FROM users
		  WHERE status='deletion_pending' AND deletion_scheduled_at <= now()
		  ORDER BY deletion_scheduled_at LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []janitor.DueUser
	for rows.Next() {
		var d janitor.DueUser
		if err := rows.Scan(&d.UserID, &d.FaceRef); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// PurgeUser runs AFTER the face template was erased. The users row is kept as an anonymous
// tombstone (the number must stay retired forever); everything personal is removed.
func (p *PG) PurgeUser(ctx context.Context, userID string) error {
	return pgx.BeginFunc(ctx, p.pool, func(tx pgx.Tx) error {
		var oldKey, number string
		err := tx.QueryRow(ctx,
			`SELECT fyber_cable_key, fyberflix_number FROM users
			  WHERE id=$1::uuid AND status='deletion_pending' FOR UPDATE SKIP LOCKED`, userID).Scan(&oldKey, &number)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil // already purged or restored meanwhile
		}
		if err != nil {
			return err
		}
		if _, err = tx.Exec(ctx,
			`INSERT INTO cable_name_history (key, user_id) VALUES ($1,$2::uuid)
			 ON CONFLICT (key) DO UPDATE SET user_id=EXCLUDED.user_id, released_at=now()`, oldKey, userID); err != nil {
			return err
		}
		if _, err = tx.Exec(ctx,
			`UPDATE users SET status='deleted', deleted_at=now(), email=NULL, email_verified_at=NULL,
			        fyber_cable_name='deleted-user', fyber_cable_key='deleted:'||id::text,
			        deletion_scheduled_at=NULL
			  WHERE id=$1::uuid`, userID); err != nil {
			return err
		}
		if _, err = tx.Exec(ctx,
			`UPDATE number_registry SET state='retired' WHERE number=$1`, number); err != nil {
			return err
		}
		for _, q := range []string{
			`DELETE FROM sessions WHERE user_id=$1::uuid`,
			`DELETE FROM login_attempts WHERE user_id=$1::uuid`,
			`DELETE FROM face_attempts WHERE user_id=$1::uuid`,
			`DELETE FROM email_otps WHERE user_id=$1::uuid`,
			`DELETE FROM staff_roles WHERE user_id=$1::uuid`,
		} {
			if _, err = tx.Exec(ctx, q, userID); err != nil {
				return err
			}
		}
		_, err = tx.Exec(ctx,
			`INSERT INTO audit_log (actor_type, actor_id, action, target_user)
			 VALUES ('system','janitor','account.purged',$1::uuid)`, userID)
		return err
	})
}
