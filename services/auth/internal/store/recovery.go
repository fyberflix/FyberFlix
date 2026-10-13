package store

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/zeaipc/fyberflix/services/auth/internal/httpapi"
)

var _ httpapi.RecoveryStore = (*PG)(nil)

func (p *PG) PutRecoveryOTP(ctx context.Context, userID string, codeHash []byte, exp time.Time) error {
	_, err := p.pool.Exec(ctx,
		`INSERT INTO recovery_otps (user_id, code_hash, attempts, expires_at) VALUES ($1::uuid,$2,0,$3)
		 ON CONFLICT (user_id) DO UPDATE
		   SET code_hash=EXCLUDED.code_hash, attempts=0, expires_at=EXCLUDED.expires_at`, userID, codeHash, exp)
	return err
}

// CheckRecoveryOTP counts the attempt before comparing and commits that count even on a wrong code.
func (p *PG) CheckRecoveryOTP(ctx context.Context, userID string, maxAttempts int, match func(stored []byte) bool) error {
	var outcome error
	err := pgx.BeginFunc(ctx, p.pool, func(tx pgx.Tx) error {
		var hash []byte
		var attempts int
		var exp time.Time
		err := tx.QueryRow(ctx,
			`SELECT code_hash, attempts, expires_at FROM recovery_otps WHERE user_id=$1::uuid FOR UPDATE`,
			userID).Scan(&hash, &attempts, &exp)
		if errors.Is(err, pgx.ErrNoRows) {
			outcome = httpapi.ErrOTPInvalid
			return nil
		}
		if err != nil {
			return err
		}
		if time.Now().After(exp) {
			outcome = httpapi.ErrOTPInvalid
			_, err = tx.Exec(ctx, `DELETE FROM recovery_otps WHERE user_id=$1::uuid`, userID)
			return err
		}
		if attempts >= maxAttempts {
			outcome = httpapi.ErrOTPLocked
			return nil
		}
		if !match(hash) {
			outcome = httpapi.ErrOTPInvalid
			_, err = tx.Exec(ctx, `UPDATE recovery_otps SET attempts=attempts+1 WHERE user_id=$1::uuid`, userID)
			return err
		}
		_, err = tx.Exec(ctx, `DELETE FROM recovery_otps WHERE user_id=$1::uuid`, userID) // single use
		return err
	})
	if err != nil {
		return err
	}
	return outcome
}

const recCols = `id::text, user_id::text, state, ready_at, expires_at`

func scanRecovery(row pgx.Row) (httpapi.Recovery, error) {
	var r httpapi.Recovery
	err := row.Scan(&r.ID, &r.UserID, &r.State, &r.ReadyAt, &r.ExpiresAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return r, httpapi.ErrNotFound
	}
	return r, err
}

func (p *PG) CreateRecovery(ctx context.Context, userID string, tokenHash []byte, readyAt, expiresAt time.Time) (httpapi.Recovery, error) {
	var rc httpapi.Recovery
	err := pgx.BeginFunc(ctx, p.pool, func(tx pgx.Tx) error {
		// an expired request must not block a new one
		if _, err := tx.Exec(ctx,
			`UPDATE recovery_requests SET state='expired'
			  WHERE user_id=$1::uuid AND state IN ('waiting','approved') AND expires_at <= now()`, userID); err != nil {
			return err
		}
		var err error
		rc, err = scanRecovery(tx.QueryRow(ctx,
			`INSERT INTO recovery_requests (user_id, token_hash, ready_at, expires_at)
			 VALUES ($1::uuid,$2,$3,$4) RETURNING `+recCols, userID, tokenHash, readyAt, expiresAt))
		if isUnique(err, "recovery_one_open") {
			return httpapi.ErrRecoveryOpen
		}
		return err
	})
	return rc, err
}

func (p *PG) RecoveryByToken(ctx context.Context, tokenHash []byte) (httpapi.Recovery, error) {
	return scanRecovery(p.pool.QueryRow(ctx,
		`SELECT `+recCols+` FROM recovery_requests WHERE token_hash=$1`, tokenHash))
}

func (p *PG) OpenRecovery(ctx context.Context, userID string) (httpapi.Recovery, error) {
	return scanRecovery(p.pool.QueryRow(ctx,
		`SELECT `+recCols+` FROM recovery_requests
		  WHERE user_id=$1::uuid AND state IN ('waiting','approved') AND expires_at > now()`, userID))
}

func (p *PG) ApproveRecovery(ctx context.Context, userID, approverID string) error {
	tag, err := p.pool.Exec(ctx,
		`UPDATE recovery_requests SET state='approved', approved_by=$2::uuid, approved_at=now()
		  WHERE user_id=$1::uuid AND state='waiting' AND expires_at > now()`, userID, approverID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return httpapi.ErrWrongState
	}
	return nil
}

func (p *PG) CompleteRecovery(ctx context.Context, id string) error {
	tag, err := p.pool.Exec(ctx,
		`UPDATE recovery_requests SET state='completed', completed_at=now()
		  WHERE id=$1::uuid AND state='approved'`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return httpapi.ErrWrongState
	}
	return nil
}

func (p *PG) CancelOpenRecovery(ctx context.Context, userID string) (bool, error) {
	tag, err := p.pool.Exec(ctx,
		`UPDATE recovery_requests SET state='cancelled'
		  WHERE user_id=$1::uuid AND state IN ('waiting','approved')`, userID)
	return tag.RowsAffected() > 0, err
}

func (p *PG) ListWaitingRecoveries(ctx context.Context, limit int) ([]httpapi.PendingRecovery, error) {
	if limit <= 0 || limit > 200 {
		limit = 100
	}
	rows, err := p.pool.Query(ctx,
		`SELECT r.user_id::text, u.fyberflix_number, u.fyber_cable_name, r.ready_at, r.created_at
		   FROM recovery_requests r JOIN users u ON u.id = r.user_id
		  WHERE r.state='waiting' AND r.expires_at > now()
		  ORDER BY r.created_at LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []httpapi.PendingRecovery
	for rows.Next() {
		var x httpapi.PendingRecovery
		if err := rows.Scan(&x.UserID, &x.Number, &x.CableName, &x.ReadyAt, &x.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, x)
	}
	return out, rows.Err()
}
