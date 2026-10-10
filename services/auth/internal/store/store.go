// Package store is the PostgreSQL implementation of httpapi.Store.
package store

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/zeaipc/fyberflix/services/auth/internal/httpapi"
)

type PG struct{ pool *pgxpool.Pool }

func New(pool *pgxpool.Pool) *PG { return &PG{pool: pool} }

var _ httpapi.Store = (*PG)(nil)

func (p *PG) CreateSession(ctx context.Context, h []byte, ip, ua string, exp time.Time) error {
	if len(ua) > 300 {
		ua = ua[:300]
	}
	_, err := p.pool.Exec(ctx,
		`INSERT INTO signup_sessions (token_hash, client_ip, user_agent, expires_at)
		 VALUES ($1, NULLIF($2,'')::inet, $3, $4)`, h, ip, ua, exp)
	return err
}

func (p *PG) RequireState(ctx context.Context, h []byte, allowed ...string) error {
	var state string
	err := p.pool.QueryRow(ctx,
		`SELECT state FROM signup_sessions WHERE token_hash=$1 AND expires_at>now()`, h).Scan(&state)
	if errors.Is(err, pgx.ErrNoRows) {
		return httpapi.ErrNoSession
	}
	if err != nil {
		return err
	}
	for _, a := range allowed {
		if a == state {
			return nil
		}
	}
	return httpapi.ErrWrongState
}

func (p *PG) HoldNumbers(ctx context.Context, h []byte, cands []string, until time.Time) ([]string, error) {
	var held []string
	for _, n := range cands {
		// Takes a free number, or one whose previous hold has expired.
		tag, err := p.pool.Exec(ctx,
			`INSERT INTO number_registry (number, state, held_by, held_until)
			 VALUES ($1,'held',$2,$3)
			 ON CONFLICT (number) DO UPDATE
			   SET held_by=EXCLUDED.held_by, held_until=EXCLUDED.held_until
			   WHERE number_registry.state='held' AND number_registry.held_until < now()`,
			n, h, until)
		if err != nil {
			return nil, err
		}
		if tag.RowsAffected() == 1 {
			held = append(held, n)
		}
	}
	return held, nil
}

func (p *PG) ReleaseForRefresh(ctx context.Context, h []byte, max int) error {
	return pgx.BeginFunc(ctx, p.pool, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx,
			`UPDATE signup_sessions SET refresh_count=refresh_count+1
			 WHERE token_hash=$1 AND refresh_count < $2`, h, max)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return httpapi.ErrRefreshLimit
		}
		_, err = tx.Exec(ctx, `DELETE FROM number_registry WHERE held_by=$1 AND state='held'`, h)
		return err
	})
}

func (p *PG) SelectNumber(ctx context.Context, h []byte, number string, until time.Time) error {
	return pgx.BeginFunc(ctx, p.pool, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx,
			`UPDATE number_registry SET held_until=$3
			 WHERE number=$1 AND held_by=$2 AND state='held' AND held_until>now()`, number, h, until)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return httpapi.ErrNotHeld
		}
		// Selection is final: free the other nine offers.
		if _, err = tx.Exec(ctx,
			`DELETE FROM number_registry WHERE held_by=$1 AND state='held' AND number<>$2`, h, number); err != nil {
			return err
		}
		_, err = tx.Exec(ctx,
			`UPDATE signup_sessions SET selected_number=$2, state='number_selected' WHERE token_hash=$1`, h, number)
		return err
	})
}

func (p *PG) CableNameTaken(ctx context.Context, key string) (bool, error) {
	var taken bool
	err := p.pool.QueryRow(ctx,
		`SELECT EXISTS (SELECT 1 FROM users WHERE fyber_cable_key=$1)`, key).Scan(&taken)
	return taken, err
}

func (p *PG) SetCableName(ctx context.Context, h []byte, display string) error {
	_, err := p.pool.Exec(ctx,
		`UPDATE signup_sessions SET fyber_cable_name=$2, state='name_chosen' WHERE token_hash=$1`, h, display)
	return err
}
