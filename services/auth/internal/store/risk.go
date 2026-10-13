package store

import (
	"context"
	"time"

	"github.com/zeaipc/fyberflix/services/auth/internal/httpapi"
)

var _ httpapi.Blocklist = (*PG)(nil)

// Block never shortens an existing block.
func (p *PG) Block(ctx context.Context, key string, until time.Time) error {
	_, err := p.pool.Exec(ctx,
		`INSERT INTO risk_blocks (key, until) VALUES ($1,$2)
		 ON CONFLICT (key) DO UPDATE SET until = GREATEST(risk_blocks.until, EXCLUDED.until)`, key, until)
	return err
}

func (p *PG) Blocked(ctx context.Context, key string) (bool, error) {
	var blocked bool
	err := p.pool.QueryRow(ctx,
		`SELECT EXISTS (SELECT 1 FROM risk_blocks WHERE key=$1 AND until > now())`, key).Scan(&blocked)
	return blocked, err
}
