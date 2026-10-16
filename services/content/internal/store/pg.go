// Package store is the Postgres implementation of the API and worker storage interfaces.
package store

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/fyberflix/fyberflix/services/content/internal/model"
)

type PG struct{ pool *pgxpool.Pool }

func Open(ctx context.Context, url string) (*PG, error) {
	p, err := pgxpool.New(ctx, url)
	if err != nil {
		return nil, err
	}
	if err := p.Ping(ctx); err != nil {
		p.Close()
		return nil, err
	}
	return &PG{pool: p}, nil
}

func (s *PG) Close()                         { s.pool.Close() }
func (s *PG) Ping(ctx context.Context) error { return s.pool.Ping(ctx) }

const cols = `id, owner_id, kind, status, caption, visibility, src_key, src_content_type, src_bytes,
 duration_ms, width, height, hls_key, thumb_key, media_keys, fail_reason, created_at, published_at`

func scan(r pgx.Row) (model.Video, error) {
	var v model.Video
	err := r.Scan(&v.ID, &v.OwnerID, &v.Kind, &v.Status, &v.Caption, &v.Visibility, &v.SrcKey, &v.SrcContentType,
		&v.SrcBytes, &v.DurationMS, &v.Width, &v.Height, &v.HLSKey, &v.ThumbKey, &v.MediaKeys, &v.FailReason,
		&v.CreatedAt, &v.PublishedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return v, model.ErrNotFound
	}
	return v, err
}

func (s *PG) CountInitsSince(ctx context.Context, owner string, since time.Time) (int, error) {
	var n int
	err := s.pool.QueryRow(ctx, `SELECT count(*) FROM videos WHERE owner_id=$1 AND created_at>$2`, owner, since).Scan(&n)
	return n, err
}

func (s *PG) CountAwaiting(ctx context.Context, owner string) (int, error) {
	var n int
	err := s.pool.QueryRow(ctx, `SELECT count(*) FROM videos WHERE owner_id=$1 AND status='awaiting_upload'`, owner).Scan(&n)
	return n, err
}

func (s *PG) Create(ctx context.Context, v *model.Video) error {
	_, err := s.pool.Exec(ctx, `INSERT INTO videos (id, owner_id, kind, status, caption, visibility, src_key, src_content_type, src_bytes)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
		v.ID, v.OwnerID, v.Kind, v.Status, v.Caption, v.Visibility, v.SrcKey, v.SrcContentType, v.SrcBytes)
	return err
}

func (s *PG) Get(ctx context.Context, id string) (model.Video, error) {
	return scan(s.pool.QueryRow(ctx, `SELECT `+cols+` FROM videos WHERE id=$1`, id))
}

func (s *PG) StartProcessing(ctx context.Context, id, owner string, size int64) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	tag, err := tx.Exec(ctx, `UPDATE videos SET status='processing', src_bytes=$3, updated_at=now()
		WHERE id=$1 AND owner_id=$2 AND status='awaiting_upload'`, id, owner, size)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return model.ErrConflict
	}
	if _, err := tx.Exec(ctx, `INSERT INTO jobs (kind, video_id) VALUES ('transcode',$1) ON CONFLICT DO NOTHING`, id); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (s *PG) ListByOwner(ctx context.Context, owner string, publicOnly bool, limit int, after *model.Cursor) ([]model.Video, error) {
	var q string
	args := []any{owner, limit}
	if publicOnly {
		q = `SELECT ` + cols + ` FROM videos WHERE owner_id=$1 AND status='ready' AND visibility='public'`
		if after != nil {
			q += ` AND (published_at, id) < ($3, $4)`
			args = append(args, after.At, after.ID)
		}
		q += ` ORDER BY published_at DESC, id DESC LIMIT $2`
	} else {
		// owner view: everything not removed; ordered by created_at (always set)
		q = `SELECT ` + cols + ` FROM videos WHERE owner_id=$1 AND status<>'removed'`
		if after != nil {
			q += ` AND (created_at, id) < ($3, $4)`
			args = append(args, after.At, after.ID)
		}
		q += ` ORDER BY created_at DESC, id DESC LIMIT $2`
	}
	rows, err := s.pool.Query(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.Video
	for rows.Next() {
		v, err := scan(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

func (s *PG) Remove(ctx context.Context, id, owner string) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	tag, err := tx.Exec(ctx, `UPDATE videos SET status='removed', updated_at=now()
		WHERE id=$1 AND owner_id=$2 AND status<>'removed'`, id, owner)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return model.ErrNotFound
	}
	// cancel a queued transcode; a running one finishes harmlessly (worker re-checks status)
	if _, err := tx.Exec(ctx, `UPDATE jobs SET state='done', updated_at=now() WHERE video_id=$1 AND kind='transcode' AND state='queued'`, id); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO jobs (kind, video_id, run_after) VALUES ('purge',$1, now())
		ON CONFLICT DO NOTHING`, id); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// ---------------- worker side ----------------

// Claim leases the next runnable job (queued, or running with an expired lease).
func (s *PG) Claim(ctx context.Context, worker string, lease time.Duration) (*model.Job, error) {
	var j model.Job
	err := s.pool.QueryRow(ctx, `
		UPDATE jobs SET state='running', attempts=attempts+1, locked_by=$1,
		       locked_until=now()+make_interval(secs => $2), updated_at=now()
		WHERE id = (SELECT id FROM jobs
		            WHERE (state='queued' AND run_after<=now()) OR (state='running' AND locked_until<now())
		            ORDER BY run_after, id FOR UPDATE SKIP LOCKED LIMIT 1)
		RETURNING id, kind, video_id, attempts, max_attempts`, worker, lease.Seconds()).
		Scan(&j.ID, &j.Kind, &j.VideoID, &j.Attempts, &j.MaxAttempts)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &j, nil
}

// Extend renews a lease; false means the job was taken over by someone else.
func (s *PG) Extend(ctx context.Context, id int64, worker string, lease time.Duration) (bool, error) {
	tag, err := s.pool.Exec(ctx, `UPDATE jobs SET locked_until=now()+make_interval(secs => $3), updated_at=now()
		WHERE id=$1 AND locked_by=$2 AND state='running'`, id, worker, lease.Seconds())
	return tag.RowsAffected() == 1, err
}

func (s *PG) Finish(ctx context.Context, id int64, worker string) error {
	_, err := s.pool.Exec(ctx, `UPDATE jobs SET state='done', locked_by=NULL, locked_until=NULL, updated_at=now()
		WHERE id=$1 AND locked_by=$2`, id, worker)
	return err
}

// Fail either schedules a retry after `retry` or, when final (or out of attempts), marks the job failed.
// It reports whether the job is now permanently failed.
func (s *PG) Fail(ctx context.Context, id int64, worker, msg string, retry time.Duration, final bool) (bool, error) {
	if len(msg) > 500 {
		msg = msg[:500]
	}
	var state string
	err := s.pool.QueryRow(ctx, `UPDATE jobs SET
		state = CASE WHEN $4 OR attempts>=max_attempts THEN 'failed' ELSE 'queued' END,
		run_after = now()+make_interval(secs => $5), last_error=$3, locked_by=NULL, locked_until=NULL, updated_at=now()
		WHERE id=$1 AND locked_by=$2 RETURNING state`, id, worker, msg, final, retry.Seconds()).Scan(&state)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	return state == "failed", err
}

func (s *PG) SetReady(ctx context.Context, id string, r model.Result) error {
	tag, err := s.pool.Exec(ctx, `UPDATE videos SET status='ready', duration_ms=$2, width=$3, height=$4, hls_key=$5,
		thumb_key=$6, media_keys=$7, published_at=now(), updated_at=now()
		WHERE id=$1 AND status='processing'`, id, r.DurationMS, r.Width, r.Height, r.HLSKey, r.ThumbKey, r.MediaKeys)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return model.ErrConflict
	}
	return nil
}

func (s *PG) SetFailed(ctx context.Context, id, reason string) error {
	_, err := s.pool.Exec(ctx, `UPDATE videos SET status='failed', fail_reason=$2, updated_at=now()
		WHERE id=$1 AND status='processing'`, id, reason)
	return err
}

// ExpireAwaiting removes uploads that were never completed and queues their purge.
func (s *PG) ExpireAwaiting(ctx context.Context, olderThan time.Duration) (int, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback(ctx)
	tag, err := tx.Exec(ctx, `WITH x AS (UPDATE videos SET status='removed', updated_at=now()
		WHERE status='awaiting_upload' AND created_at < now()-make_interval(secs => $1) RETURNING id)
		INSERT INTO jobs (kind, video_id) SELECT 'purge', id FROM x ON CONFLICT DO NOTHING`, olderThan.Seconds())
	if err != nil {
		return 0, err
	}
	return int(tag.RowsAffected()), tx.Commit(ctx)
}
