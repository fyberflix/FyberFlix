// Package janitor runs periodic cleanup: abandoned signups, expired rows,
// and the final purge of accounts whose deletion grace period has ended.
package janitor

import (
	"context"
	"log/slog"
	"time"
)

type StaleSignup struct {
	TokenHash []byte
	FaceRef   string
	Enrolled  bool // a face template may exist in face-service
}

type Store interface {
	CleanupExpired(ctx context.Context) error
	StaleSignups(ctx context.Context, limit int) ([]StaleSignup, error)
	DeleteStaleSignup(ctx context.Context, s StaleSignup) error
	DueDeletions(ctx context.Context, limit int) ([]DueUser, error)
	PurgeUser(ctx context.Context, userID string) error
}

type DueUser struct{ UserID, FaceRef string }

type FaceEraser interface {
	Delete(ctx context.Context, ref string) error
}

// RunOnce is idempotent and safe to run on every replica at once: the store uses
// row locks (SKIP LOCKED) and every step can be repeated.
// Biometric data is erased FIRST; the database row is only purged if that succeeded.
func RunOnce(ctx context.Context, st Store, face FaceEraser, log *slog.Logger) {
	if err := st.CleanupExpired(ctx); err != nil {
		log.Error("janitor: cleanup expired", "err", err)
	}

	stale, err := st.StaleSignups(ctx, 100)
	if err != nil {
		log.Error("janitor: list stale signups", "err", err)
	}
	for _, s := range stale {
		if s.Enrolled {
			if err := face.Delete(ctx, s.FaceRef); err != nil {
				log.Error("janitor: face erase failed, will retry", "err", err)
				continue
			}
		}
		if err := st.DeleteStaleSignup(ctx, s); err != nil {
			log.Error("janitor: delete stale signup", "err", err)
		}
	}

	due, err := st.DueDeletions(ctx, 50)
	if err != nil {
		log.Error("janitor: list due deletions", "err", err)
	}
	for _, d := range due {
		if err := face.Delete(ctx, d.FaceRef); err != nil {
			log.Error("janitor: face erase failed, will retry", "user", d.UserID, "err", err)
			continue
		}
		if err := st.PurgeUser(ctx, d.UserID); err != nil {
			log.Error("janitor: purge user", "user", d.UserID, "err", err)
			continue
		}
		log.Info("janitor: account purged", "user", d.UserID)
	}
}

func Run(ctx context.Context, st Store, face FaceEraser, log *slog.Logger, every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		RunOnce(ctx, st, face, log)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}
