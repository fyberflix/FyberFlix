// Package worker runs background jobs: video transcoding, purging removed videos,
// and expiring abandoned uploads.
package worker

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/fyberflix/fyberflix/services/content/internal/media"
	"github.com/fyberflix/fyberflix/services/content/internal/model"
	"github.com/fyberflix/fyberflix/services/content/internal/objstore"
)

type Store interface {
	Claim(ctx context.Context, worker string, lease time.Duration) (*model.Job, error)
	Extend(ctx context.Context, id int64, worker string, lease time.Duration) (bool, error)
	Finish(ctx context.Context, id int64, worker string) error
	Fail(ctx context.Context, id int64, worker, msg string, retry time.Duration, final bool) (bool, error)
	Get(ctx context.Context, id string) (model.Video, error)
	SetReady(ctx context.Context, id string, r model.Result) error
	SetFailed(ctx context.Context, id, reason string) error
	ExpireAwaiting(ctx context.Context, olderThan time.Duration) (int, error)
}

type Objects interface {
	Download(ctx context.Context, bucket, key string, w io.Writer, max int64) error
	UploadFile(ctx context.Context, bucket, key, contentType, path string) error
	Delete(ctx context.Context, bucket, key string) error
}

type Config struct {
	ID              string
	OriginalsBucket string
	MediaBucket     string
	Concurrency     int
	Lease           time.Duration
	PollEvery       time.Duration
	AbandonAfter    time.Duration
}

type Worker struct {
	cfg Config
	st  Store
	obj Objects
}

func New(cfg Config, st Store, obj Objects) *Worker {
	if cfg.Lease == 0 {
		cfg.Lease = 10 * time.Minute
	}
	if cfg.PollEvery == 0 {
		cfg.PollEvery = 3 * time.Second
	}
	if cfg.AbandonAfter == 0 {
		cfg.AbandonAfter = 24 * time.Hour
	}
	if cfg.Concurrency < 1 {
		cfg.Concurrency = 1
	}
	return &Worker{cfg: cfg, st: st, obj: obj}
}

// permanent errors are the uploader's fault (bad media); retrying cannot help.
type permanent struct{ error }

func (w *Worker) Run(ctx context.Context) {
	var wg sync.WaitGroup
	for i := 0; i < w.cfg.Concurrency; i++ {
		wg.Add(1)
		id := fmt.Sprintf("%s-%d", w.cfg.ID, i)
		go func() { defer wg.Done(); w.loop(ctx, id) }()
	}
	wg.Add(1)
	go func() { defer wg.Done(); w.janitor(ctx) }()
	wg.Wait()
}

func (w *Worker) loop(ctx context.Context, id string) {
	for ctx.Err() == nil {
		job, err := w.st.Claim(ctx, id, w.cfg.Lease)
		if err != nil {
			slog.Error("claim failed", "err", err)
		}
		if job == nil {
			select {
			case <-ctx.Done():
				return
			case <-time.After(w.cfg.PollEvery):
			}
			continue
		}
		w.handle(ctx, id, job)
	}
}

func (w *Worker) janitor(ctx context.Context) {
	t := time.NewTicker(10 * time.Minute)
	defer t.Stop()
	for {
		if n, err := w.st.ExpireAwaiting(ctx, w.cfg.AbandonAfter); err != nil {
			slog.Error("janitor", "err", err)
		} else if n > 0 {
			slog.Info("expired abandoned uploads", "count", n)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

func backoff(attempt int) time.Duration {
	d := 30 * time.Second << min(attempt-1, 6) // 30s, 1m, 2m, ... capped ~32m
	return d
}

func (w *Worker) handle(ctx context.Context, wid string, j *model.Job) {
	log := slog.With("job", j.ID, "kind", j.Kind, "video", j.VideoID, "attempt", j.Attempts)
	// keep the lease alive while we work
	jctx, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() {
		t := time.NewTicker(w.cfg.Lease / 3)
		defer t.Stop()
		for {
			select {
			case <-jctx.Done():
				return
			case <-t.C:
				if ok, err := w.st.Extend(jctx, j.ID, wid, w.cfg.Lease); err == nil && !ok {
					log.Warn("lost lease; aborting")
					cancel()
					return
				}
			}
		}
	}()

	var err error
	switch j.Kind {
	case model.JobTranscode:
		err = w.transcode(jctx, j)
	case model.JobPurge:
		err = w.purge(jctx, j)
	default:
		err = permanent{fmt.Errorf("unknown job kind %q", j.Kind)}
	}
	if ctx.Err() != nil { // shutting down: leave the lease to expire and be reclaimed
		return
	}
	if err == nil {
		if e := w.st.Finish(ctx, j.ID, wid); e != nil {
			log.Error("finish failed", "err", e)
		}
		log.Info("job done")
		return
	}
	var perm permanent
	final := errors.As(err, &perm)
	log.Warn("job failed", "err", err, "final", final)
	dead, e := w.st.Fail(ctx, j.ID, wid, err.Error(), backoff(j.Attempts), final)
	if e != nil {
		log.Error("fail bookkeeping failed", "err", e)
		return
	}
	if dead && j.Kind == model.JobTranscode {
		reason := "We could not process this video."
		if final {
			reason = perm.Error()
		}
		if e := w.st.SetFailed(ctx, j.VideoID, reason); e != nil {
			log.Error("mark video failed", "err", e)
		}
	}
}

func (w *Worker) transcode(ctx context.Context, j *model.Job) error {
	v, err := w.st.Get(ctx, j.VideoID)
	if err != nil {
		if errors.Is(err, model.ErrNotFound) {
			return nil
		}
		return err
	}
	if v.Status != model.StatusProcessing { // removed meanwhile, or already done
		return nil
	}
	dir, err := os.MkdirTemp("", "fyber-tc-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)

	src := filepath.Join(dir, "src.bin")
	f, err := os.OpenFile(src, os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	err = w.obj.Download(ctx, w.cfg.OriginalsBucket, v.SrcKey, f, v.SrcBytes)
	f.Close()
	if err != nil {
		return err
	}
	head := make([]byte, 16)
	rf, _ := os.Open(src)
	n, _ := io.ReadFull(rf, head)
	rf.Close()
	demux := media.Sniff(head[:n])
	if demux == "" {
		return permanent{errors.New("This file is not a supported video (use MP4, MOV or WebM).")}
	}
	info, err := media.Probe(ctx, src, demux, v.Kind)
	if err != nil {
		return permanent{fmt.Errorf("Video rejected: %v.", err)}
	}
	rs := media.PlanRenditions(info.Width, info.Height)
	out := filepath.Join(dir, "out")
	if err := os.MkdirAll(out, 0o700); err != nil {
		return err
	}
	if err := media.Transcode(ctx, src, demux, out, info, rs); err != nil {
		return err
	}

	prefix := "v/" + v.ID + "/"
	keys, err := w.uploadTree(ctx, out, prefix)
	if err != nil {
		return err
	}
	res := model.Result{DurationMS: info.DurationMS, Width: rs[0].W, Height: rs[0].H,
		HLSKey: prefix + "master.m3u8", ThumbKey: prefix + "thumb.jpg", MediaKeys: keys}
	if err := w.st.SetReady(ctx, v.ID, res); err != nil {
		if errors.Is(err, model.ErrConflict) { // removed while we worked: clean our output
			for _, k := range keys {
				_ = w.obj.Delete(ctx, w.cfg.MediaBucket, k)
			}
			return nil
		}
		return err
	}
	return nil
}

func contentType(name string) string {
	switch strings.ToLower(filepath.Ext(name)) {
	case ".m3u8":
		return "application/vnd.apple.mpegurl"
	case ".ts":
		return "video/mp2t"
	case ".jpg":
		return "image/jpeg"
	}
	return "application/octet-stream"
}

// uploadTree uploads every file under root to prefix+relpath (8 at a time), playlists last
// so a player never sees a playlist whose segments are missing.
func (w *Worker) uploadTree(ctx context.Context, root, prefix string) ([]string, error) {
	var files []string
	err := filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			rel, _ := filepath.Rel(root, p)
			files = append(files, filepath.ToSlash(rel))
		}
		return err
	})
	if err != nil {
		return nil, err
	}
	sort.Strings(files)
	var data, sub, master []string
	for _, f := range files {
		switch {
		case f == "master.m3u8":
			master = append(master, f)
		case strings.HasSuffix(f, ".m3u8"):
			sub = append(sub, f)
		default:
			data = append(data, f)
		}
	}
	put := func(batch []string) error {
		sem := make(chan struct{}, 8)
		var wg sync.WaitGroup
		var mu sync.Mutex
		var first error
		for _, rel := range batch {
			sem <- struct{}{}
			wg.Add(1)
			go func(rel string) {
				defer func() { <-sem; wg.Done() }()
				if err := w.obj.UploadFile(ctx, w.cfg.MediaBucket, prefix+rel, contentType(rel), filepath.Join(root, rel)); err != nil {
					mu.Lock()
					if first == nil {
						first = err
					}
					mu.Unlock()
				}
			}(rel)
		}
		wg.Wait()
		return first
	}
	// segments + thumbnail first, then rendition playlists, master playlist last
	for _, batch := range [][]string{data, sub, master} {
		if err := put(batch); err != nil {
			return nil, err
		}
	}
	keys := make([]string, 0, len(files))
	for _, f := range files {
		keys = append(keys, prefix+f)
	}
	return keys, nil
}

func (w *Worker) purge(ctx context.Context, j *model.Job) error {
	v, err := w.st.Get(ctx, j.VideoID)
	if err != nil {
		if errors.Is(err, model.ErrNotFound) {
			return nil
		}
		return err
	}
	if v.Status != model.StatusRemoved {
		return permanent{errors.New("refusing to purge a video that is not removed")}
	}
	if err := w.obj.Delete(ctx, w.cfg.OriginalsBucket, v.SrcKey); err != nil {
		return err
	}
	for _, k := range v.MediaKeys {
		if err := w.obj.Delete(ctx, w.cfg.MediaBucket, k); err != nil {
			return err
		}
	}
	return nil
}

var _ Objects = (*objstore.Store)(nil)
