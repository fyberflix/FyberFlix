// Package api is the HTTP layer of the content service.
package api

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/fyberflix/fyberflix/libs/authz"
	"github.com/fyberflix/fyberflix/services/content/internal/model"
	"github.com/fyberflix/fyberflix/services/content/internal/objstore"
)

// Store is what the API needs from the database.
type Store interface {
	CountInitsSince(ctx context.Context, owner string, since time.Time) (int, error)
	CountAwaiting(ctx context.Context, owner string) (int, error)
	Create(ctx context.Context, v *model.Video) error
	Get(ctx context.Context, id string) (model.Video, error)
	// StartProcessing moves awaiting_upload -> processing and queues the transcode job atomically.
	StartProcessing(ctx context.Context, id, owner string, size int64) error
	ListByOwner(ctx context.Context, owner string, readyOnlyPublic bool, limit int, after *model.Cursor) ([]model.Video, error)
	// Remove soft-deletes the video and queues a purge job.
	Remove(ctx context.Context, id, owner string) error
	Ping(ctx context.Context) error
}

// Objects is what the API needs from object storage.
type Objects interface {
	PresignPut(bucket, key, contentType string, size int64, ttl time.Duration) (string, map[string]string, error)
	Head(ctx context.Context, bucket, key string) (objstore.Info, error)
}

type Authenticator interface {
	Verify(ctx context.Context, tok string) (authz.Claims, error)
}

type Config struct {
	OriginalsBucket string
	MaxUploadBytes  int64
	UploadURLTTL    time.Duration
	MediaBaseURL    string
}

type Server struct {
	cfg   Config
	st    Store
	obj   Objects
	auth  Authenticator
	now   func() time.Time
	newID func() string
}

func New(cfg Config, st Store, obj Objects, auth Authenticator, newID func() string) *Server {
	return &Server{cfg: cfg, st: st, obj: obj, auth: auth, now: time.Now, newID: newID}
}

const (
	maxCaption      = 2200
	initsPerHour    = 30
	maxAwaiting     = 5
	maxBodyBytes    = 16 << 10
	defaultPageSize = 20
	maxPageSize     = 50
)

var allowedTypes = map[string]string{"video/mp4": "mp4", "video/quicktime": "mp4", "video/webm": "webm"}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.healthz)
	mux.Handle("POST /v1/videos", s.require(http.HandlerFunc(s.initUpload)))
	mux.Handle("POST /v1/videos/{id}/complete", s.require(http.HandlerFunc(s.complete)))
	mux.Handle("DELETE /v1/videos/{id}", s.require(http.HandlerFunc(s.remove)))
	mux.Handle("GET /v1/me/videos", s.require(http.HandlerFunc(s.listMine)))
	mux.Handle("GET /v1/videos/{id}", s.optional(http.HandlerFunc(s.getVideo)))
	mux.HandleFunc("GET /v1/users/{owner}/videos", s.listPublic)
	return secure(mux)
}

func secure(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}

// ---------- auth helpers ----------

func bearer(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if len(h) > 7 && strings.EqualFold(h[:7], "bearer ") {
		return strings.TrimSpace(h[7:])
	}
	return ""
}

type ctxUser struct{}

func (s *Server) require(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := s.auth.Verify(r.Context(), bearer(r))
		if err != nil || c.Sub == "" {
			writeErr(w, 401, "unauthorized", "Sign in required.")
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), ctxUser{}, c.Sub)))
	})
}

// optional attaches the user when a valid token is present; anonymous otherwise.
func (s *Server) optional(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if t := bearer(r); t != "" {
			if c, err := s.auth.Verify(r.Context(), t); err == nil && c.Sub != "" {
				r = r.WithContext(context.WithValue(r.Context(), ctxUser{}, c.Sub))
			}
		}
		next.ServeHTTP(w, r)
	})
}

func user(r *http.Request) string { s, _ := r.Context().Value(ctxUser{}).(string); return s }

// ---------- JSON helpers ----------

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, code int, c, msg string) {
	writeJSON(w, code, map[string]any{"error": map[string]string{"code": c, "message": msg}})
}

func decode(w http.ResponseWriter, r *http.Request, dst any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		writeErr(w, 400, "bad_request", "Invalid request body.")
		return false
	}
	return true
}

func (s *Server) fail(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, model.ErrNotFound):
		writeErr(w, 404, "not_found", "Not found.")
	case errors.Is(err, model.ErrConflict):
		writeErr(w, 409, "conflict", "This video is not in a state that allows that.")
	default:
		slog.Error("request failed", "path", r.URL.Path, "err", err)
		writeErr(w, 500, "internal", "Something went wrong.")
	}
}

func isUUID(s string) bool {
	if len(s) != 36 {
		return false
	}
	for i, c := range s {
		switch {
		case i == 8 || i == 13 || i == 18 || i == 23:
			if c != '-' {
				return false
			}
		case !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F'):
			return false
		}
	}
	return true
}

// ---------- views ----------

type videoView struct {
	ID          string     `json:"id"`
	OwnerID     string     `json:"owner_id"`
	Kind        string     `json:"kind"`
	Status      string     `json:"status"`
	Caption     string     `json:"caption"`
	Visibility  string     `json:"visibility"`
	DurationMS  int        `json:"duration_ms,omitempty"`
	Width       int        `json:"width,omitempty"`
	Height      int        `json:"height,omitempty"`
	HLSURL      string     `json:"hls_url,omitempty"`
	ThumbURL    string     `json:"thumb_url,omitempty"`
	FailReason  string     `json:"fail_reason,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`
	PublishedAt *time.Time `json:"published_at,omitempty"`
}

func (s *Server) view(v model.Video, owner bool) videoView {
	o := videoView{ID: v.ID, OwnerID: v.OwnerID, Kind: v.Kind, Status: v.Status, Caption: v.Caption,
		Visibility: v.Visibility, DurationMS: v.DurationMS, Width: v.Width, Height: v.Height,
		CreatedAt: v.CreatedAt, PublishedAt: v.PublishedAt}
	if v.Status == model.StatusReady {
		o.HLSURL = s.cfg.MediaBaseURL + "/" + v.HLSKey
		o.ThumbURL = s.cfg.MediaBaseURL + "/" + v.ThumbKey
	}
	if owner {
		o.FailReason = v.FailReason
	}
	return o
}

// ---------- handlers ----------

func (s *Server) healthz(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	if err := s.st.Ping(ctx); err != nil {
		writeErr(w, 503, "unavailable", "Database unreachable.")
		return
	}
	writeJSON(w, 200, map[string]string{"status": "ok"})
}

type initReq struct {
	Kind        string `json:"kind"`
	Caption     string `json:"caption"`
	Visibility  string `json:"visibility"`
	ContentType string `json:"content_type"`
	Size        int64  `json:"size"`
}

func (s *Server) initUpload(w http.ResponseWriter, r *http.Request) {
	var in initReq
	if !decode(w, r, &in) {
		return
	}
	if in.Visibility == "" {
		in.Visibility = model.VisPublic
	}
	if in.Kind == "" {
		in.Kind = model.KindReel
	}
	ext, okType := allowedTypes[in.ContentType]
	switch {
	case in.Kind != model.KindReel && in.Kind != model.KindVideo:
		writeErr(w, 400, "bad_kind", "kind must be reel or video.")
	case in.Visibility != model.VisPublic && in.Visibility != model.VisUnlisted && in.Visibility != model.VisPrivate:
		writeErr(w, 400, "bad_visibility", "visibility must be public, unlisted or private.")
	case !okType:
		writeErr(w, 400, "bad_content_type", "Only MP4, MOV or WebM videos are allowed.")
	case in.Size < 1 || in.Size > s.cfg.MaxUploadBytes:
		writeErr(w, 400, "bad_size", fmt.Sprintf("File must be between 1 byte and %d MB.", s.cfg.MaxUploadBytes>>20))
	case utf8.RuneCountInString(in.Caption) > maxCaption:
		writeErr(w, 400, "bad_caption", "Caption is too long.")
	default:
		s.createUpload(w, r, in, ext)
	}
}

func (s *Server) createUpload(w http.ResponseWriter, r *http.Request, in initReq, ext string) {
	uid := user(r)
	n, err := s.st.CountInitsSince(r.Context(), uid, s.now().Add(-time.Hour))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if n >= initsPerHour {
		w.Header().Set("Retry-After", "600")
		writeErr(w, 429, "rate_limited", "Too many uploads. Try again later.")
		return
	}
	a, err := s.st.CountAwaiting(r.Context(), uid)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if a >= maxAwaiting {
		writeErr(w, 429, "too_many_pending", "Finish or wait for your pending uploads first.")
		return
	}
	id := s.newID()
	v := &model.Video{ID: id, OwnerID: uid, Kind: in.Kind, Status: model.StatusAwaitingUpload,
		Caption: strings.TrimSpace(in.Caption), Visibility: in.Visibility,
		SrcKey: "u/" + id + "/original." + ext, SrcContentType: in.ContentType, SrcBytes: in.Size}
	url, hdrs, err := s.obj.PresignPut(s.cfg.OriginalsBucket, v.SrcKey, in.ContentType, in.Size, s.cfg.UploadURLTTL)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if err := s.st.Create(r.Context(), v); err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, 201, map[string]any{
		"video_id": id,
		"upload":   map[string]any{"method": "PUT", "url": url, "headers": hdrs, "expires_in": int(s.cfg.UploadURLTTL.Seconds())},
	})
}

func (s *Server) complete(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !isUUID(id) {
		writeErr(w, 404, "not_found", "Not found.")
		return
	}
	v, err := s.st.Get(r.Context(), id)
	if err != nil || v.OwnerID != user(r) {
		s.fail(w, r, model.ErrNotFound)
		return
	}
	switch v.Status {
	case model.StatusProcessing, model.StatusReady:
		writeJSON(w, 202, map[string]string{"video_id": id, "status": v.Status}) // idempotent
		return
	case model.StatusAwaitingUpload:
	default:
		s.fail(w, r, model.ErrConflict)
		return
	}
	info, err := s.obj.Head(r.Context(), s.cfg.OriginalsBucket, v.SrcKey)
	if errors.Is(err, objstore.ErrNotFound) {
		writeErr(w, 409, "upload_missing", "The file has not been uploaded yet.")
		return
	}
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if info.Size != v.SrcBytes {
		writeErr(w, 409, "size_mismatch", "Uploaded size does not match what you declared.")
		return
	}
	if err := s.st.StartProcessing(r.Context(), id, v.OwnerID, info.Size); err != nil {
		if errors.Is(err, model.ErrConflict) { // raced with another complete call
			writeJSON(w, 202, map[string]string{"video_id": id, "status": model.StatusProcessing})
			return
		}
		s.fail(w, r, err)
		return
	}
	writeJSON(w, 202, map[string]string{"video_id": id, "status": model.StatusProcessing})
}

func (s *Server) getVideo(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !isUUID(id) {
		writeErr(w, 404, "not_found", "Not found.")
		return
	}
	v, err := s.st.Get(r.Context(), id)
	if err != nil || v.Status == model.StatusRemoved {
		s.fail(w, r, model.ErrNotFound)
		return
	}
	isOwner := user(r) != "" && user(r) == v.OwnerID
	if !isOwner && !(v.Status == model.StatusReady && v.Visibility != model.VisPrivate) {
		s.fail(w, r, model.ErrNotFound) // never reveal that private/unfinished videos exist
		return
	}
	writeJSON(w, 200, s.view(v, isOwner))
}

func (s *Server) remove(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !isUUID(id) {
		writeErr(w, 404, "not_found", "Not found.")
		return
	}
	if err := s.st.Remove(r.Context(), id, user(r)); err != nil {
		s.fail(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) listMine(w http.ResponseWriter, r *http.Request) { s.list(w, r, user(r), false) }

func (s *Server) listPublic(w http.ResponseWriter, r *http.Request) {
	owner := r.PathValue("owner")
	if !isUUID(owner) {
		writeErr(w, 404, "not_found", "Not found.")
		return
	}
	s.list(w, r, owner, true)
}

func (s *Server) list(w http.ResponseWriter, r *http.Request, owner string, public bool) {
	limit := defaultPageSize
	if q := r.URL.Query().Get("limit"); q != "" {
		n, err := strconv.Atoi(q)
		if err != nil || n < 1 || n > maxPageSize {
			writeErr(w, 400, "bad_limit", "limit must be 1..50.")
			return
		}
		limit = n
	}
	var cur *model.Cursor
	if c := r.URL.Query().Get("cursor"); c != "" {
		var err error
		if cur, err = DecodeCursor(c); err != nil {
			writeErr(w, 400, "bad_cursor", "Invalid cursor.")
			return
		}
	}
	rows, err := s.st.ListByOwner(r.Context(), owner, public, limit+1, cur)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	next := ""
	if len(rows) > limit {
		rows = rows[:limit]
		last := rows[len(rows)-1]
		at := last.CreatedAt
		if public && last.PublishedAt != nil {
			at = *last.PublishedAt
		}
		next = EncodeCursor(model.Cursor{At: at, ID: last.ID})
	}
	items := make([]videoView, 0, len(rows))
	for _, v := range rows {
		items = append(items, s.view(v, !public))
	}
	writeJSON(w, 200, map[string]any{"items": items, "next_cursor": next})
}

// EncodeCursor / DecodeCursor: opaque keyset cursor "unixMicro.id" in base64url.
func EncodeCursor(c model.Cursor) string {
	return base64.RawURLEncoding.EncodeToString([]byte(strconv.FormatInt(c.At.UnixMicro(), 10) + "." + c.ID))
}

func DecodeCursor(s string) (*model.Cursor, error) {
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return nil, err
	}
	p := strings.SplitN(string(b), ".", 2)
	if len(p) != 2 || !isUUID(p[1]) {
		return nil, errors.New("bad cursor")
	}
	us, err := strconv.ParseInt(p[0], 10, 64)
	if err != nil {
		return nil, err
	}
	return &model.Cursor{At: time.UnixMicro(us).UTC(), ID: p[1]}, nil
}
