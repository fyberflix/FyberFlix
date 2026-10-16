// Package objstore talks to an S3-compatible bucket using pre-signed URLs only (no SDK).
// Browsers/apps upload with URLs signed for the PUBLIC endpoint; the server and worker use the
// INTERNAL endpoint (e.g. http://minio:9000) with the same mechanism.
package objstore

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/fyberflix/fyberflix/services/content/internal/s3sign"
)

var ErrNotFound = errors.New("object not found")

type Info struct {
	Size        int64
	ContentType string
}

type Store struct {
	Creds    s3sign.Creds
	Internal string // endpoint reachable from this process
	Public   string // endpoint reachable from users' devices
	HTTP     *http.Client
	Now      func() time.Time
}

func New(c s3sign.Creds, internal, public string) *Store {
	return &Store{Creds: c, Internal: internal, Public: public,
		HTTP: &http.Client{Timeout: 10 * time.Minute}, Now: time.Now}
}

// PresignPut returns the URL and the headers a client must send for a direct upload.
// Content-Type and Content-Length are signed, so the object must be exactly size bytes.
func (s *Store) PresignPut(bucket, key, contentType string, size int64, ttl time.Duration) (string, map[string]string, error) {
	signed := map[string]string{"content-type": contentType, "content-length": strconv.FormatInt(size, 10)}
	u, err := s.Creds.Presign(http.MethodPut, s.Public, bucket, key, ttl, s.Now(), signed)
	return u, map[string]string{"Content-Type": contentType}, err
}

func (s *Store) Head(ctx context.Context, bucket, key string) (Info, error) {
	u, err := s.Creds.Presign(http.MethodHead, s.Internal, bucket, key, 2*time.Minute, s.Now(), nil)
	if err != nil {
		return Info{}, err
	}
	req, _ := http.NewRequestWithContext(ctx, http.MethodHead, u, nil)
	res, err := s.HTTP.Do(req)
	if err != nil {
		return Info{}, err
	}
	defer res.Body.Close()
	switch res.StatusCode {
	case http.StatusOK:
		return Info{Size: res.ContentLength, ContentType: res.Header.Get("Content-Type")}, nil
	case http.StatusNotFound:
		return Info{}, ErrNotFound
	}
	return Info{}, fmt.Errorf("objstore head: HTTP %d", res.StatusCode)
}

func (s *Store) Delete(ctx context.Context, bucket, key string) error {
	u, err := s.Creds.Presign(http.MethodDelete, s.Internal, bucket, key, 2*time.Minute, s.Now(), nil)
	if err != nil {
		return err
	}
	req, _ := http.NewRequestWithContext(ctx, http.MethodDelete, u, nil)
	res, err := s.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode == http.StatusNoContent || res.StatusCode == http.StatusOK || res.StatusCode == http.StatusNotFound {
		return nil
	}
	return fmt.Errorf("objstore delete: HTTP %d", res.StatusCode)
}

// Download streams an object into w and fails if it is larger than max bytes.
func (s *Store) Download(ctx context.Context, bucket, key string, w io.Writer, max int64) error {
	u, err := s.Creds.Presign(http.MethodGet, s.Internal, bucket, key, 10*time.Minute, s.Now(), nil)
	if err != nil {
		return err
	}
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	res, err := s.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode == http.StatusNotFound {
		return ErrNotFound
	}
	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("objstore get: HTTP %d", res.StatusCode)
	}
	n, err := io.Copy(w, io.LimitReader(res.Body, max+1))
	if err != nil {
		return err
	}
	if n > max {
		return errors.New("objstore get: object larger than allowed")
	}
	return nil
}

// UploadFile uploads a local file with a signed content type and exact length.
func (s *Store) UploadFile(ctx context.Context, bucket, key, contentType, path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return err
	}
	signed := map[string]string{"content-type": contentType, "content-length": strconv.FormatInt(st.Size(), 10)}
	u, err := s.Creds.Presign(http.MethodPut, s.Internal, bucket, key, 10*time.Minute, s.Now(), signed)
	if err != nil {
		return err
	}
	req, _ := http.NewRequestWithContext(ctx, http.MethodPut, u, f)
	req.ContentLength = st.Size()
	req.Header.Set("Content-Type", contentType)
	res, err := s.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(res.Body, 300))
		return fmt.Errorf("objstore put %s: HTTP %d %s", key, res.StatusCode, b)
	}
	return nil
}
