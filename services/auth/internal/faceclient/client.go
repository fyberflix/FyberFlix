// Package faceclient talks to the internal face-service.
package faceclient

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"strings"
	"time"
)

var ErrUnavailable = errors.New("face service unavailable")

type Challenge struct {
	ID        string   `json:"challenge_id"`
	Steps     []string `json:"steps"`
	ExpiresIn int      `json:"expires_in"`
}

type Outcome struct {
	OK     bool   `json:"ok"`
	Reason string `json:"reason"`
}

type Client struct {
	base, token string
	hc          *http.Client
}

func New(base, token string) *Client {
	return &Client{base: strings.TrimRight(base, "/"), token: token,
		hc: &http.Client{Timeout: 25 * time.Second}}
}

func (c *Client) Challenge(ctx context.Context, ref, purpose string) (Challenge, error) {
	var out Challenge
	err := c.post(ctx, "/v1/challenges", map[string]string{"subject_ref": ref, "purpose": purpose}, nil, &out)
	return out, err
}

func (c *Client) Enroll(ctx context.Context, ref, challengeID string, frames [][]byte) (Outcome, error) {
	var out Outcome
	err := c.post(ctx, "/v1/enroll", map[string]string{"subject_ref": ref, "challenge_id": challengeID}, frames, &out)
	return out, err
}

func (c *Client) Verify(ctx context.Context, ref, challengeID string, frames [][]byte) (Outcome, error) {
	var out Outcome
	err := c.post(ctx, "/v1/verify", map[string]string{"subject_ref": ref, "challenge_id": challengeID}, frames, &out)
	return out, err
}

// Delete erases a face template (account deletion / DPDP erasure).
func (c *Client) Delete(ctx context.Context, ref string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, c.base+"/v1/templates/"+url.PathEscape(ref), nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	res, err := c.hc.Do(req)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("%w: status %d", ErrUnavailable, res.StatusCode)
	}
	return nil
}

func (c *Client) post(ctx context.Context, path string, fields map[string]string, frames [][]byte, out any) error {
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	for k, v := range fields {
		if err := mw.WriteField(k, v); err != nil {
			return err
		}
	}
	for i, f := range frames {
		w, err := mw.CreateFormFile("frames", fmt.Sprintf("f%02d.jpg", i))
		if err != nil {
			return err
		}
		if _, err = w.Write(f); err != nil {
			return err
		}
	}
	if err := mw.Close(); err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base+path, &buf)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", mw.FormDataContentType())
	req.Header.Set("Authorization", "Bearer "+c.token)
	res, err := c.hc.Do(req)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		io.Copy(io.Discard, io.LimitReader(res.Body, 4096))
		return fmt.Errorf("%w: status %d", ErrUnavailable, res.StatusCode)
	}
	return json.NewDecoder(io.LimitReader(res.Body, 64<<10)).Decode(out)
}
