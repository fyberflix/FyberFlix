// Package riskclient talks to risk-service (Python, zikriyon-prism) over internal HTTP.
package riskclient

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

type Decision string

const (
	Allow  Decision = "allow"
	StepUp Decision = "step_up"
	Deny   Decision = "deny"
)

type Verdict struct {
	Decision Decision `json:"decision"`
	RuleIDs  []string `json:"rule_ids"`
	Reasons  []string `json:"reasons"`
	Degraded bool     `json:"degraded"`
}

var ErrUnavailable = errors.New("risk service unavailable")

type Client struct {
	base, token string
	hc          *http.Client
}

// New uses a short timeout: risk is advisory and must never make login or signup hang.
func New(base, token string) *Client {
	return &Client{base: strings.TrimRight(base, "/"), token: token, hc: &http.Client{Timeout: 800 * time.Millisecond}}
}

func (c *Client) Evaluate(ctx context.Context, spec string, event map[string]any, subject string) (Verdict, error) {
	body, err := json.Marshal(map[string]any{"spec": spec, "event": event, "subject_id": subject})
	if err != nil {
		return Verdict{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base+"/v1/evaluate", bytes.NewReader(body))
	if err != nil {
		return Verdict{}, err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Content-Type", "application/json")
	res, err := c.hc.Do(req)
	if err != nil {
		return Verdict{}, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(res.Body, 4096))
		return Verdict{}, fmt.Errorf("%w: status %d", ErrUnavailable, res.StatusCode)
	}
	var v Verdict
	if err := json.NewDecoder(io.LimitReader(res.Body, 64<<10)).Decode(&v); err != nil {
		return Verdict{}, fmt.Errorf("%w: bad response", ErrUnavailable)
	}
	switch v.Decision {
	case Allow, StepUp, Deny:
		return v, nil
	}
	return Verdict{}, fmt.Errorf("%w: unknown decision %q", ErrUnavailable, v.Decision)
}
