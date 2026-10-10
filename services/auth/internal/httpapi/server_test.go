package httpapi

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type fake struct {
	state string
	held  map[string]bool
	taken map[string]bool
}

func (f *fake) CreateSession(context.Context, []byte, string, string, time.Time) error {
	f.state = "started"
	return nil
}
func (f *fake) RequireState(_ context.Context, _ []byte, a ...string) error {
	for _, s := range a {
		if s == f.state {
			return nil
		}
	}
	return ErrWrongState
}
func (f *fake) HoldNumbers(_ context.Context, _ []byte, c []string, _ time.Time) ([]string, error) {
	for _, n := range c {
		f.held[n] = true
	}
	return c, nil
}
func (f *fake) ReleaseForRefresh(context.Context, []byte, int) error { return nil }
func (f *fake) SelectNumber(_ context.Context, _ []byte, n string, _ time.Time) error {
	if !f.held[n] {
		return ErrNotHeld
	}
	f.state = "number_selected"
	return nil
}
func (f *fake) CableNameTaken(_ context.Context, k string) (bool, error) { return f.taken[k], nil }
func (f *fake) SetCableName(context.Context, []byte, string) error       { f.state = "name_chosen"; return nil }

func TestSignupFlow(t *testing.T) {
	f := &fake{held: map[string]bool{}, taken: map[string]bool{"taken_one": true}}
	srv := httptest.NewServer(New(f, Config{SessionTTL: time.Minute, HoldTTL: time.Minute, MaxRefresh: 5},
		slog.New(slog.NewTextHandler(io.Discard, nil))).Handler())
	defer srv.Close()

	do := func(method, path, tok, body string) (int, map[string]any) {
		req, _ := http.NewRequest(method, srv.URL+path, strings.NewReader(body))
		if tok != "" {
			req.Header.Set("Authorization", "Bearer "+tok)
		}
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		var m map[string]any
		_ = json.NewDecoder(res.Body).Decode(&m)
		return res.StatusCode, m
	}

	code, m := do("POST", "/v1/signup/sessions", "", "")
	if code != 201 {
		t.Fatal(code, m)
	}
	tok := m["session_token"].(string)
	offers := m["number_offers"].([]any)
	if len(offers) != 10 {
		t.Fatalf("want 10 offers, got %d", len(offers))
	}
	if c, _ := do("POST", "/v1/signup/number", tok, `{"number":"123123123"}`); c != 409 {
		t.Fatalf("unoffered number must be rejected, got %d", c)
	}
	if c, _ := do("POST", "/v1/signup/number", tok, `{"number":"`+offers[3].(string)+`"}`); c != 200 {
		t.Fatalf("select failed %d", c)
	}
	if c, _ := do("POST", "/v1/signup/number-offers/refresh", tok, ""); c != 409 {
		t.Fatalf("refresh after selection must fail, got %d", c)
	}
	if _, m := do("GET", "/v1/signup/cable-name/check?name=ZEAIPC", tok, ""); m["available"] != false {
		t.Fatal("reserved name must be unavailable")
	}
	if c, _ := do("POST", "/v1/signup/cable-name", tok, `{"name":"Taken_One"}`); c != 409 {
		t.Fatalf("taken name must 409, got %d", c)
	}
	if c, m := do("POST", "/v1/signup/cable-name", tok, `{"name":"Arman_Films"}`); c != 200 {
		t.Fatal(c, m)
	}
	if c, _ := do("GET", "/v1/signup/cable-name/check?name=x", "", ""); c != 401 {
		t.Fatalf("missing token must 401, got %d", c)
	}
}
