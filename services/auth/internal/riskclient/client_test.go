package riskclient

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestEvaluate(t *testing.T) {
	var got map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer secret" {
			w.WriteHeader(401)
			return
		}
		_ = json.NewDecoder(r.Body).Decode(&got)
		_, _ = w.Write([]byte(`{"decision":"deny","rule_ids":["repeated_failed_logins"],"reasons":["x"],"degraded":false}`))
	}))
	defer srv.Close()

	v, err := New(srv.URL+"/", "secret").Evaluate(context.Background(), "login_fail",
		map[string]any{"auth": map[string]any{"failed_login_count": 1}}, "ip:1.2.3.4")
	if err != nil || v.Decision != Deny || v.RuleIDs[0] != "repeated_failed_logins" {
		t.Fatalf("verdict %+v err %v", v, err)
	}
	if got["spec"] != "login_fail" || got["subject_id"] != "ip:1.2.3.4" {
		t.Fatalf("request body %v", got)
	}
	if _, err = New(srv.URL, "wrong").Evaluate(context.Background(), "login_fail", nil, "x"); err == nil {
		t.Fatal("401 must be an error")
	}
}

func TestBadResponses(t *testing.T) {
	for name, body := range map[string]string{"junk": `nope`, "unknown": `{"decision":"maybe"}`} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(body)) }))
		if _, err := New(srv.URL, "s").Evaluate(context.Background(), "auth_risk", map[string]any{}, "x"); err == nil {
			t.Errorf("%s must be an error", name)
		}
		srv.Close()
	}
	if _, err := New("http://127.0.0.1:1", "s").Evaluate(context.Background(), "auth_risk", map[string]any{}, "x"); err == nil {
		t.Error("unreachable must be an error")
	}
}
