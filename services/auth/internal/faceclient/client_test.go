package faceclient

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestClient(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer secret" {
			w.WriteHeader(401)
			return
		}
		switch r.URL.Path {
		case "/v1/challenges":
			r.ParseMultipartForm(1 << 20)
			if r.FormValue("purpose") != "verify" || r.FormValue("subject_ref") != "ref-1" {
				w.WriteHeader(422)
				return
			}
			w.Write([]byte(`{"challenge_id":"c1","steps":["center","turn_left","center","turn_right"],"expires_in":120}`))
		case "/v1/verify":
			r.ParseMultipartForm(1 << 20)
			n := len(r.MultipartForm.File["frames"])
			if r.FormValue("challenge_id") != "c1" || n != 2 {
				w.Write([]byte(`{"ok":false,"reason":"challenge_invalid"}`))
				return
			}
			w.Write([]byte(`{"ok":true,"reason":null}`))
		default:
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()

	c := New(srv.URL, "secret")
	ch, err := c.Challenge(context.Background(), "ref-1", "verify")
	if err != nil || ch.ID != "c1" || len(ch.Steps) != 4 {
		t.Fatalf("challenge: %v %+v", err, ch)
	}
	out, err := c.Verify(context.Background(), "ref-1", "c1", [][]byte{{1}, {2}})
	if err != nil || !out.OK {
		t.Fatalf("verify: %v %+v", err, out)
	}
	if _, err := New(srv.URL, "wrong").Challenge(context.Background(), "ref-1", "verify"); err == nil {
		t.Fatal("bad token must fail")
	}
}
