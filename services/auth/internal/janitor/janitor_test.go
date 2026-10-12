package janitor

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"
)

type fakeStore struct {
	stale   []StaleSignup
	due     []DueUser
	deleted []string
	purged  []string
}

func (f *fakeStore) CleanupExpired(context.Context) error { return nil }
func (f *fakeStore) StaleSignups(context.Context, int) ([]StaleSignup, error) {
	return f.stale, nil
}
func (f *fakeStore) DeleteStaleSignup(_ context.Context, s StaleSignup) error {
	f.deleted = append(f.deleted, s.FaceRef)
	return nil
}
func (f *fakeStore) DueDeletions(context.Context, int) ([]DueUser, error) { return f.due, nil }
func (f *fakeStore) PurgeUser(_ context.Context, id string) error {
	f.purged = append(f.purged, id)
	return nil
}

type fakeFace struct {
	fail  map[string]bool
	erase []string
}

func (f *fakeFace) Delete(_ context.Context, ref string) error {
	if f.fail[ref] {
		return errors.New("face down")
	}
	f.erase = append(f.erase, ref)
	return nil
}

func TestRunOnce(t *testing.T) {
	st := &fakeStore{
		stale: []StaleSignup{{FaceRef: "enrolled-ok", Enrolled: true}, {FaceRef: "never-enrolled"}, {FaceRef: "enrolled-fail", Enrolled: true}},
		due:   []DueUser{{"u1", "face-u1"}, {"u2", "face-u2"}},
	}
	face := &fakeFace{fail: map[string]bool{"enrolled-fail": true, "face-u2": true}}
	RunOnce(context.Background(), st, face, slog.New(slog.NewTextHandler(io.Discard, nil)))

	// stale: enrolled-ok and never-enrolled are deleted; enrolled-fail is kept for retry
	if len(st.deleted) != 2 || st.deleted[0] != "enrolled-ok" || st.deleted[1] != "never-enrolled" {
		t.Fatalf("stale deleted = %v", st.deleted)
	}
	// never call face-service for sessions that never enrolled
	for _, r := range face.erase {
		if r == "never-enrolled" {
			t.Fatal("face erase called for a never-enrolled signup")
		}
	}
	// due: u1 purged; u2 NOT purged because its biometric erase failed
	if len(st.purged) != 1 || st.purged[0] != "u1" {
		t.Fatalf("purged = %v", st.purged)
	}
}
