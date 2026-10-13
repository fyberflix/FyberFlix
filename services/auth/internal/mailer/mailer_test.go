package mailer

import (
	"strings"
	"testing"
	"time"
)

func TestBuildMessage(t *testing.T) {
	b, err := BuildMessage("FyberFlix <no-reply@zeaipc.in>", "user@example.com", "123456", 10*time.Minute)
	if err != nil || !strings.Contains(string(b), "123456") || !strings.Contains(string(b), "10 minutes") {
		t.Fatalf("bad message: %v\n%s", err, b)
	}
	for _, to := range []string{"a@b.com\r\nBcc: evil@x.com", "Name <a@b.com>", "not-an-email", ""} {
		if _, err := BuildMessage("no-reply@zeaipc.in", to, "123456", time.Minute); err == nil {
			t.Errorf("recipient %q must be rejected", to)
		}
	}
	if _, err := BuildMessage("a@b.com\r\nX: y", "u@example.com", "1", time.Minute); err == nil {
		t.Error("header injection in From must be rejected")
	}
}
func TestBuildNotice(t *testing.T) {
	b, err := BuildNotice("FyberFlix <no-reply@zeaipc.in>", "user@example.com", "Recovery requested", "line one\nline two")
	if err != nil || !strings.Contains(string(b), "Subject: Recovery requested") || !strings.Contains(string(b), "line one\r\nline two") {
		t.Fatalf("bad notice: %v\n%s", err, b)
	}
	if _, err := BuildNotice("a@b.com", "u@example.com", "Hi\r\nBcc: x@y.com", "x"); err == nil {
		t.Error("header injection in subject must be rejected")
	}
	if _, err := BuildNotice("a@b.com", "not-an-email", "Hi", "x"); err == nil {
		t.Error("invalid recipient must be rejected")
	}
}
