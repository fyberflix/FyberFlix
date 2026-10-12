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
