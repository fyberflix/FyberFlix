// Package mailer sends verification emails.
package mailer

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/mail"
	"net/smtp"
	"strings"
	"time"
)

// Log prints the code instead of sending it. Development only (config refuses it in production).
type Log struct{ L *slog.Logger }

func (m Log) SendOTP(_ context.Context, to, code string, _ time.Duration) error {
	m.L.Warn("DEV MAIL (not sent)", "to", to, "code", code)
	return nil
}

func (m Log) SendNotice(_ context.Context, to, subject, body string) error {
	m.L.Warn("DEV MAIL (not sent)", "to", to, "subject", subject, "body", body)
	return nil
}
type SMTP struct {
	Host, User, Pass, From string
	Port                   int
}

func (m SMTP) SendOTP(ctx context.Context, to, code string, ttl time.Duration) error {
	msg, err := BuildMessage(m.From, to, code, ttl)
	if err != nil {
		return err
	}
	return m.deliver(ctx, to, msg)
}

// SendNotice sends a plain security notice (recovery requested, cancelled, completed ...).
func (m SMTP) SendNotice(ctx context.Context, to, subject, body string) error {
	msg, err := BuildNotice(m.From, to, subject, body)
	if err != nil {
		return err
	}
	return m.deliver(ctx, to, msg)
}

func (m SMTP) deliver(ctx context.Context, to string, msg []byte) error {
	addr := net.JoinHostPort(m.Host, fmt.Sprint(m.Port))
	d := net.Dialer{Timeout: 10 * time.Second}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return err
	}
	_ = conn.SetDeadline(time.Now().Add(25 * time.Second))
	c, err := smtp.NewClient(conn, m.Host)
	if err != nil {
		conn.Close()
		return err
	}
	defer c.Close()
	if ok, _ := c.Extension("STARTTLS"); ok {
		if err := c.StartTLS(&tls.Config{ServerName: m.Host, MinVersion: tls.VersionTLS12}); err != nil {
			return err
		}
	} else if m.Host != "localhost" && m.Host != "127.0.0.1" {
		return errors.New("smtp server does not offer STARTTLS; refusing to send in clear text")
	}
	if m.User != "" {
		if err := c.Auth(smtp.PlainAuth("", m.User, m.Pass, m.Host)); err != nil {
			return err
		}
	}
	from, _ := mail.ParseAddress(m.From)
	if from == nil {
		return errors.New("invalid SMTP_FROM")
	}
	if err := c.Mail(from.Address); err != nil {
		return err
	}
	if err := c.Rcpt(to); err != nil {
		return err
	}
	w, err := c.Data()
	if err != nil {
		return err
	}
	if _, err := w.Write(msg); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	return c.Quit()
}

// BuildMessage builds the RFC 5322 message. It refuses anything that could inject headers.
func BuildMessage(from, to, code string, ttl time.Duration) ([]byte, error) {
	for _, v := range []string{from, to, code} {
		if strings.ContainsAny(v, "\r\n") {
			return nil, errors.New("illegal characters in mail field")
		}
	}
	if a, err := mail.ParseAddress(to); err != nil || a.Address != to {
		return nil, errors.New("invalid recipient")
	}
	body := fmt.Sprintf("Your FyberFlix verification code is %s\r\n\r\n"+
		"It expires in %d minutes. If you did not ask for it, ignore this email.\r\n"+
		"Never share this code with anyone, including ZEAIPC staff.\r\n\r\n"+
		"ZEAIPC - Zikr-e-Ameen Innovations & Programming Corporation\r\n", code, int(ttl.Minutes()))
	h := "From: " + from + "\r\nTo: " + to + "\r\nSubject: Your FyberFlix verification code\r\n" +
		"Date: " + time.Now().UTC().Format(time.RFC1123Z) + "\r\n" +
		"MIME-Version: 1.0\r\nContent-Type: text/plain; charset=UTF-8\r\n\r\n"
	return []byte(h + body), nil
}
// BuildNotice builds a plain-text notice. Subject and body may not contain header-breaking characters.
func BuildNotice(from, to, subject, body string) ([]byte, error) {
	for _, v := range []string{from, to, subject} {
		if strings.ContainsAny(v, "\r\n") {
			return nil, errors.New("illegal characters in mail field")
		}
	}
	if a, err := mail.ParseAddress(to); err != nil || a.Address != to {
		return nil, errors.New("invalid recipient")
	}
	body = strings.ReplaceAll(strings.ReplaceAll(body, "\r\n", "\n"), "\n", "\r\n")
	h := "From: " + from + "\r\nTo: " + to + "\r\nSubject: " + subject + "\r\n" +
		"Date: " + time.Now().UTC().Format(time.RFC1123Z) + "\r\n" +
		"MIME-Version: 1.0\r\nContent-Type: text/plain; charset=UTF-8\r\n\r\n"
	return []byte(h + body + "\r\n\r\nZEAIPC - Zikr-e-Ameen Innovations & Programming Corporation\r\n"), nil
}
