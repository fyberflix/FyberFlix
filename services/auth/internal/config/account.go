package config

import (
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"strconv"
)

// Account holds settings for email OTP, mail delivery and the environment.
type Account struct {
	AppEnv    string // "production" refuses MAIL_MODE=log
	MailMode  string // "smtp" | "log" (log prints codes: development only)
	SMTPHost  string
	SMTPPort  int
	SMTPUser  string
	SMTPPass  string
	SMTPFrom  string
	OTPPepper []byte // 32 bytes; HMAC key for email codes
}

func LoadAccount() (Account, error) {
	a := Account{
		AppEnv:   env("APP_ENV", "development"),
		MailMode: env("MAIL_MODE", "log"),
		SMTPHost: os.Getenv("SMTP_HOST"),
		SMTPUser: os.Getenv("SMTP_USER"),
		SMTPPass: os.Getenv("SMTP_PASS"),
		SMTPFrom: os.Getenv("SMTP_FROM"),
	}
	port, err := strconv.Atoi(env("SMTP_PORT", "587"))
	if err != nil {
		return a, errors.New("SMTP_PORT must be a number")
	}
	a.SMTPPort = port
	pepper, err := base64.StdEncoding.DecodeString(os.Getenv("OTP_PEPPER"))
	if err != nil || len(pepper) != 32 {
		return a, errors.New("OTP_PEPPER must be base64 of 32 bytes")
	}
	a.OTPPepper = pepper
	switch a.MailMode {
	case "log":
		if a.AppEnv == "production" {
			return a, errors.New("MAIL_MODE=log is not allowed when APP_ENV=production")
		}
	case "smtp":
		if a.SMTPHost == "" || a.SMTPFrom == "" {
			return a, errors.New("SMTP_HOST and SMTP_FROM are required for MAIL_MODE=smtp")
		}
	default:
		return a, fmt.Errorf("unknown MAIL_MODE %q", a.MailMode)
	}
	return a, nil
}
