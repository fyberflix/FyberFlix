// Package identity holds the pure rules for FyberFlix identities:
// Fyber Cable names (channel name / URL slug) and FyberFlix Numbers.
package identity

import (
	"errors"
	"strings"
	"unicode"
)

var (
	ErrLength    = errors.New("name must be 3-30 characters")
	ErrChars     = errors.New("only letters, digits, '.', '_' and '-' are allowed")
	ErrEdges     = errors.New("name must start and end with a letter or digit, without repeated separators")
	ErrAllDigits = errors.New("name must contain at least one letter")
	ErrReserved  = errors.New("this name is reserved")
)

// Brand tokens: any name CONTAINING these (after confusable folding) is blocked,
// so nobody can register "zeaipc-support" or "z3aipc_official".
var brandTokens = []string{"zeaipc", "zikriyon", "fyberflix", "fybercable", "zikreameen"}

// Names reserved exactly (after folding). Extend freely; this is the one list.
var reservedExact = []string{
	"zeaipc", "zikriyon", "zikriyonos", "zikriyonai", "fyberflix", "fybercable", "fyber", "cable",
	// platform / routing
	"admin", "administrator", "root", "system", "support", "help", "helpdesk", "staff", "official",
	"security", "abuse", "trust", "safety", "moderator", "mod", "legal", "dmca", "privacy", "terms",
	"billing", "payments", "press", "media", "careers", "jobs", "contact", "about", "team", "founder",
	"api", "app", "apps", "www", "web", "mail", "email", "cdn", "static", "assets", "status", "docs",
	"developer", "developers", "dev", "login", "logout", "signin", "signup", "register", "auth",
	"account", "accounts", "settings", "profile", "channel", "channels", "user", "users", "me", "null",
	"undefined", "anonymous", "everyone", "all", "home", "feed", "explore", "search", "trending",
	"watch", "video", "videos", "shorts", "reels", "stories", "live", "inbox", "messages", "chat",
	"call", "calls", "notifications", "upload", "studio", "ads", "monetization", "premium", "verified",
	"verify", "report", "reports", "community", "guidelines", "policy", "policies", "cookies",
	"robots", "sitemap", "favicon", "health", "metrics", "internal", "console", "dashboard",
	"armanansari", "arman",
}

var confusables = map[rune]rune{'0': 'o', '1': 'l', '3': 'e', '4': 'a', '5': 's', '7': 't', '8': 'b', '@': 'a', '$': 's', 'i': 'l'}

// Skeleton folds a key so look-alikes collapse ("Z3A1PC" and "zeaipc" match).
func Skeleton(key string) string {
	var b strings.Builder
	for _, r := range key {
		switch r {
		case '.', '_', '-':
			continue
		}
		if m, ok := confusables[r]; ok {
			r = m
		}
		b.WriteRune(r)
	}
	return b.String()
}

var reservedSkeletons = func() map[string]struct{} {
	m := make(map[string]struct{}, len(reservedExact))
	for _, n := range reservedExact {
		m[Skeleton(n)] = struct{}{}
	}
	return m
}()

var brandSkeletons = func() []string {
	out := make([]string, len(brandTokens))
	for i, t := range brandTokens {
		out[i] = Skeleton(t)
	}
	return out
}()

// ParseCableName validates a user-supplied Fyber Cable name and returns the
// display form (as typed) and the unique lowercase key.
func ParseCableName(raw string) (display, key string, err error) {
	display = strings.TrimSpace(raw)
	if len(display) < 3 || len(display) > 30 { // ASCII-only, so bytes == chars
		return "", "", ErrLength
	}
	hasLetter := false
	var prev rune
	for i, r := range display {
		isAlpha := r < unicode.MaxASCII && unicode.IsLetter(r) // non-ASCII is rejected
		isDigit := r >= '0' && r <= '9'
		isSep := r == '.' || r == '_' || r == '-'
		if !isAlpha && !isDigit && !isSep {
			return "", "", ErrChars
		}
		if isSep && (i == 0 || prev == '.' || prev == '_' || prev == '-') {
			return "", "", ErrEdges
		}
		hasLetter = hasLetter || isAlpha
		prev = r
	}
	if prev == '.' || prev == '_' || prev == '-' {
		return "", "", ErrEdges
	}
	// All-digit names would collide with /{FyberFlix number} URLs.
	if !hasLetter {
		return "", "", ErrAllDigits
	}
	key = strings.ToLower(display)
	sk := Skeleton(key)
	if _, bad := reservedSkeletons[sk]; bad {
		return "", "", ErrReserved
	}
	for _, t := range brandSkeletons {
		if strings.Contains(sk, t) {
			return "", "", ErrReserved
		}
	}
	return display, key, nil
}
