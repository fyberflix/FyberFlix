package identity

import (
	"crypto/rand"
	"math/big"
	"strconv"
)

const (
	offerCount = 10
	// 100,000,000 - 109,999,999 is reserved for ZEAIPC staff/system accounts.
	staffBlockEnd = 109_999_999
	minNumber     = 100_000_000
	maxNumber     = 999_999_999
)

// IsVanity reports numbers that look "special" (4+ repeated digits, or 5+
// ascending/descending run). They are withheld from random offers so they can
// be allocated deliberately later.
func IsVanity(n string) bool {
	rep, up, down := 1, 1, 1
	for i := 1; i < len(n); i++ {
		d, p := n[i], n[i-1]
		if d == p {
			rep++
		} else {
			rep = 1
		}
		if d == p+1 {
			up++
		} else {
			up = 1
		}
		if d+1 == p {
			down++
		} else {
			down = 1
		}
		if rep >= 4 || up >= 5 || down >= 5 {
			return true
		}
	}
	return false
}

// RandomNumber returns a cryptographically random, eligible 9-digit number.
func RandomNumber() (string, error) {
	span := big.NewInt(maxNumber - staffBlockEnd)
	for {
		x, err := rand.Int(rand.Reader, span)
		if err != nil {
			return "", err
		}
		s := strconv.FormatInt(x.Int64()+staffBlockEnd+1, 10)
		if !IsVanity(s) {
			return s, nil
		}
	}
}

// Candidates returns n distinct random numbers (default 10).
func Candidates(n int) ([]string, error) {
	if n <= 0 {
		n = offerCount
	}
	seen := make(map[string]struct{}, n)
	out := make([]string, 0, n)
	for len(out) < n {
		s, err := RandomNumber()
		if err != nil {
			return nil, err
		}
		if _, dup := seen[s]; dup {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out, nil
}

func OfferCount() int { return offerCount }
