package gateway

import (
	"sync"
	"time"
)

type bucket struct {
	tokens float64
	last   time.Time
}

// limiter is a per-IP token bucket kept in memory. It is a coarse flood guard per gateway
// replica; the precise per-action limits live in the services themselves.
type limiter struct {
	mu    sync.Mutex
	rate  float64
	burst float64
	m     map[string]*bucket
	sweep time.Time
}

const maxTracked = 200_000

func newLimiter(rps float64, burst int) *limiter {
	return &limiter{rate: rps, burst: float64(burst), m: map[string]*bucket{}}
}

func (l *limiter) allow(key string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if now.Sub(l.sweep) > time.Minute || len(l.m) > maxTracked {
		for k, b := range l.m {
			if now.Sub(b.last) > time.Minute {
				delete(l.m, k)
			}
		}
		if len(l.m) > maxTracked { // flood from a huge number of addresses: start over, never block newcomers
			l.m = map[string]*bucket{}
		}
		l.sweep = now
	}
	b := l.m[key]
	if b == nil {
		b = &bucket{tokens: l.burst, last: now}
		l.m[key] = b
	}
	b.tokens += now.Sub(b.last).Seconds() * l.rate
	if b.tokens > l.burst {
		b.tokens = l.burst
	}
	b.last = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}
