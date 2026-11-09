// Package ratelimit limits login attempts: a fixed number of attempts per key
// (an IP, an email, both) in a sliding window, in memory.
//
//	limiter := ratelimit.New(5, time.Minute)         // 5 attempts a minute
//	ok, retry := limiter.Allow(ip + "|" + email)
//	if !ok { /* 429, Retry-After: retry */ }
//	limiter.Reset(ip + "|" + email)                  // after a successful login
//
// httpauth.LimitLogin wraps a login handler with it. For several instances
// implement Limiter on a shared store (Redis INCR with EXPIRE).
package ratelimit

import (
	"sync"
	"time"
)

// Limiter is what httpauth.LimitLogin uses.
type Limiter interface {
	// Allow records an attempt and reports whether it is within the limit;
	// if not, retryAfter is how long until the next attempt is allowed.
	Allow(key string) (ok bool, retryAfter time.Duration)
	// Reset forgets the attempts of key (after a successful login).
	Reset(key string)
}

// Memory is an in-process Limiter: a sliding window per key.
type Memory struct {
	mu     sync.Mutex
	max    int
	window time.Duration
	hits   map[string][]time.Time
	calls  int
	now    func() time.Time
}

// New allows max attempts per window and key.
func New(max int, window time.Duration) *Memory {
	if max < 1 {
		max = 1
	}
	return &Memory{max: max, window: window, hits: map[string][]time.Time{}, now: time.Now}
}

// WithClock replaces the clock (tests).
func (m *Memory) WithClock(now func() time.Time) *Memory { m.now = now; return m }

func (m *Memory) Allow(key string) (bool, time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.now()
	recent := m.recent(key, now)
	m.calls++
	if m.calls%1024 == 0 { // forget keys that went quiet
		for k := range m.hits {
			if len(m.recent(k, now)) == 0 {
				delete(m.hits, k)
			}
		}
	}
	if len(recent) >= m.max {
		return false, recent[0].Add(m.window).Sub(now)
	}
	m.hits[key] = append(recent, now)
	return true, 0
}

// recent drops the attempts of key older than the window.
func (m *Memory) recent(key string, now time.Time) []time.Time {
	list := m.hits[key]
	i := 0
	for i < len(list) && !list[i].After(now.Add(-m.window)) {
		i++
	}
	list = list[i:]
	m.hits[key] = list
	return list
}

func (m *Memory) Reset(key string) {
	m.mu.Lock()
	delete(m.hits, key)
	m.mu.Unlock()
}

var _ Limiter = (*Memory)(nil)
