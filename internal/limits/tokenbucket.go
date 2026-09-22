package limits

import (
	"math"
	"sync"
	"time"
)

// TokenBucket implements a thread-safe token bucket rate limiter.
type TokenBucket struct {
	mu         sync.Mutex
	rate       float64   // tokens added per second
	capacity   float64   // maximum tokens bucket can hold
	tokens     float64   // current token count
	lastRefill time.Time // last time tokens were replenished
}

// NewTokenBucket creates a new TokenBucket initialized to capacity.
func NewTokenBucket(rate float64, burst int64) *TokenBucket {
	if burst <= 0 {
		burst = 1
	}
	if rate <= 0 {
		rate = 1.0
	}
	cap := float64(burst)
	return &TokenBucket{
		rate:       rate,
		capacity:   cap,
		tokens:     cap,
		lastRefill: time.Now(),
	}
}

// Allow consumes 1 token if available, returning whether permitted and the retry-after duration if denied.
func (tb *TokenBucket) Allow() (bool, time.Duration) {
	return tb.AllowN(time.Now(), 1)
}

// AllowN consumes n tokens if available at time now.
func (tb *TokenBucket) AllowN(now time.Time, n int64) (bool, time.Duration) {
	tb.mu.Lock()
	defer tb.mu.Unlock()

	tb.refill(now)

	needed := float64(n)
	if tb.tokens >= needed {
		tb.tokens -= needed
		return true, 0
	}

	// Calculate wait time until enough tokens are replenished
	missing := needed - tb.tokens
	waitSeconds := missing / tb.rate
	retryAfter := time.Duration(math.Ceil(waitSeconds)) * time.Second
	if retryAfter < 1*time.Second {
		retryAfter = 1 * time.Second
	}

	return false, retryAfter
}

func (tb *TokenBucket) refill(now time.Time) {
	elapsed := now.Sub(tb.lastRefill).Seconds()
	if elapsed <= 0 {
		return
	}

	tb.tokens = math.Min(tb.capacity, tb.tokens+elapsed*tb.rate)
	tb.lastRefill = now
}
