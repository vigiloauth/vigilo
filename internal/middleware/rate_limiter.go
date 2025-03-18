package middleware

import (
	"sync"
	"time"
)

// RateLimiter implements a token bucket rate limiting algorithm.
type RateLimiter struct {
	rate       int        // Number of requests allowed per second.
	tokens     int        // Current number of available tokens.
	lastUpdate time.Time  // Timestamp of the last token update.
	mu         sync.Mutex // Mutex to protect concurrent access.
}

// NewRateLimiter creates a new RateLimiter instance.
//
// Parameters:
//
//	rate int: Number of requests allowed per second.
//
// Returns:
//
//	*RateLimiter: A new RateLimiter instance.
func NewRateLimiter(rate int) *RateLimiter {
	return &RateLimiter{
		rate:       rate,
		tokens:     rate,
		lastUpdate: time.Now(),
	}
}

// Allow checks if a request is allowed based on the rate limit.
//
// Returns:
//
//	bool: True if the request is allowed, false otherwise.
func (rl *RateLimiter) Allow() bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	elapsed := now.Sub(rl.lastUpdate).Seconds()
	rl.lastUpdate = now

	// Add tokens based on the elapsed time.
	rl.tokens += int(elapsed * float64(rl.rate))
	if rl.tokens > rl.rate {
		rl.tokens = rl.rate // Ensure tokens don't exceed the rate.
	}

	if rl.tokens > 0 {
		rl.tokens-- // Consume a token.
		return true
	}

	return false // No tokens available.
}
