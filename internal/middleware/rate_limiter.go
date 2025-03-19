package middleware

import (
	"sync"
	"time"
)

// RateLimiter implements a token bucket rate limiting algorithm.
type RateLimiter struct {
	rate       float64    // Number of tokens to add per second
	capacity   float64    // Maximum number of tokens that can be stored
	tokens     float64    // Current number of available tokens
	lastUpdate time.Time  // Timestamp of the last token update
	mu         sync.Mutex // Mutex to protect concurrent access
}

// NewRateLimiter creates a new RateLimiter instance.
func NewRateLimiter(rate int) *RateLimiter {
	return &RateLimiter{
		rate:       float64(rate),
		capacity:   float64(rate),
		tokens:     float64(rate),
		lastUpdate: time.Now(),
	}
}

// Allow checks if a request is allowed based on the rate limit.
func (rl *RateLimiter) Allow() bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	elapsed := now.Sub(rl.lastUpdate).Seconds()
	rl.lastUpdate = now

	// Add tokens based on the elapsed time
	rl.tokens += elapsed * rl.rate

	// Cap tokens at the maximum capacity
	if rl.tokens > rl.capacity {
		rl.tokens = rl.capacity
	}

	if rl.tokens >= 1.0 {
		rl.tokens -= 1.0 // Consume a token
		return true
	}

	return false // Not enough tokens available
}
