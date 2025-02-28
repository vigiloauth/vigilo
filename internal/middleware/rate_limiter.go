package middleware

import (
	"sync"
	"time"
)

type RateLimiter struct {
	rate       int
	tokens     int
	lastUpdate time.Time
	mu         sync.Mutex
}

func NewRateLimiter(rate int) *RateLimiter {
	return &RateLimiter{
		rate:       rate,
		tokens:     rate,
		lastUpdate: time.Now(),
	}
}

func (rl *RateLimiter) Allow() bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	elapsed := now.Sub(rl.lastUpdate).Seconds()
	rl.lastUpdate = now

	// Add tokens based on the elapsed time
	rl.tokens += int(elapsed * float64(rl.rate))
	if rl.tokens > rl.rate {
		rl.tokens = rl.rate
	}

	if rl.tokens > 0 {
		rl.tokens--
		return true
	}

	return false
}
