package middleware

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestRateLimiter_Allow(t *testing.T) {
	rate := 2
	rl := NewRateLimiter(rate)
	assert.True(t, rl.Allow())
	assert.True(t, rl.Allow())
	assert.False(t, rl.Allow())
}

func TestRateLimiter_TokenRefill(t *testing.T) {
	rate := 1
	rl := NewRateLimiter(rate)
	assert.True(t, rl.Allow())
	assert.False(t, rl.Allow())
	time.Sleep(2 * time.Second)
	assert.True(t, rl.Allow())
}
