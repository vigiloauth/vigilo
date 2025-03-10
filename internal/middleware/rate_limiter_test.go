package middleware

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestRateLimiter_Allow(t *testing.T) {
	rl := NewRateLimiter(2)
	assert.True(t, rl.Allow())
	assert.True(t, rl.Allow())
	assert.False(t, rl.Allow())
}

func TestRateLimiter_TokenRefill(t *testing.T) {
	rl := NewRateLimiter(1)
	assert.True(t, rl.Allow())
	assert.False(t, rl.Allow())
	time.Sleep(2 * time.Second)
	assert.True(t, rl.Allow())
}
