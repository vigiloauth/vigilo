package middleware

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

const testRequestID string = "requestID"

func TestRateLimiter_Allow(t *testing.T) {
	rate := 2
	rl := NewRateLimiter(rate)
	assert.True(t, rl.Allow(testRequestID))
	assert.True(t, rl.Allow(testRequestID))
	assert.False(t, rl.Allow(testRequestID))
}

func TestRateLimiter_TokenRefill(t *testing.T) {
	rate := 1
	rl := NewRateLimiter(rate)
	assert.True(t, rl.Allow(testRequestID))
	assert.False(t, rl.Allow(testRequestID))
	time.Sleep(2 * time.Second)
	assert.True(t, rl.Allow(testRequestID))
}
