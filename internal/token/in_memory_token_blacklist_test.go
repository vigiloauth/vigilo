package token

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestTokenBlacklist_AddToken(t *testing.T) {
	blacklist := GetTokenBlacklist()
	token := "test-token"
	expiration := time.Now().Add(1 * time.Hour)

	blacklist.AddToken(token, expiration)

	blacklist.mu.Lock()
	defer blacklist.mu.Unlock()
	assert.Contains(t, blacklist.blacklistedTokens, token)
	assert.Equal(t, expiration, blacklist.blacklistedTokens[token])
}

func TestTokenBlacklist_IsTokenBlacklisted(t *testing.T) {
	blacklist := GetTokenBlacklist()
	token := "test-token"
	expiration := time.Now().Add(1 * time.Hour)

	blacklist.AddToken(token, expiration)
	isBlacklisted := blacklist.IsTokenBlacklisted(token)

	assert.True(t, isBlacklisted)
}

func TestTokenBlacklist_TokenExpires(t *testing.T) {
	blacklist := GetTokenBlacklist()
	token := "test-token"
	expiration := time.Now().Add(-1 * time.Hour) // Token already expired

	blacklist.AddToken(token, expiration)
	isBlacklisted := blacklist.IsTokenBlacklisted(token)

	assert.False(t, isBlacklisted)
	blacklist.mu.Lock()
	defer blacklist.mu.Unlock()
	assert.NotContains(t, blacklist.blacklistedTokens, token)
}
