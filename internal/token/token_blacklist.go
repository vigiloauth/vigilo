package token

import (
	"sync"
	"time"
)

// TokenBlacklist manages blacklisted tokens.
type TokenBlacklist struct {
	blacklistedTokens map[string]time.Time
	mu                sync.Mutex
}

var instance *TokenBlacklist
var once sync.Once

func GetTokenBlacklist() *TokenBlacklist {
	once.Do(func() {
		instance = &TokenBlacklist{
			blacklistedTokens: make(map[string]time.Time),
		}
	})
	return instance
}

// AddToken adds a token to the blacklist with an expiration time.
func (b *TokenBlacklist) AddToken(token string, expiration time.Time) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.blacklistedTokens[token] = expiration
}

// IsTokenBlacklisted checks if a token is blacklisted.
func (b *TokenBlacklist) IsTokenBlacklisted(token string) bool {
	b.mu.Lock()
	defer b.mu.Unlock()

	expiration, exists := b.blacklistedTokens[token]
	if !exists {
		return false
	}

	if time.Now().After(expiration) {
		delete(b.blacklistedTokens, token)
		return false
	}

	return true
}
