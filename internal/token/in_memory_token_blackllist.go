package token

import (
	"sync"
	"time"
)

type InMemoryTokenBlacklist struct {
	blacklistedTokens map[string]time.Time
	mu                sync.Mutex
}

var instance *InMemoryTokenBlacklist
var once sync.Once

func GetTokenBlacklist() *InMemoryTokenBlacklist {
	once.Do(func() {
		instance = &InMemoryTokenBlacklist{
			blacklistedTokens: make(map[string]time.Time),
		}
	})
	return instance
}

// AddToken adds a token to the blacklist with an expiration time.
func (b *InMemoryTokenBlacklist) AddToken(token string, expiration time.Time) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.blacklistedTokens[token] = expiration
}

// IsTokenBlacklisted checks if a token is blacklisted.
func (b *InMemoryTokenBlacklist) IsTokenBlacklisted(token string) bool {
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
