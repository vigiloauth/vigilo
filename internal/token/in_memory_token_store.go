package token

import (
	"sync"
	"time"

	"github.com/vigiloauth/vigilo/internal/errors"
)

type InMemoryTokenStore struct {
	tokens map[string]TokenData
	mu     sync.Mutex
}

var instance *InMemoryTokenStore
var once sync.Once

func GetInMemoryTokenStore() *InMemoryTokenStore {
	once.Do(func() {
		instance = &InMemoryTokenStore{
			tokens: make(map[string]TokenData),
		}
		go instance.cleanupExpiredTokens()
	})
	return instance
}

func (b *InMemoryTokenStore) AddToken(token string, email string, expiration time.Time) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.tokens[token] = TokenData{
		Email:     email,
		ExpiresAt: expiration,
	}
}

func (b *InMemoryTokenStore) GetToken(token string, email string) (*TokenData, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	data, exists := b.tokens[token]
	if !exists {
		return nil, errors.NewTokenNotFoundError()
	}

	if time.Now().After(data.ExpiresAt) {
		delete(b.tokens, token)
		return nil, errors.NewTokenNotFoundError()
	}

	if data.Email != email {
		return nil, errors.NewInvalidFormatError("email", "Emails do not match")
	}

	data.Token = token
	return &data, nil
}

func (b *InMemoryTokenStore) IsTokenBlacklisted(token string) bool {
	b.mu.Lock()
	defer b.mu.Unlock()

	data, exists := b.tokens[token]
	if !exists {
		return false
	}

	if time.Now().After(data.ExpiresAt) {
		delete(b.tokens, token)
		return false
	}

	return true
}

func (b *InMemoryTokenStore) DeleteToken(token string) error {
	if _, exists := b.tokens[token]; !exists {
		return errors.NewTokenNotFoundError()
	}

	delete(b.tokens, token)
	return nil
}

func (b *InMemoryTokenStore) cleanupExpiredTokens() {
	ticker := time.NewTicker(1 * time.Minute)
	for range ticker.C {
		b.mu.Lock()
		now := time.Now()
		for token, data := range b.tokens {
			if now.After(data.ExpiresAt) {
				delete(b.tokens, token)
			}
		}
		b.mu.Unlock()
	}
}
