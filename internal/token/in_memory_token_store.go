package token

import (
	"sync"
	"time"

	"github.com/vigiloauth/vigilo/internal/errors"
)

// InMemoryTokenStore implements a token store using an in-memory map.
type InMemoryTokenStore struct {
	tokens map[string]TokenData // Map to store tokens, key is the token string.
	mu     sync.Mutex           // Mutex to protect concurrent access.
}

var _ TokenStore = (*InMemoryTokenStore)(nil)
var instance *InMemoryTokenStore // Singleton instance.
var once sync.Once               // Ensures singleton initialization only once.

// GetInMemoryTokenStore returns the singleton instance of InMemoryTokenStore.
// It initializes the store and starts a goroutine to clean up expired tokens.
//
// Returns:
//
//	*InMemoryTokenStore: The singleton instance of InMemoryTokenStore.
func GetInMemoryTokenStore() *InMemoryTokenStore {
	once.Do(func() {
		instance = &InMemoryTokenStore{
			tokens: make(map[string]TokenData),
		}
		go instance.cleanupExpiredTokens()
	})
	return instance
}

// AddToken adds a token to the store.
//
// Parameters:
//
//	token string: The token string.
//	email string: The email associated with the token.
//	expiration time.Time: The token's expiration time.
func (b *InMemoryTokenStore) AddToken(token string, email string, expiration time.Time) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.tokens[token] = TokenData{
		Email:     email,
		ExpiresAt: expiration,
	}
}

// GetToken retrieves a token from the store and validates it.
//
// Parameters:
//
//	token string: The token string.
//	email string: The email to validate against.
//
// Returns:
//
//	*TokenData: The TokenData if the token is valid, or nil if not found or invalid.
//	error: An error if the token is not found, expired, or the email doesn't match.
func (b *InMemoryTokenStore) GetToken(token string, email string) (*TokenData, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	data, exists := b.tokens[token]
	if !exists {
		return nil, errors.New(errors.ErrCodeTokenNotFound, "token not found")
	}

	if time.Now().After(data.ExpiresAt) {
		delete(b.tokens, token)
		return nil, errors.New(errors.ErrCodeTokenNotFound, "token not found")
	}

	if data.Email != email {
		return nil, errors.New(errors.ErrCodeInvalidFormat, "emails do no match")
	}

	data.Token = token
	return &data, nil
}

// IsTokenBlacklisted checks if a token is blacklisted.
//
// Parameters:
//
//	token string: The token string to check.
//
// Returns:
//
//	bool: True if the token is blacklisted (exists and is not expired), false otherwise.
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

// DeleteToken removes a token from the store.
//
// Parameters:
//
//	token string: The token string to delete.
//
// Returns:
//
//	error: An error if the token is not found.
func (b *InMemoryTokenStore) DeleteToken(token string) error {
	if _, exists := b.tokens[token]; !exists {
		return errors.New(errors.ErrCodeTokenNotFound, "token not found")
	}

	delete(b.tokens, token)
	return nil
}

// cleanupExpiredTokens periodically removes expired tokens from the store.
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
