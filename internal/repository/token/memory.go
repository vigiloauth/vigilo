package repository

import (
	"sync"
	"time"

	domain "github.com/vigiloauth/vigilo/internal/domain/token"
	"github.com/vigiloauth/vigilo/internal/errors"
)

var (
	_        domain.TokenRepository = (*InMemoryTokenRepository)(nil)
	instance *InMemoryTokenRepository
	once     sync.Once
)

// InMemoryTokenRepository implements a token store using an in-memory map.
type InMemoryTokenRepository struct {
	tokens map[string]*domain.TokenData
	mu     sync.Mutex
}

// GetInMemoryTokenRepository returns the singleton instance of InMemoryTokenStore.
// It initializes the store and starts a goroutine to clean up expired tokens.
//
// Returns:
//
//	*InMemoryTokenStore: The singleton instance of InMemoryTokenStore.
func GetInMemoryTokenRepository() *InMemoryTokenRepository {
	once.Do(func() {
		instance = &InMemoryTokenRepository{tokens: make(map[string]*domain.TokenData)}
		go instance.cleanupExpiredTokens()
	})
	return instance
}

// ResetInMemoryTokenRepository resets the in-memory token store for testing purposes.
func ResetInMemoryTokenRepository() {
	if instance != nil {
		instance.mu.Lock()
		instance.tokens = make(map[string]*domain.TokenData)
		instance.mu.Unlock()
	}
}

// SaveToken adds a token to the store.
//
// Parameters:
//
//	token string: The token string.
//	id string: The id associated with the token.
//	expiration time.Time: The token's expiration time.
func (b *InMemoryTokenRepository) SaveToken(tokenStr string, id string, expiration time.Time) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.tokens[tokenStr] = &domain.TokenData{
		ID:        id,
		ExpiresAt: expiration,
		Token:     tokenStr,
	}
}

// GetToken retrieves a token from the store and validates it.
//
// Parameters:
//
//	token string: The token string.
//	id string: The id to validate against.
//
// Returns:
//
//	*TokenData: The TokenData if the token is valid, or nil if not found or invalid.
//	error: An error if the token is not found, expired, or the email doesn't match.
func (b *InMemoryTokenRepository) GetToken(token string, id string) (*domain.TokenData, error) {
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

	if data.ID != id {
		return nil, errors.New(errors.ErrCodeInvalidFormat, "emails do no match")
	}

	data.Token = token
	return data, nil
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
func (b *InMemoryTokenRepository) IsTokenBlacklisted(token string) bool {
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
func (b *InMemoryTokenRepository) DeleteToken(token string) error {
	if _, exists := b.tokens[token]; !exists {
		return errors.New(errors.ErrCodeTokenNotFound, "token not found")
	}

	delete(b.tokens, token)
	return nil
}

// cleanupExpiredTokens periodically removes expired tokens from the store.
func (b *InMemoryTokenRepository) cleanupExpiredTokens() {
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
