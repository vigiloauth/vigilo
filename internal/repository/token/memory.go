package repository

import (
	"sync"
	"time"

	"github.com/vigiloauth/vigilo/identity/config"
	domain "github.com/vigiloauth/vigilo/internal/domain/token"
	"github.com/vigiloauth/vigilo/internal/errors"
)

var (
	logger                          = config.GetServerConfig().Logger()
	_        domain.TokenRepository = (*InMemoryTokenRepository)(nil)
	instance *InMemoryTokenRepository
	once     sync.Once
)

const module = "InMemoryTokenRepository"

// InMemoryTokenRepository implements a token store using an in-memory map.
type InMemoryTokenRepository struct {
	tokens map[string]*domain.TokenData
	mu     sync.RWMutex
}

// GetInMemoryTokenRepository returns the singleton instance of InMemoryTokenStore.
// It initializes the store and starts a goroutine to clean up expired tokens.
//
// Returns:
//
//	*InMemoryTokenStore: The singleton instance of InMemoryTokenStore.
func GetInMemoryTokenRepository() *InMemoryTokenRepository {
	once.Do(func() {
		logger.Debug(module, "Creating new instance of InMemoryTokenRepository")
		instance = &InMemoryTokenRepository{tokens: make(map[string]*domain.TokenData)}
		go instance.cleanupExpiredTokens()
	})
	return instance
}

// ResetInMemoryTokenRepository resets the in-memory token store for testing purposes.
func ResetInMemoryTokenRepository() {
	if instance != nil {
		logger.Debug(module, "Resetting instance")
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
//	id string: The ID that the token is associated to (e.g. client_id, user_id)
//
// Returns:
//
//	*TokenData: The TokenData if the token is valid, or nil if not found or invalid.
//	error: An error if the token is not found, expired, or the id doesn't match.
func (b *InMemoryTokenRepository) GetToken(token string, id string) (*domain.TokenData, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	data, exists := b.tokens[token]
	if !exists {
		logger.Debug(module, "GetToken: Token not found")
		return nil, errors.New(errors.ErrCodeTokenNotFound, "token not found")
	}

	if time.Now().After(data.ExpiresAt) {
		logger.Debug(module, "GetToken: Deleting expired token=%s", token)
		delete(b.tokens, token)
		return nil, errors.New(errors.ErrCodeTokenNotFound, "token is expired")
	}

	if data.ID != id {
		logger.Error(module, "GetToken: TokenData ID and given ID do not match")
		return nil, errors.New(errors.ErrCodeInvalidFormat, "ID's do not match")
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
	b.mu.RLock()
	defer b.mu.RUnlock()

	data, exists := b.tokens[token]
	if !exists {
		logger.Debug(module, "IsTokenBlacklisted: Token=%s is not blacklisted", truncateToken(token))
		return false
	}

	if time.Now().After(data.ExpiresAt) {
		logger.Debug(module, "IsTokenBlacklisted: Deleting expired token=%s", truncateToken(token))
		delete(b.tokens, token)
		return true
	}

	logger.Debug(module, "IsTokenBlacklisted: Token=%s is blacklisted", truncateToken(token))
	return false
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
	b.mu.Lock()
	defer b.mu.Unlock()

	if _, exists := b.tokens[token]; !exists {
		logger.Warn(module, "DeleteToken: Attempted to delete non-existent token=%s", truncateToken(token))
		return errors.New(errors.ErrCodeTokenNotFound, "token not found")
	}

	delete(b.tokens, token)
	logger.Debug(module, "DeleteToken: Successfully deleted token=%s", truncateToken(token))
	return nil
}

// cleanupExpiredTokens periodically removes expired tokens from the store.
func (b *InMemoryTokenRepository) cleanupExpiredTokens() {
	logger.Debug(module, "Starting cleanup of expired tokens")
	ticker := time.NewTicker(1 * time.Minute)
	for range ticker.C {
		b.mu.Lock()
		now := time.Now()
		for token, data := range b.tokens {
			if now.After(data.ExpiresAt) {
				logger.Debug(module, "Deleting expired token=%s", truncateToken(token))
				delete(b.tokens, token)
			}
		}
		b.mu.Unlock()
	}
	logger.Debug(module, "Finished cleanup of expired tokens")
}

// truncateToken truncates a token for safe logging.
func truncateToken(token string) string {
	if len(token) > 10 {
		return token[:10] + "..."
	}
	return token
}
