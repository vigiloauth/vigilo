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
	tokens    map[string]*domain.TokenData
	blacklist map[string]struct{}
	mu        sync.RWMutex
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
		instance = &InMemoryTokenRepository{
			tokens:    make(map[string]*domain.TokenData),
			blacklist: make(map[string]struct{}),
		}
	})
	return instance
}

// ResetInMemoryTokenRepository resets the in-memory token store for testing purposes.
func ResetInMemoryTokenRepository() {
	if instance != nil {
		logger.Debug(module, "Resetting instance")
		instance.mu.Lock()
		instance.tokens = make(map[string]*domain.TokenData)
		instance.blacklist = make(map[string]struct{})
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

	if _, blacklisted := b.blacklist[tokenStr]; blacklisted {
		logger.Debug(module, "SaveToken: Token=%s is blacklisted and will not be saved", truncateToken(tokenStr))
		return
	}

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
//	tokenStr string: The token string to retrieve.
//
// Returns:
//
//	*TokenData: The TokenData if the token is valid, or nil if not found.
func (b *InMemoryTokenRepository) GetToken(token string) *domain.TokenData {
	b.mu.RLock()
	defer b.mu.RUnlock()

	data, exists := b.tokens[token]
	if !exists {
		logger.Debug(module, "GetToken: Token not found")
		return nil
	}

	return data
}

func (b *InMemoryTokenRepository) BlacklistToken(token string) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	data, exists := b.tokens[token]
	if !exists || time.Now().After(data.ExpiresAt) {
		logger.Debug(module, "BlacklistToken: Token=%s not found or expired", truncateToken(token))
		return errors.New(errors.ErrCodeTokenNotFound, "token not found or expired")
	}

	b.blacklist[token] = struct{}{}
	logger.Debug(module, "BlacklistToken: Token=%s has been blacklisted", truncateToken(token))
	return nil
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

	_, blacklisted := b.blacklist[token]
	if blacklisted {
		logger.Debug(module, "IsTokenBlacklisted: Token=%s is blacklisted", truncateToken(token))
		return true
	}

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
	delete(b.blacklist, token)

	logger.Debug(module, "DeleteToken: Successfully deleted token=%s", truncateToken(token))
	return nil
}

func (b *InMemoryTokenRepository) ExistsByTokenID(tokenID string) bool {
	for _, data := range b.tokens {
		if data.TokenID == tokenID {
			return true
		}
	}

	return false
}

func (b *InMemoryTokenRepository) GetExpiredTokens() []*domain.TokenData {
	b.mu.RLock()
	defer b.mu.RUnlock()

	now := time.Now()
	tokens := []*domain.TokenData{}

	for _, data := range b.tokens {
		if now.After(data.ExpiresAt) {
			tokens = append(tokens, data)
		}
	}

	return tokens
}

// truncateToken truncates a token for safe logging.
func truncateToken(token string) string {
	if len(token) > 10 {
		return token[:10] + "..."
	}
	return token
}
