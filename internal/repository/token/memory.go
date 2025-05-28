package repository

import (
	"context"
	"sync"
	"time"

	"github.com/vigiloauth/vigilo/v2/idp/config"
	domain "github.com/vigiloauth/vigilo/v2/internal/domain/token"
	"github.com/vigiloauth/vigilo/v2/internal/errors"
	"github.com/vigiloauth/vigilo/v2/internal/utils"
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
	blacklist map[string]*domain.TokenData
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
		logger.Debug(module, "", "Creating new instance of InMemoryTokenRepository")
		instance = &InMemoryTokenRepository{
			tokens:    make(map[string]*domain.TokenData),
			blacklist: make(map[string]*domain.TokenData),
		}
	})
	return instance
}

// ResetInMemoryTokenRepository resets the in-memory token store for testing purposes.
func ResetInMemoryTokenRepository() {
	if instance != nil {
		logger.Debug(module, "", "Resetting instance")
		instance.mu.Lock()
		instance.tokens = make(map[string]*domain.TokenData)
		instance.blacklist = make(map[string]*domain.TokenData)
		instance.mu.Unlock()
	}
}

// SaveToken adds a token to the store.
//
// Parameters:
//   - ctx Context: The context for managing timeouts and cancellations.
//   - token string: The token string to add.
//   - id string: The id associated with the token.
//   - tokenData *TokenData: The data associated with the token.
//   - expiration time.Time: The token's expiration time.
//
// Returns:
//   - error: If an error occurs saving the token.
func (b *InMemoryTokenRepository) SaveToken(ctx context.Context, tokenStr string, id string, tokenData *domain.TokenData, expiration time.Time) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	requestID := utils.GetRequestID(ctx)
	if _, blacklisted := b.blacklist[tokenStr]; blacklisted {
		logger.Debug(module, requestID, "[SaveToken]: Token=%s is blacklisted and will not be saved", truncateToken(tokenStr))
		return nil
	}

	b.tokens[tokenStr] = tokenData

	return nil
}

// GetToken retrieves a token from the store and validates it.
//
// Parameters:
//   - ctx Context: The context for managing timeouts and cancellations.
//   - tokenStr string: The token string to retrieve.
//
// Returns:
//   - *TokenData: The TokenData if the token is valid, or nil if not found.
//   - error: If an error occurs retrieving the token.
func (b *InMemoryTokenRepository) GetToken(ctx context.Context, token string) (*domain.TokenData, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	requestID := utils.GetRequestID(ctx)
	data, exists := b.tokens[token]
	if !exists {
		logger.Debug(module, requestID, "[GetToken]: Token not found")
		return nil, errors.New(errors.ErrCodeTokenNotFound, "token not found or expired")
	}

	return data, nil
}

// BlacklistToken adds a token to the blacklist.
//
// Parameters:
//   - ctx Context: The context for managing timeouts and cancellations.
//   - token string: The token string to delete.
//
// Returns:
//   - error: An error if the token blacklisting fails.
func (b *InMemoryTokenRepository) BlacklistToken(ctx context.Context, token string) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	tokenData := b.tokens[token]
	delete(b.tokens, token)
	b.blacklist[token] = tokenData
	return nil
}

// IsTokenBlacklisted checks if a token is blacklisted.
//
// Parameters:
//   - ctx Context: The context for managing timeouts and cancellations.
//   - token string: The token string to check.
//
// Returns:
//   - bool: True if the token is blacklisted, false otherwise.
//   - error: If an error occurs checking the token.
func (b *InMemoryTokenRepository) IsTokenBlacklisted(ctx context.Context, token string) (bool, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	requestID := utils.GetRequestID(ctx)

	_, blacklisted := b.blacklist[token]
	if blacklisted {
		logger.Debug(module, requestID, "[IsTokenBlacklisted]: Token is blacklisted")
		return true, nil
	}

	data, exists := b.tokens[token]
	if !exists {
		logger.Debug(module, requestID, "[IsTokenBlacklisted]: Token is not blacklisted")
		return false, nil
	}

	expirationTime := time.Unix(data.TokenClaims.ExpiresAt, 0)
	if time.Now().After(expirationTime) {
		logger.Debug(module, requestID, "[IsTokenBlacklisted]: Deleting expired token")
		delete(b.tokens, token)
		return true, nil
	}

	return false, nil
}

// DeleteToken removes a token from the store.
//
// Parameters:
//   - ctx Context: The context for managing timeouts and cancellations.
//   - token string: The token string to delete.
//
// Returns:
//   - error: An error if the token deletion fails.
func (b *InMemoryTokenRepository) DeleteToken(ctx context.Context, token string) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	requestID := utils.GetRequestID(ctx)
	if _, exists := b.tokens[token]; !exists {
		logger.Warn(module, requestID, "[DeleteToken]: Attempted to delete non-existent token=[%s]", truncateToken(token))
		return errors.New(errors.ErrCodeTokenNotFound, "token not found")
	}

	delete(b.tokens, token)
	delete(b.blacklist, token)

	logger.Debug(module, requestID, "[DeleteToken]: Successfully deleted token=[%s]", truncateToken(token))
	return nil
}

// ExistsByTokenID checks to see if the given ID matches with any token in the repository.
//
// Parameters:
//   - ctx Context: The context for managing timeouts and cancellations.
//   - tokenID string: The token ID to search.
//
// Returns:
//   - error: An error if the searching for the token fails.
func (b *InMemoryTokenRepository) ExistsByTokenID(ctx context.Context, tokenID string) (bool, error) {
	for _, data := range b.tokens {
		if data.TokenID == tokenID {
			return true, nil
		}
	}

	return false, nil
}

// GetExpiredTokens searches for all expired tokens in the repository.
//
// Parameters:
//   - ctx Context: The context for managing timeouts and cancellations.
//
// Returns:
//   - []*TokenData: A slice of token data.
//   - error: An error if searching fails.
func (b *InMemoryTokenRepository) GetExpiredTokens(ctx context.Context) ([]*domain.TokenData, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	now := time.Now()
	tokens := []*domain.TokenData{}

	for _, data := range b.tokens {
		expirationTime := time.Unix(data.TokenClaims.ExpiresAt, 0)
		if now.After(expirationTime) {
			tokens = append(tokens, data)
		}
	}

	return tokens, nil
}

// truncateToken truncates a token for safe logging.
func truncateToken(token string) string {
	if len(token) > 10 {
		return token[:10] + "..."
	}
	return token
}
