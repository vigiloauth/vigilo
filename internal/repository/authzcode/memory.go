package repository

import (
	"context"
	"sync"
	"time"

	"github.com/vigiloauth/vigilo/idp/config"
	authz "github.com/vigiloauth/vigilo/internal/domain/authzcode"
	"github.com/vigiloauth/vigilo/internal/errors"
)

const module = "InMemoryAuthorizationCodeRepository"

var (
	logger                                     = config.GetServerConfig().Logger()
	_        authz.AuthorizationCodeRepository = (*InMemoryAuthorizationCodeRepository)(nil)
	instance *InMemoryAuthorizationCodeRepository
	once     sync.Once
)

type InMemoryAuthorizationCodeRepository struct {
	codes     map[string]codeEntry
	mu        sync.RWMutex
	cleanupCh chan struct{} // Channel for triggering cleanup
}

// codeEntry represents a stored authorization code with expiration.
type codeEntry struct {
	Data      *authz.AuthorizationCodeData
	ExpiresAt time.Time
}

// GetInMemoryAuthorizationCodeRepository returns the singleton instance of InMemoryAuthorizationCodeRepository.
//
// Returns:
//   - *InMemoryAuthorizationCodeStore: The singleton instance of InMemoryAuthorizationCodeRepository.
func GetInMemoryAuthorizationCodeRepository() *InMemoryAuthorizationCodeRepository {
	once.Do(func() {
		logger.Debug(module, "", "Creating new instance of InMemoryAuthorizationCodeRepository")
		instance = &InMemoryAuthorizationCodeRepository{
			codes: make(map[string]codeEntry),
		}
	})
	return instance
}

// StoreAuthorizationCode persists an authorization code with its associated data.
//
// Parameters:
//   - ctx Context: The context for managing timeouts and cancellations.
//   - code string: The authorization code.
//   - data *AuthorizationCodeData: The data associated with the code.
//   - expiresAt time.Time: When the code expires.
//
// Returns:
//   - error: An error if storing fails, nil otherwise.
func (s *InMemoryAuthorizationCodeRepository) StoreAuthorizationCode(ctx context.Context, code string, data *authz.AuthorizationCodeData, expiresAt time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.codes[code] = codeEntry{
		Data:      data,
		ExpiresAt: expiresAt,
	}

	return nil
}

// GetAuthorizationCode retrieves the data associated with an authorization code.
//
// Parameters:
//   - ctx Context: The context for managing timeouts and cancellations.
//   - code string: The authorization code to look up.
//
// Returns:
//   - *AuthorizationCodeData: The associated data if found.
//   - error: An error if retrieval fails.
func (s *InMemoryAuthorizationCodeRepository) GetAuthorizationCode(ctx context.Context, code string) (*authz.AuthorizationCodeData, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	entry, exists := s.codes[code]
	if !exists {
		logger.Debug(module, "", "[GetAuthorizationCode]: Code=%s does not exist", code)
		return nil, errors.New(errors.ErrCodeInvalidAuthorizationCode, "authorization code does not exist")
	}

	// Check if code has expired
	if time.Now().After(entry.ExpiresAt) {
		logger.Warn(module, "", "[GetAuthorizationCode]: Authorization code is expired")
		return nil, errors.New(errors.ErrCodeExpiredAuthorizationCode, "authorization code is expired")
	}

	return entry.Data, nil
}

// DeleteAuthorizationCode deletes an authorization code after use.
//
// Parameters:
//   - ctx Context: The context for managing timeouts and cancellations.
//   - code string: The authorization code to remove.
//
// Returns:
//   - error: An error if removal fails, nil otherwise.
func (s *InMemoryAuthorizationCodeRepository) DeleteAuthorizationCode(ctx context.Context, code string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.codes, code)
	return nil
}

// UpdateAuthorizationCode updates existing authorization code data.
//
// Parameters:
//   - ctx Context: The context for managing timeouts and cancellations.
//   - code string: The authorization code to update.
//   - authData *AuthorizationCodeData: The update authorization code data.
//
// Returns:
//   - error: An error if update fails, nil otherwise.
func (s *InMemoryAuthorizationCodeRepository) UpdateAuthorizationCode(ctx context.Context, code string, authData *authz.AuthorizationCodeData) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.codes[code] = codeEntry{
		Data: authData,
	}

	return nil
}
