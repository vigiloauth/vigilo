package repository

import (
	"context"
	"strings"
	"sync"
	"time"

	"slices"

	"github.com/vigiloauth/vigilo/identity/config"
	"github.com/vigiloauth/vigilo/internal/common"
	consent "github.com/vigiloauth/vigilo/internal/domain/userconsent"
	"github.com/vigiloauth/vigilo/internal/errors"
)

var (
	logger                                 = config.GetServerConfig().Logger()
	_        consent.UserConsentRepository = (*InMemoryUserConsentRepository)(nil)
	instance *InMemoryUserConsentRepository
	once     sync.Once
)

const module = "InMemoryUserConsentRepository"

// InMemoryUserConsentRepository implements the ConsentStore interface using an in-memory map.
type InMemoryUserConsentRepository struct {
	data map[string]*consent.UserConsentRecord
	mu   sync.RWMutex
}

// GetInMemoryUserConsentRepository returns the singleton instance of InMemoryConsentRepository.
//
// Returns:
//   - *InMemoryConsentStore: The singleton instance of InMemoryConsentRepository.
func GetInMemoryUserConsentRepository() *InMemoryUserConsentRepository {
	once.Do(func() {
		logger.Debug(module, "", "Creating new instance of InMemoryUserConsentRepository")
		instance = &InMemoryUserConsentRepository{data: make(map[string]*consent.UserConsentRecord)}
	})
	return instance
}

// ResetInMemoryUserConsentRepository resets the in-memory repository for testing purposes.
func ResetInMemoryUserConsentRepository() {
	if instance != nil {
		logger.Debug(module, "", "Resetting instance")
		instance.mu.Lock()
		instance.data = make(map[string]*consent.UserConsentRecord)
		instance.mu.Unlock()
	}
}

// HasConsent checks if a user has granted consent to a client for specific scopes.
//
// Parameters:
//   - ctx Context: The context for managing timeouts and cancellations.
//   - userID string: The ID of the user.
//   - clientID string: The ID of the client application.
//   - requestedScope string: The requested scope(s).
//
// Returns:
//
//	bool: True if consent exists, false otherwise.
//	error: An error if the check fails, or nil if successful.
func (c *InMemoryUserConsentRepository) HasConsent(ctx context.Context, userID, clientID, requestedScope string) (bool, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	requestID := common.GetRequestID(ctx)
	key := createConsentKey(userID, clientID)
	record, exists := c.data[key]
	if !exists {
		logger.Debug(module, requestID, "[HasConsent]: Record does not exist with given consent key=[%s]", key)
		return false, nil
	}

	grantedScopes := strings.Fields(record.Scope)
	requestedScopes := strings.Fields(requestedScope)

	for _, reqScope := range requestedScopes {
		found := slices.Contains(grantedScopes, reqScope)
		if !found {
			logger.Error(module, requestID, "[HasConsent]: The requested scope=[%s] was not previously granted", reqScope)
			return false, errors.New(errors.ErrCodeInsufficientScope, "at least one requested scope wasn't previously granted")
		}
	}

	return true, nil
}

// SaveConsent stores a user's consent for a client and scope.
//
// Parameters:
//   - ctx Context: The context for managing timeouts and cancellations.
//   - userID string: The ID of the user.
//   - clientID string: The ID of the client application.
//   - scope string: The granted scope(s).
//
// Returns:
//   - error: An error if the consent cannot be saved, or nil if successful.
func (c *InMemoryUserConsentRepository) SaveConsent(ctx context.Context, userID, clientID, scope string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	key := createConsentKey(userID, clientID)
	c.data[key] = &consent.UserConsentRecord{
		UserID:    userID,
		ClientID:  clientID,
		Scope:     scope,
		CreatedAt: time.Now(),
	}

	return nil
}

// RevokeConsent removes a user's consent for a client.
//
// Parameters:
//   - ctx Context: The context for managing timeouts and cancellations.
//   - userID string: The ID of the user.
//   - clientID string: The ID of the client application.
//
// Returns:
//   - error: An error if the consent cannot be revoked, or nil if successful.
func (c *InMemoryUserConsentRepository) RevokeConsent(ctx context.Context, userID, clientID string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	key := createConsentKey(userID, clientID)
	delete(c.data, key)

	return nil
}

// Helper function to generate a composite key.
func createConsentKey(userID, clientID string) string {
	return userID + "::" + clientID
}
