package repository

import (
	"strings"
	"sync"
	"time"

	consent "github.com/vigiloauth/vigilo/internal/domain/userconsent"
	"github.com/vigiloauth/vigilo/internal/errors"
)

var (
	_        consent.ConsentRepository = (*InMemoryConsentRepository)(nil)
	instance *InMemoryConsentRepository
	once     sync.Once
)

// InMemoryConsentRepository implements the ConsentStore interface using an in-memory map.
type InMemoryConsentRepository struct {
	data map[string]*consent.ConsentRecord
	mu   sync.RWMutex
}

// GetInMemoryConsentRepository returns the singleton instance of InMemoryConsentRepository.
//
// Returns:
//
//	*InMemoryConsentStore: The singleton instance of InMemoryConsentRepository.
func GetInMemoryConsentRepository() *InMemoryConsentRepository {
	once.Do(func() {
		instance = &InMemoryConsentRepository{data: make(map[string]*consent.ConsentRecord)}
	})
	return instance
}

// ResetInMemoryConsentRepository resets the in-memory user store for testing purposes.
func ResetInMemoryConsentRepository() {
	if instance != nil {
		instance.mu.Lock()
		instance.data = make(map[string]*consent.ConsentRecord)
		instance.mu.Unlock()
	}
}

// HasConsent checks if a user has granted consent to a client for specific scopes.
//
// Parameters:
//
//	userID string: The ID of the user.
//	clientID string: The ID of the client application.
//	scope string: The requested scope(s).
//
// Returns:
//
//	bool: True if consent exists, false otherwise.
//	error: An error if the check fails, or nil if successful.
func (c *InMemoryConsentRepository) HasConsent(userID, clientID, requestedScope string) (bool, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	key := createConsentKey(userID, clientID)
	record, exists := c.data[key]
	if !exists {
		return false, nil
	}

	grantedScopes := strings.Fields(record.Scope)
	requestedScopes := strings.Fields(requestedScope)

	for _, reqScope := range requestedScopes {
		found := false
		for _, grantedScope := range grantedScopes {
			if reqScope == grantedScope {
				found = true
				break
			}
		}

		if !found {
			return false, errors.New(
				errors.ErrCodeInvalidScope,
				"at least one requested scope wasn't previously granted",
			)
		}
	}

	return true, nil
}

// SaveConsent stores a user's consent for a client and scope.
//
// Parameters:
//
//	userID string: The ID of the user.
//	clientID string: The ID of the client application.
//	scope string: The granted scope(s).
//
// Returns:
//
//	error: An error if the consent cannot be saved, or nil if successful.
func (c *InMemoryConsentRepository) SaveConsent(userID, clientID, scope string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	key := createConsentKey(userID, clientID)
	c.data[key] = &consent.ConsentRecord{
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
//
//	userID string: The ID of the user.
//	clientID string: The ID of the client application.
//
// Returns:
//
//	error: An error if the consent cannot be revoked, or nil if successful.
func (c *InMemoryConsentRepository) RevokeConsent(userID, clientID string) error {
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
