package repository

import (
	"sync"
	"time"

	authz "github.com/vigiloauth/vigilo/internal/domain/authzcode"
)

var (
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
//
//	*InMemoryAuthorizationCodeStore: The singleton instance of InMemoryAuthorizationCodeRepository.
func GetInMemoryAuthorizationCodeRepository() *InMemoryAuthorizationCodeRepository {
	once.Do(func() {
		instance = &InMemoryAuthorizationCodeRepository{
			codes: make(map[string]codeEntry),
		}
		go instance.cleanupRoutine()
	})
	return instance
}

// StoreAuthorizationCode persists an authorization code with its associated data.
//
// Parameters:
//
//	code string: The authorization code.
//	data *AuthorizationData: The data associated with the code.
//	expiresAt time.Time: When the code expires.
//
// Returns:
//
//	error: An error if storing fails, nil otherwise.
func (s *InMemoryAuthorizationCodeRepository) StoreAuthorizationCode(
	code string,
	data *authz.AuthorizationCodeData,
	expiresAt time.Time,
) error {
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
//
//	code string: The authorization code to look up.
//
// Returns:
//
//	*AuthorizationData: The associated data if found.
//	bool: Whether the code exists and is valid.
//	error: An error if retrieval fails.
func (s *InMemoryAuthorizationCodeRepository) GetAuthorizationCode(code string) (*authz.AuthorizationCodeData, bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	entry, exists := s.codes[code]
	if !exists {
		return nil, false, nil
	}

	// Check if code has expired
	if time.Now().After(entry.ExpiresAt) {
		return nil, false, nil
	}

	return entry.Data, true, nil
}

// DeleteAuthorizationCode deletes an authorization code after use.
//
// Parameters:
//
//	code string: The authorization code to remove.
//
// Returns:
//
//	error: An error if removal fails, nil otherwise.
func (s *InMemoryAuthorizationCodeRepository) DeleteAuthorizationCode(code string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.codes, code)
	return nil
}

// CleanExpiredCodes removes all expired authorization codes.
//
// Returns:
//
//	error: An error if the cleanup fails, nil otherwise.
func (s *InMemoryAuthorizationCodeRepository) CleanupExpiredAuthorizationCodes() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	for code, entry := range s.codes {
		if now.After(entry.ExpiresAt) {
			delete(s.codes, code)
		}
	}

	return nil
}

func (s *InMemoryAuthorizationCodeRepository) UpdateAuthorizationCode(code string, authData *authz.AuthorizationCodeData) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.codes[code] = codeEntry{
		Data: authData,
	}

	return nil
}

// Close stops the background cleanup routine if it's running.
func (s *InMemoryAuthorizationCodeRepository) Close() {
	close(s.cleanupCh)
}

// cleanupRoutine periodically cleans up expired codes.
func (s *InMemoryAuthorizationCodeRepository) cleanupRoutine() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			_ = s.CleanupExpiredAuthorizationCodes()
		case <-s.cleanupCh:
			return
		}
	}
}
