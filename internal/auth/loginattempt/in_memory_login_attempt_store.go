package auth

import (
	"sync"
	"time"
)

// Ensure InMemoryLoginAttemptStore implements the LoginAttemptStore interface.
var _ LoginAttemptStore = (*InMemoryLoginAttemptStore)(nil)

// NewLoginAttempt creates a new LoginAttempt instance.
//
// Parameters:
//
//	ipAddress string: The IP address of the login attempt.
//	requestMetadata string: Additional request metadata.
//	details string: Details about the login attempt.
//	userAgent string: The user agent of the login attempt.
//
// Returns:
//
//	*LoginAttempt: A new LoginAttempt instance.
func NewLoginAttempt(ipAddress, requestMetadata, details, userAgent string) *LoginAttempt {
	return &LoginAttempt{
		IPAddress:       ipAddress,
		Timestamp:       time.Now(),
		RequestMetadata: requestMetadata,
		Details:         details,
		UserAgent:       userAgent,
		FailedAttempts:  0,
	}
}

// InMemoryLoginAttemptStore is a store for login attempts.
// It uses an in-memory map to store login attempts, keyed by user ID.
type InMemoryLoginAttemptStore struct {
	attempts map[string][]*LoginAttempt // Map of user ID to login attempts.
	mu       sync.RWMutex               // Mutex for concurrent access.
}

// NewInMemoryLoginAttemptStore creates a new InMemoryLoginAttemptStore instance.
//
// Returns:
//
//	*InMemoryLoginAttemptStore: A new InMemoryLoginAttemptStore instance.
func NewInMemoryLoginAttemptStore() *InMemoryLoginAttemptStore {
	return &InMemoryLoginAttemptStore{
		attempts: make(map[string][]*LoginAttempt),
	}
}

// SaveLoginAttempt logs a login attempt.
// It adds the login attempt to the store and trims the list if it exceeds the maximum stored attempts.
//
// Parameters:
//
//	attempt *LoginAttempt: The login attempt to save.
func (s *InMemoryLoginAttemptStore) SaveLoginAttempt(attempt *LoginAttempt) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.attempts[attempt.UserID] = append(s.attempts[attempt.UserID], attempt)
	s.trimLoginAttempts(attempt.UserID)
}

// GetLoginAttempts returns all login attempts for a given user.
//
// Parameters:
//
//	userID string: The user ID.
//
// Returns:
//
//	[]*LoginAttempt: A slice of login attempts for the user.
func (s *InMemoryLoginAttemptStore) GetLoginAttempts(userID string) []*LoginAttempt {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return s.attempts[userID]
}

// trimLoginAttempts trims the list of login attempts for a user if it exceeds the maximum stored attempts.
//
// Parameters:
//
//	userID string: The user ID.
func (s *InMemoryLoginAttemptStore) trimLoginAttempts(userID string) {
	if len(s.attempts[userID]) > maxStoredLoginAttempts {
		s.attempts[userID] = s.attempts[userID][1:]
	}
}
