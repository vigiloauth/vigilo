package repository

import (
	"sync"

	domain "github.com/vigiloauth/vigilo/internal/domain/login"
	user "github.com/vigiloauth/vigilo/internal/domain/user"
)

// maxStoredLoginAttempts defines the maximum number of login attempts stored per user.
const maxStoredLoginAttempts = 100

var (
	_        domain.LoginAttemptRepository = (*InMemoryLoginAttemptRepository)(nil)
	instance *InMemoryLoginAttemptRepository
	once     sync.Once
)

// InMemoryLoginAttemptRepository is a store for login attempts.
// It uses an in-memory map to store login attempts, keyed by user ID.
type InMemoryLoginAttemptRepository struct {
	attempts map[string][]*user.UserLoginAttempt
	mu       sync.RWMutex
}

// GetInMemoryLoginRepository returns the singleton instance of InMemoryLoginAttemptStore.
//
// Returns:
//
//	*InMemoryLoginAttemptStore: The singleton instance of InMemoryLoginAttemptStore.
func GetInMemoryLoginRepository() *InMemoryLoginAttemptRepository {
	once.Do(func() {
		instance = &InMemoryLoginAttemptRepository{
			attempts: make(map[string][]*user.UserLoginAttempt),
		}
	})
	return instance
}

// ResetInMemoryLoginAttemptStore resets the in-memory store for testing purposes.
func ResetInMemoryLoginAttemptStore() {
	if instance != nil {
		instance.mu.Lock()
		instance.attempts = make(map[string][]*user.UserLoginAttempt)
		instance.mu.Unlock()
	}
}

// SaveLoginAttempt logs a login attempt.
// It adds the login attempt to the store and trims the list if it exceeds the maximum stored attempts.
//
// Parameters:
//
//	attempt *LoginAttempt: The login attempt to save.
func (s *InMemoryLoginAttemptRepository) SaveLoginAttempt(attempt *user.UserLoginAttempt) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.attempts[attempt.UserID] = append(s.attempts[attempt.UserID], attempt)
	s.trimLoginAttempts(attempt.UserID)

	return nil
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
func (s *InMemoryLoginAttemptRepository) GetLoginAttempts(userID string) []*user.UserLoginAttempt {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return s.attempts[userID]
}

// trimLoginAttempts trims the list of login attempts for a user if it exceeds the maximum stored attempts.
//
// Parameters:
//
//	userID string: The user ID.
func (s *InMemoryLoginAttemptRepository) trimLoginAttempts(userID string) {
	if len(s.attempts[userID]) > maxStoredLoginAttempts {
		s.attempts[userID] = s.attempts[userID][1:]
	}
}
