package repository

import (
	"context"
	"sync"

	"github.com/vigiloauth/vigilo/v2/idp/config"
	domain "github.com/vigiloauth/vigilo/v2/internal/domain/login"
	user "github.com/vigiloauth/vigilo/v2/internal/domain/user"
	"github.com/vigiloauth/vigilo/v2/internal/errors"
)

// maxStoredLoginAttempts defines the maximum number of login attempts stored per user.
const (
	module                 = "InMemoryLoginAttemptRepository"
	maxStoredLoginAttempts = 100
)

var (
	logger                                 = config.GetServerConfig().Logger()
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
//   - *InMemoryLoginAttemptStore: The singleton instance of InMemoryLoginAttemptStore.
func GetInMemoryLoginRepository() *InMemoryLoginAttemptRepository {
	once.Do(func() {
		logger.Debug(module, "", "Creating new instance of InMemoryLoginAttemptRepository")
		instance = &InMemoryLoginAttemptRepository{
			attempts: make(map[string][]*user.UserLoginAttempt),
		}
	})
	return instance
}

// ResetInMemoryLoginAttemptStore resets the in-memory store for testing purposes.
func ResetInMemoryLoginAttemptStore() {
	if instance != nil {
		logger.Debug(module, "", "Resetting instance")
		instance.mu.Lock()
		instance.attempts = make(map[string][]*user.UserLoginAttempt)
		instance.mu.Unlock()
	}
}

// SaveLoginAttempt saves a login attempt.
//
// Parameters:
//   - ctx Context: The context for managing timeouts and cancellations.
//   - attempt *UserLoginAttempt: The login attempt to save.
//
// Returns:
//   - error: If an error occurs saving the login attempts.
func (s *InMemoryLoginAttemptRepository) SaveLoginAttempt(ctx context.Context, attempt *user.UserLoginAttempt) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.attempts[attempt.UserID] = append(s.attempts[attempt.UserID], attempt)
	s.trimLoginAttempts(attempt.UserID)

	return nil
}

// GetLoginAttemptsByUserID retrieves all login attempts for a given user.
//
// Parameters:
//   - ctx Context: The context for managing timeouts and cancellations.
//   - userID string: The user ID.
//
// Returns:
//   - []*UserLoginAttempt: A slice of login attempts for the user.
//   - error: If an error occurs retrieving user login attempts.
func (s *InMemoryLoginAttemptRepository) GetLoginAttemptsByUserID(ctx context.Context, userID string) ([]*user.UserLoginAttempt, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	attempts, found := s.attempts[userID]
	if !found {
		return nil, errors.New(errors.ErrCodeNotFound, "failed to retrieve user login attempts")
	}
	return attempts, nil
}

// trimLoginAttempts trims the list of login attempts for a user if it exceeds the maximum stored attempts.
//
// Parameters:
//   - userID string: The user ID.
func (s *InMemoryLoginAttemptRepository) trimLoginAttempts(userID string) {
	if len(s.attempts[userID]) > maxStoredLoginAttempts {
		s.attempts[userID] = s.attempts[userID][1:]
	}
}
