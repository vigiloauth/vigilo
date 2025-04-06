package mocks

import user "github.com/vigiloauth/vigilo/internal/domain/user"

// MockLoginAttemptRepository is a mock implementation of the loginattempt.LoginAttemptStore interface.
type MockLoginAttemptRepository struct {
	// SaveLoginAttemptFunc is a mock function for the SaveLoginAttempt method.
	SaveLoginAttemptFunc func(attempt *user.UserLoginAttempt) error

	// GetLoginAttemptsFunc is a mock function for the GetLoginAttempts method.
	GetLoginAttemptsFunc func(userID string) []*user.UserLoginAttempt
}

// SaveLoginAttempt calls the mock SaveLoginAttemptFunc.
func (m *MockLoginAttemptRepository) SaveLoginAttempt(attempt *user.UserLoginAttempt) error {
	return m.SaveLoginAttemptFunc(attempt)
}

// GetLoginAttempts calls the mock GetLoginAttemptsFunc.
func (m *MockLoginAttemptRepository) GetLoginAttempts(userID string) []*user.UserLoginAttempt {
	return m.GetLoginAttemptsFunc(userID)
}
