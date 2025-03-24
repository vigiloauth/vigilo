package mocks

import user "github.com/vigiloauth/vigilo/internal/domain/user"

// MockLoginAttemptService is a mock implementation of the loginattempt.LoginAttemptStore interface.
type MockLoginAttemptService struct {
	// SaveLoginAttemptFunc is a mock function for the SaveLoginAttempt method.
	SaveLoginAttemptFunc func(attempt *user.UserLoginAttempt) error

	// GetLoginAttemptsFunc is a mock function for the GetLoginAttempts method.
	GetLoginAttemptsFunc func(userID string) []*user.UserLoginAttempt

	// HandleFailedLoginAttemptFunc is a mock function for the HandleFailedLoginAttempt method.
	HandleFailedLoginAttemptFunc func(user *user.User, attempt *user.UserLoginAttempt) error
}

// SaveLoginAttempt calls the mock SaveLoginAttemptFunc.
func (m *MockLoginAttemptService) SaveLoginAttempt(attempt *user.UserLoginAttempt) error {
	return m.SaveLoginAttemptFunc(attempt)
}

// GetLoginAttempts calls the mock GetLoginAttemptsFunc.
func (m *MockLoginAttemptService) GetLoginAttempts(userID string) []*user.UserLoginAttempt {
	return m.GetLoginAttemptsFunc(userID)
}

// HandleFailedLoginAttempt calls the mock HandleFailedLoginAttemptFunc.
func (m *MockLoginAttemptService) HandleFailedLoginAttempt(user *user.User, attempt *user.UserLoginAttempt) error {
	return m.HandleFailedLoginAttemptFunc(user, attempt)
}
