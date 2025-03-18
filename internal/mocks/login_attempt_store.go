package mocks

import login "github.com/vigiloauth/vigilo/internal/auth/loginattempt"

// MockLoginAttemptStore is a mock implementation of the loginattempt.LoginAttemptStore interface.
type MockLoginAttemptStore struct {
	// SaveLoginAttemptFunc is a mock function for the SaveLoginAttempt method.
	SaveLoginAttemptFunc func(attempt *login.LoginAttempt)

	// GetLoginAttemptsFunc is a mock function for the GetLoginAttempts method.
	GetLoginAttemptsFunc func(userID string) []*login.LoginAttempt
}

// SaveLoginAttempt calls the mock SaveLoginAttemptFunc.
func (m *MockLoginAttemptStore) SaveLoginAttempt(attempt *login.LoginAttempt) {
	m.SaveLoginAttemptFunc(attempt)
}

// GetLoginAttempts calls the mock GetLoginAttemptsFunc.
func (m *MockLoginAttemptStore) GetLoginAttempts(userID string) []*login.LoginAttempt {
	return m.GetLoginAttemptsFunc(userID)
}
