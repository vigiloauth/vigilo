package mocks

import login "github.com/vigiloauth/vigilo/internal/auth/loginattempt"

type MockLoginAttemptStore struct {
	SaveLoginAttemptFunc func(attempt *login.LoginAttempt)
	GetLoginAttemptsFunc func(userID string) []*login.LoginAttempt
}

func (m *MockLoginAttemptStore) SaveLoginAttempt(attempt *login.LoginAttempt) {
	m.SaveLoginAttemptFunc(attempt)
}

func (m *MockLoginAttemptStore) GetLoginAttempts(userID string) []*login.LoginAttempt {
	return m.GetLoginAttemptsFunc(userID)
}
