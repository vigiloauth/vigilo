package mocks

import (
	"time"

	"github.com/vigiloauth/vigilo/internal/token"
)

// MockTokenStore is a mock implementation of the token.TokenStore interface.
type MockTokenStore struct {
	// AddTokenFunc is a mock function for the AddToken method.
	AddTokenFunc func(token string, email string, expiration time.Time)

	// IsTokenBlacklistedFunc is a mock function for the IsTokenBlacklisted method.
	IsTokenBlacklistedFunc func(token string) bool

	// GetTokenFunc is a mock function for the GetToken method.
	GetTokenFunc func(token string, email string) (*token.TokenData, error)

	// DeleteTokenFunc is a mock function for the DeleteToken method.
	DeleteTokenFunc func(token string) error
}

// AddToken calls the mock AddTokenFunc.
func (m *MockTokenStore) AddToken(token string, email string, expiration time.Time) {
	m.AddTokenFunc(token, email, expiration)
}

// IsTokenBlacklisted calls the mock IsTokenBlacklistedFunc.
func (m *MockTokenStore) IsTokenBlacklisted(token string) bool {
	return m.IsTokenBlacklistedFunc(token)
}

// GetToken calls the mock GetTokenFunc.
func (m *MockTokenStore) GetToken(token string, email string) (*token.TokenData, error) {
	return m.GetTokenFunc(token, email)
}

// DeleteToken calls the mock DeleteTokenFunc.
func (m *MockTokenStore) DeleteToken(token string) error {
	return m.DeleteTokenFunc(token)
}
