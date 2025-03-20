package mocks

import (
	"time"

	"github.com/vigiloauth/vigilo/internal/token"
)

// MockTokenStore is a mock implementation of the token.TokenStore interface.
type MockTokenStore struct {
	// SaveTokenFunc is a mock function for the AddToken method.
	SaveTokenFunc func(token string, id string, expiration time.Time)

	// IsTokenBlacklistedFunc is a mock function for the IsTokenBlacklisted method.
	IsTokenBlacklistedFunc func(token string) bool

	// GetTokenFunc is a mock function for the GetToken method.
	GetTokenFunc func(token string, id string) (*token.TokenData, error)

	// DeleteTokenFunc is a mock function for the DeleteToken method.
	DeleteTokenFunc func(token string) error
}

// AddToken calls the mock AddTokenFunc.
func (m *MockTokenStore) SaveToken(token string, id string, expiration time.Time) {
	m.SaveTokenFunc(token, id, expiration)
}

// IsTokenBlacklisted calls the mock IsTokenBlacklistedFunc.
func (m *MockTokenStore) IsTokenBlacklisted(token string) bool {
	return m.IsTokenBlacklistedFunc(token)
}

// GetToken calls the mock GetTokenFunc.
func (m *MockTokenStore) GetToken(token string, id string) (*token.TokenData, error) {
	return m.GetTokenFunc(token, id)
}

// DeleteToken calls the mock DeleteTokenFunc.
func (m *MockTokenStore) DeleteToken(token string) error {
	return m.DeleteTokenFunc(token)
}
