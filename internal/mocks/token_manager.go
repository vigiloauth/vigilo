package mocks

import (
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/vigiloauth/vigilo/internal/token"
)

// MockTokenManager is a mock implementation of the token.TokenManager interface.
type MockTokenManager struct {
	// GenerateTokenFunc is a mock function for the GenerateToken method.
	GenerateTokenFunc func(email string, duration time.Duration) (string, error)

	// AddTokenFunc is a mock function for the AddToken method.
	AddTokenFunc func(token, email string, expiry time.Time)

	// ParseTokenFunc is a mock function for the ParseToken method.
	ParseTokenFunc func(token string) (*jwt.StandardClaims, error)

	// IsTokenBlacklistedFunc is a mock function for the IsTokenBlacklisted method.
	IsTokenBlacklistedFunc func(token string) bool

	// GetTokenFunc is a mock function for the GetToken method.
	GetTokenFunc func(email string, token string) (*token.TokenData, error)

	// DeleteTokenFunc is a mock function for the DeleteToken method.
	DeleteTokenFunc func(token string) error

	// IsTokenExpired is a mock function for the IsTokenExpired method
	IsTokenExpiredFunc func(token string) bool
}

// GenerateToken calls the mock GenerateTokenFunc.
func (m *MockTokenManager) GenerateToken(email string, duration time.Duration) (string, error) {
	return m.GenerateTokenFunc(email, duration)
}

// AddToken calls the mock AddTokenFunc.
func (m *MockTokenManager) AddToken(token, email string, expiry time.Time) {
	m.AddTokenFunc(token, email, expiry)
}

// ParseToken calls the mock ParseTokenFunc.
func (m *MockTokenManager) ParseToken(token string) (*jwt.StandardClaims, error) {
	return m.ParseTokenFunc(token)
}

// IsTokenBlacklisted calls the mock IsTokenBlacklistedFunc.
func (m *MockTokenManager) IsTokenBlacklisted(token string) bool {
	return m.IsTokenBlacklistedFunc(token)
}

// GetToken calls the mock GetTokenFunc.
func (m *MockTokenManager) GetToken(email string, token string) (*token.TokenData, error) {
	return m.GetTokenFunc(email, token)
}

// DeleteToken calls the mock DeleteTokenFunc.
func (m *MockTokenManager) DeleteToken(token string) error {
	return m.DeleteTokenFunc(token)
}

// IsTokenExpired calls the mock IsTokenExpiredFunc
func (m *MockTokenManager) IsTokenExpired(token string) bool {
	return m.IsTokenExpiredFunc(token)
}
