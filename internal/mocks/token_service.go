package mocks

import (
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/vigiloauth/vigilo/internal/token"
)

// MockTokenService is a mock implementation of the token.TokenManager interface.
type MockTokenService struct {
	// GenerateTokenFunc is a mock function for the GenerateToken method.
	GenerateTokenFunc func(id string, duration time.Duration) (string, error)

	// SaveTokenFunc is a mock function for the AddToken method.
	SaveTokenFunc func(token, id string, expiry time.Time)

	// ParseTokenFunc is a mock function for the ParseToken method.
	ParseTokenFunc func(token string) (*jwt.StandardClaims, error)

	// IsTokenBlacklistedFunc is a mock function for the IsTokenBlacklisted method.
	IsTokenBlacklistedFunc func(token string) bool

	// GetTokenFunc is a mock function for the GetToken method.
	GetTokenFunc func(id string, token string) (*token.TokenData, error)

	// DeleteTokenFunc is a mock function for the DeleteToken method.
	DeleteTokenFunc func(token string) error

	// IsTokenExpired is a mock function for the IsTokenExpired method
	IsTokenExpiredFunc func(token string) bool
}

// GenerateToken calls the mock GenerateTokenFunc.
func (m *MockTokenService) GenerateToken(id string, duration time.Duration) (string, error) {
	return m.GenerateTokenFunc(id, duration)
}

// AddToken calls the mock AddTokenFunc.
func (m *MockTokenService) SaveToken(token, id string, expiry time.Time) {
	m.SaveTokenFunc(token, id, expiry)
}

// ParseToken calls the mock ParseTokenFunc.
func (m *MockTokenService) ParseToken(token string) (*jwt.StandardClaims, error) {
	return m.ParseTokenFunc(token)
}

// IsTokenBlacklisted calls the mock IsTokenBlacklistedFunc.
func (m *MockTokenService) IsTokenBlacklisted(token string) bool {
	return m.IsTokenBlacklistedFunc(token)
}

// GetToken calls the mock GetTokenFunc.
func (m *MockTokenService) GetToken(id string, token string) (*token.TokenData, error) {
	return m.GetTokenFunc(id, token)
}

// DeleteToken calls the mock DeleteTokenFunc.
func (m *MockTokenService) DeleteToken(token string) error {
	return m.DeleteTokenFunc(token)
}

// IsTokenExpired calls the mock IsTokenExpiredFunc
func (m *MockTokenService) IsTokenExpired(token string) bool {
	return m.IsTokenExpiredFunc(token)
}
