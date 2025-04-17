package mocks

import (
	"time"

	token "github.com/vigiloauth/vigilo/internal/domain/token"
)

// MockTokenService is a mock implementation of the token.TokenManager interface.
type MockTokenService struct {
	// GenerateTokenFunc is a mock function for the GenerateToken method.
	GenerateTokenFunc func(id, scopes string, duration time.Duration) (string, error)

	// GenerateTokenPairFunc is a mock function for the GenerateTokenPair method.
	GenerateTokensWithAudienceFunc func(userID, clientID, scopes string) (string, string, error)

	// SaveTokenFunc is a mock function for the AddToken method.
	SaveTokenFunc func(token, id string, expiry time.Time)

	// ParseTokenFunc is a mock function for the ParseToken method.
	ParseTokenFunc func(token string) (*token.TokenClaims, error)

	// IsTokenBlacklistedFunc is a mock function for the IsTokenBlacklisted method.
	IsTokenBlacklistedFunc func(token string) bool

	// GetTokenFunc is a mock function for the GetToken method.
	GetTokenFunc func(token string) (*token.TokenData, error)

	// DeleteTokenFunc is a mock function for the DeleteToken method.
	DeleteTokenFunc func(token string) error

	// IsTokenExpired is a mock function for the IsTokenExpired method
	IsTokenExpiredFunc func(token string) bool

	ValidateTokenFunc func(token string) error

	DeleteTokenAsyncFunc func(token string) <-chan error

	GenerateRefreshAndAccessTokensFunc func(subject, scopes string) (string, string, error)

	BlacklistTokenFunc func(token string) error

	DeleteExpiredTokensFunc func()
}

// GenerateToken calls the mock GenerateTokenFunc.
func (m *MockTokenService) GenerateToken(id, scopes string, duration time.Duration) (string, error) {
	return m.GenerateTokenFunc(id, scopes, duration)
}

// GenerateTokens calls the mock GenerateTokensFunc
func (m *MockTokenService) GenerateTokensWithAudience(userID, clientID, scopes string) (string, string, error) {
	return m.GenerateTokensWithAudienceFunc(userID, clientID, scopes)
}

// AddToken calls the mock AddTokenFunc.
func (m *MockTokenService) SaveToken(token, id string, expiry time.Time) {
	m.SaveTokenFunc(token, id, expiry)
}

// ParseToken calls the mock ParseTokenFunc.
func (m *MockTokenService) ParseToken(token string) (*token.TokenClaims, error) {
	return m.ParseTokenFunc(token)
}

// IsTokenBlacklisted calls the mock IsTokenBlacklistedFunc.
func (m *MockTokenService) IsTokenBlacklisted(token string) bool {
	return m.IsTokenBlacklistedFunc(token)
}

// GetToken calls the mock GetTokenFunc.
func (m *MockTokenService) GetToken(token string) (*token.TokenData, error) {
	return m.GetTokenFunc(token)
}

// DeleteToken calls the mock DeleteTokenFunc.
func (m *MockTokenService) DeleteToken(token string) error {
	return m.DeleteTokenFunc(token)
}

// IsTokenExpired calls the mock IsTokenExpiredFunc
func (m *MockTokenService) IsTokenExpired(token string) bool {
	return m.IsTokenExpiredFunc(token)
}

func (m *MockTokenService) ValidateToken(token string) error {
	return m.ValidateTokenFunc(token)
}

func (m *MockTokenService) DeleteTokenAsync(token string) <-chan error {
	return m.DeleteTokenAsyncFunc(token)
}

func (m *MockTokenService) GenerateRefreshAndAccessTokens(subject, scopes string) (string, string, error) {
	return m.GenerateRefreshAndAccessTokensFunc(subject, scopes)
}

func (m *MockTokenService) BlacklistToken(token string) error {
	return m.BlacklistTokenFunc(token)
}

func (m *MockTokenService) DeleteExpiredTokens() {
	m.DeleteExpiredTokensFunc()
}
