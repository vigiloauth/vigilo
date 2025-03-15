package mocks

import (
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/vigiloauth/vigilo/internal/token"
)

type MockTokenManager struct {
	GenerateTokenFunc      func(email string, duration time.Duration) (string, error)
	AddTokenFunc           func(token, email string, expiry time.Time)
	ParseTokenFunc         func(token string) (*jwt.StandardClaims, error)
	IsTokenBlacklistedFunc func(token string) bool
	GetTokenFunc           func(email string, token string) (*token.TokenData, error)
	DeleteTokenFunc        func(token string) error
}

func (m *MockTokenManager) GenerateToken(email string, duration time.Duration) (string, error) {
	return m.GenerateTokenFunc(email, duration)
}

func (m *MockTokenManager) AddToken(token, email string, expiry time.Time) {
	m.AddTokenFunc(token, email, expiry)
}

func (m *MockTokenManager) ParseToken(token string) (*jwt.StandardClaims, error) {
	return m.ParseTokenFunc(token)
}

func (m *MockTokenManager) IsTokenBlacklisted(token string) bool {
	return m.IsTokenBlacklistedFunc(token)
}

func (m *MockTokenManager) GetToken(email string, token string) (*token.TokenData, error) {
	return m.GetTokenFunc(email, token)
}

func (m *MockTokenManager) DeleteToken(token string) error {
	return m.DeleteTokenFunc(token)
}
