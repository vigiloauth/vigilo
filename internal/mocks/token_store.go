package mocks

import (
	"time"

	"github.com/vigiloauth/vigilo/internal/token"
)

type MockTokenStore struct {
	AddTokenFunc           func(token string, email string, expiration time.Time)
	IsTokenBlacklistedFunc func(token string) bool
	GetTokenFunc           func(token string, email string) (*token.TokenData, error)
	DeleteTokenFunc        func(token string) error
}

func (m *MockTokenStore) AddToken(token string, email string, expiration time.Time) {
	m.AddTokenFunc(token, email, expiration)
}

func (m *MockTokenStore) IsTokenBlacklisted(token string) bool {
	return m.IsTokenBlacklistedFunc(token)
}

func (m *MockTokenStore) GetToken(token string, email string) (*token.TokenData, error) {
	return m.GetTokenFunc(token, email)
}

func (m *MockTokenStore) DeleteToken(token string) error {
	return m.DeleteTokenFunc(token)
}
