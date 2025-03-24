package mocks

import (
	"time"

	authzCode "github.com/vigiloauth/vigilo/internal/domain/authzcode"
)

type MockAuthorizationCodeService struct {
	GenerateAuthorizationCodeFunc    func(userID, clientID, redirectURI, scope string) (string, error)
	ValidateAuthorizationCodeFunc    func(code, clientID, redirectURI string) (*authzCode.AuthorizationCodeData, error)
	RevokeAuthorizationCodeFunc      func(code string) error
	SetAuthorizationCodeLifeTimeFunc func(lifetime time.Duration)
	GetAuthorizationCodeFunc         func(code string) *authzCode.AuthorizationCodeData
}

func (m *MockAuthorizationCodeService) GenerateAuthorizationCode(userID, clientID, redirectURI, scope string) (string, error) {
	return m.GenerateAuthorizationCodeFunc(userID, clientID, redirectURI, scope)
}

func (m *MockAuthorizationCodeService) ValidateAuthorizationCode(code, clientID, redirectURI string) (*authzCode.AuthorizationCodeData, error) {
	return m.ValidateAuthorizationCodeFunc(code, clientID, redirectURI)
}

func (m *MockAuthorizationCodeService) RevokeAuthorizationCode(code string) error {
	return m.RevokeAuthorizationCodeFunc(code)
}

func (m *MockAuthorizationCodeService) SetAuthorizationCodeLifeTime(lieftime time.Duration) {
	m.SetAuthorizationCodeLifeTimeFunc(lieftime)
}

func (m *MockAuthorizationCodeService) GetAuthorizationCode(code string) *authzCode.AuthorizationCodeData {
	return m.GetAuthorizationCodeFunc(code)
}
