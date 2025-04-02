package mocks

import (
	"time"

	authzCode "github.com/vigiloauth/vigilo/internal/domain/authzcode"
	client "github.com/vigiloauth/vigilo/internal/domain/client"
)

type MockAuthorizationCodeService struct {
	GenerateAuthorizationCodeFunc    func(req *client.ClientAuthorizationRequest) (string, error)
	ValidateAuthorizationCodeFunc    func(code, clientID, redirectURI string) (*authzCode.AuthorizationCodeData, error)
	RevokeAuthorizationCodeFunc      func(code string) error
	SetAuthorizationCodeLifeTimeFunc func(lifetime time.Duration)
	GetAuthorizationCodeFunc         func(code string) (*authzCode.AuthorizationCodeData, error)
}

func (m *MockAuthorizationCodeService) GenerateAuthorizationCode(req *client.ClientAuthorizationRequest) (string, error) {
	return m.GenerateAuthorizationCodeFunc(req)
}

func (m *MockAuthorizationCodeService) ValidateAuthorizationCode(code, clientID, redirectURI string) (*authzCode.AuthorizationCodeData, error) {
	return m.ValidateAuthorizationCodeFunc(code, clientID, redirectURI)
}

func (m *MockAuthorizationCodeService) RevokeAuthorizationCode(code string) error {
	return m.RevokeAuthorizationCodeFunc(code)
}

func (m *MockAuthorizationCodeService) SetAuthorizationCodeLifeTime(lifetime time.Duration) {
	m.SetAuthorizationCodeLifeTimeFunc(lifetime)
}

func (m *MockAuthorizationCodeService) GetAuthorizationCode(code string) (*authzCode.AuthorizationCodeData, error) {
	return m.GetAuthorizationCodeFunc(code)
}
