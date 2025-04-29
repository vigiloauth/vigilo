package mocks

import (
	"context"

	authzCode "github.com/vigiloauth/vigilo/v2/internal/domain/authzcode"
	client "github.com/vigiloauth/vigilo/v2/internal/domain/client"
)

var _ authzCode.AuthorizationCodeService = (*MockAuthorizationCodeService)(nil)

type MockAuthorizationCodeService struct {
	GenerateAuthorizationCodeFunc func(ctx context.Context, req *client.ClientAuthorizationRequest) (string, error)
	ValidateAuthorizationCodeFunc func(ctx context.Context, code, clientID, redirectURI string) (*authzCode.AuthorizationCodeData, error)
	RevokeAuthorizationCodeFunc   func(ctx context.Context, code string) error
	GetAuthorizationCodeFunc      func(ctx context.Context, code string) (*authzCode.AuthorizationCodeData, error)
	ValidatePKCEFunc              func(authzCodeData *authzCode.AuthorizationCodeData, codeVerifier string) error
	SaveAuthorizationCodeFunc     func(ctx context.Context, authzCodeData *authzCode.AuthorizationCodeData) error
}

func (m *MockAuthorizationCodeService) GenerateAuthorizationCode(ctx context.Context, req *client.ClientAuthorizationRequest) (string, error) {
	return m.GenerateAuthorizationCodeFunc(ctx, req)
}

func (m *MockAuthorizationCodeService) ValidateAuthorizationCode(ctx context.Context, code, clientID, redirectURI string) (*authzCode.AuthorizationCodeData, error) {
	return m.ValidateAuthorizationCodeFunc(ctx, code, clientID, redirectURI)
}

func (m *MockAuthorizationCodeService) RevokeAuthorizationCode(ctx context.Context, code string) error {
	return m.RevokeAuthorizationCodeFunc(ctx, code)
}

func (m *MockAuthorizationCodeService) GetAuthorizationCode(ctx context.Context, code string) (*authzCode.AuthorizationCodeData, error) {
	return m.GetAuthorizationCodeFunc(ctx, code)
}

func (m *MockAuthorizationCodeService) ValidatePKCE(authzCodeData *authzCode.AuthorizationCodeData, codeVerifier string) error {
	return m.ValidatePKCEFunc(authzCodeData, codeVerifier)
}

func (m *MockAuthorizationCodeService) SaveAuthorizationCode(ctx context.Context, authzData *authzCode.AuthorizationCodeData) error {
	return m.SaveAuthorizationCodeFunc(ctx, authzData)
}
