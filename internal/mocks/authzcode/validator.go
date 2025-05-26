package mocks

import (
	"context"

	domain "github.com/vigiloauth/vigilo/v2/internal/domain/authzcode"
	client "github.com/vigiloauth/vigilo/v2/internal/domain/client"
)

var _ domain.AuthorizationCodeValidator = (*MockAuthorizationCodeRequestValidator)(nil)

type MockAuthorizationCodeRequestValidator struct {
	ValidateRequestFunc           func(ctx context.Context, req *client.ClientAuthorizationRequest) error
	ValidateAuthorizationCodeFunc func(ctx context.Context, code, clientID, redirectURI string) error
	ValidatePKCEFunc              func(ctx context.Context, authzCodeData *domain.AuthorizationCodeData, codeVerifier string) error
}

func (m *MockAuthorizationCodeRequestValidator) ValidateRequest(ctx context.Context, req *client.ClientAuthorizationRequest) error {
	return m.ValidateRequestFunc(ctx, req)
}

func (m *MockAuthorizationCodeRequestValidator) ValidateAuthorizationCode(ctx context.Context, code, clientID, redirectURI string) error {
	return m.ValidateAuthorizationCodeFunc(ctx, code, clientID, redirectURI)
}

func (m *MockAuthorizationCodeRequestValidator) ValidatePKCE(ctx context.Context, authzCodeData *domain.AuthorizationCodeData, codeVerifier string) error {
	return m.ValidatePKCEFunc(ctx, authzCodeData, codeVerifier)
}
