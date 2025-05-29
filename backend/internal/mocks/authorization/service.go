package mocks

import (
	"context"

	authz "github.com/vigiloauth/vigilo/v2/internal/domain/authorization"
	authzCode "github.com/vigiloauth/vigilo/v2/internal/domain/authzcode"
	client "github.com/vigiloauth/vigilo/v2/internal/domain/client"
	token "github.com/vigiloauth/vigilo/v2/internal/domain/token"
	user "github.com/vigiloauth/vigilo/v2/internal/domain/user"
)

var _ authz.AuthorizationService = (*MockAuthorizationService)(nil)

type MockAuthorizationService struct {
	AuthorizeClientFunc          func(ctx context.Context, authorizationRequest *client.ClientAuthorizationRequest) (string, error)
	AuthorizeTokenExchangeFunc   func(ctx context.Context, tokenRequest *token.TokenRequest) (*authzCode.AuthorizationCodeData, error)
	AuthorizeUserInfoRequestFunc func(ctx context.Context, accessTokenClaims *token.TokenClaims) (*user.User, error)
	UpdateAuthorizationCodeFunc  func(ctx context.Context, authzCode *authzCode.AuthorizationCodeData) error
}

func (m *MockAuthorizationService) AuthorizeClient(ctx context.Context, authorizationRequest *client.ClientAuthorizationRequest) (string, error) {
	return m.AuthorizeClientFunc(ctx, authorizationRequest)
}

func (m *MockAuthorizationService) AuthorizeTokenExchange(ctx context.Context, tokenRequest *token.TokenRequest) (*authzCode.AuthorizationCodeData, error) {
	return m.AuthorizeTokenExchangeFunc(ctx, tokenRequest)
}

func (m *MockAuthorizationService) AuthorizeUserInfoRequest(ctx context.Context, accessTokenClaims *token.TokenClaims) (*user.User, error) {
	return m.AuthorizeUserInfoRequestFunc(ctx, accessTokenClaims)
}

func (m *MockAuthorizationService) UpdateAuthorizationCode(ctx context.Context, authData *authzCode.AuthorizationCodeData) error {
	return m.UpdateAuthorizationCodeFunc(ctx, authData)
}
