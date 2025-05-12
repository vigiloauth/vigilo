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
	GenerateTokensFunc           func(ctx context.Context, authCodeData *authzCode.AuthorizationCodeData) (*token.TokenResponse, error)
	AuthorizeUserInfoRequestFunc func(ctx context.Context, accessTokenClaims *token.TokenClaims) (*user.User, error)
}

func (m *MockAuthorizationService) AuthorizeClient(ctx context.Context, authorizationRequest *client.ClientAuthorizationRequest) (string, error) {
	return m.AuthorizeClientFunc(ctx, authorizationRequest)
}

func (m *MockAuthorizationService) AuthorizeTokenExchange(ctx context.Context, tokenRequest *token.TokenRequest) (*authzCode.AuthorizationCodeData, error) {
	return m.AuthorizeTokenExchangeFunc(ctx, tokenRequest)
}

func (m *MockAuthorizationService) GenerateTokens(ctx context.Context, authCodeData *authzCode.AuthorizationCodeData) (*token.TokenResponse, error) {
	return m.GenerateTokensFunc(ctx, authCodeData)
}

func (m *MockAuthorizationService) AuthorizeUserInfoRequest(ctx context.Context, accessTokenClaims *token.TokenClaims) (*user.User, error) {
	return m.AuthorizeUserInfoRequestFunc(ctx, accessTokenClaims)
}
