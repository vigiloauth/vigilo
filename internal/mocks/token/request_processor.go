package mocks

import (
	"context"

	authz "github.com/vigiloauth/vigilo/v2/internal/domain/authzcode"
	token "github.com/vigiloauth/vigilo/v2/internal/domain/token"
	users "github.com/vigiloauth/vigilo/v2/internal/domain/user"
	"github.com/vigiloauth/vigilo/v2/internal/types"
)

var _ token.TokenRequestProcessor = (*MockTokenRequestProcessor)(nil)

type MockTokenRequestProcessor struct {
	IssueClientCredentialsTokenFunc        func(ctx context.Context, clientID, clientSecret, grantType string, scopes types.Scope) (*token.TokenResponse, error)
	IssueResourceOwnerTokenFunc            func(ctx context.Context, clientID, clientSecret, grantType string, scopes types.Scope, user *users.UserLoginAttempt) (*token.TokenResponse, error)
	RefreshTokenFunc                       func(ctx context.Context, clientID, clientSecret, grantType, refreshToken string, scopes types.Scope) (*token.TokenResponse, error)
	ExchangeAuthorizationCodeForTokensFunc func(ctx context.Context, authzCodeData *authz.AuthorizationCodeData) (*token.TokenResponse, error)
}

func (m *MockTokenRequestProcessor) IssueClientCredentialsToken(ctx context.Context, clientID, clientSecret, grantType string, scopes types.Scope) (*token.TokenResponse, error) {
	return m.IssueClientCredentialsTokenFunc(ctx, clientID, clientSecret, grantType, scopes)
}

func (m *MockTokenRequestProcessor) IssueResourceOwnerToken(ctx context.Context, clientID, clientSecret, grantType string, scopes types.Scope, user *users.UserLoginAttempt) (*token.TokenResponse, error) {
	return m.IssueResourceOwnerTokenFunc(ctx, clientID, clientSecret, grantType, scopes, user)
}

func (m *MockTokenRequestProcessor) RefreshToken(ctx context.Context, clientID, clientSecret, grantType, refreshToken string, scopes types.Scope) (*token.TokenResponse, error) {
	return m.RefreshTokenFunc(ctx, clientID, clientSecret, grantType, refreshToken, scopes)
}

func (m *MockTokenRequestProcessor) ExchangeAuthorizationCodeForTokens(ctx context.Context, authzCodeData *authz.AuthorizationCodeData) (*token.TokenResponse, error) {
	return m.ExchangeAuthorizationCodeForTokensFunc(ctx, authzCodeData)
}
