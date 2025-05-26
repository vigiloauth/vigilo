package mocks

import (
	"context"
	"net/http"

	token "github.com/vigiloauth/vigilo/v2/internal/domain/token"
	users "github.com/vigiloauth/vigilo/v2/internal/domain/user"
	"github.com/vigiloauth/vigilo/v2/internal/types"
)

var _ token.TokenGrantProcessor = (*MockTokenGrantProcessor)(nil)

type MockTokenGrantProcessor struct {
	IssueClientCredentialsTokenFunc func(ctx context.Context, clientID, clientSecret, grantType string, scopes types.Scope) (*token.TokenResponse, error)
	IssueResourceOwnerTokenFunc     func(ctx context.Context, clientID, clientSecret, grantType string, scopes types.Scope, user *users.UserLoginRequest) (*token.TokenResponse, error)
	RefreshTokenFunc                func(ctx context.Context, clientID, clientSecret, grantType, refreshToken string, scopes types.Scope) (*token.TokenResponse, error)
	ExchangeAuthorizationCodeFunc   func(ctx context.Context, req *token.TokenRequest) (*token.TokenResponse, error)
	IntrospectTokenFunc             func(ctx context.Context, r *http.Request, tokenStr string) (*token.TokenIntrospectionResponse, error)
	RevokeTokenFunc                 func(ctx context.Context, r *http.Request, tokenStr string) error
}

func (m *MockTokenGrantProcessor) IssueClientCredentialsToken(ctx context.Context, clientID, clientSecret, grantType string, scopes types.Scope) (*token.TokenResponse, error) {
	return m.IssueClientCredentialsTokenFunc(ctx, clientID, clientSecret, grantType, scopes)
}

func (m *MockTokenGrantProcessor) IssueResourceOwnerToken(ctx context.Context, clientID, clientSecret, grantType string, scopes types.Scope, user *users.UserLoginRequest) (*token.TokenResponse, error) {
	return m.IssueResourceOwnerTokenFunc(ctx, clientID, clientSecret, grantType, scopes, user)
}

func (m *MockTokenGrantProcessor) RefreshToken(ctx context.Context, clientID, clientSecret, grantType, refreshToken string, scopes types.Scope) (*token.TokenResponse, error) {
	return m.RefreshTokenFunc(ctx, clientID, clientSecret, grantType, refreshToken, scopes)
}

func (m *MockTokenGrantProcessor) ExchangeAuthorizationCode(ctx context.Context, req *token.TokenRequest) (*token.TokenResponse, error) {
	return m.ExchangeAuthorizationCodeFunc(ctx, req)
}

func (m *MockTokenGrantProcessor) IntrospectToken(ctx context.Context, r *http.Request, tokenStr string) (*token.TokenIntrospectionResponse, error) {
	return m.IntrospectTokenFunc(ctx, r, tokenStr)
}

func (m *MockTokenGrantProcessor) RevokeToken(ctx context.Context, r *http.Request, tokenStr string) error {
	return m.RevokeTokenFunc(ctx, r, tokenStr)
}
