package mocks

import (
	"context"

	token "github.com/vigiloauth/vigilo/v2/internal/domain/token"
	users "github.com/vigiloauth/vigilo/v2/internal/domain/user"
	"github.com/vigiloauth/vigilo/v2/internal/types"
)

var _ token.TokenGrantService = (*MockTokenGrantService)(nil)

type MockTokenGrantService struct {
	IssueClientCredentialsTokenFunc func(ctx context.Context, clientID, clientSecret, grantType string, scopes types.Scope) (*token.TokenResponse, error)
	IssueResourceOwnerTokenFunc     func(ctx context.Context, clientID, clientSecret, grantType string, scopes types.Scope, user *users.UserLoginAttempt) (*token.TokenResponse, error)
	RefreshTokenFunc                func(ctx context.Context, clientID, clientSecret, grantType, refreshToken string, scopes types.Scope) (*token.TokenResponse, error)
}

func (m *MockTokenGrantService) IssueClientCredentialsToken(ctx context.Context, clientID, clientSecret, grantType string, scopes types.Scope) (*token.TokenResponse, error) {
	return m.IssueClientCredentialsTokenFunc(ctx, clientID, clientSecret, grantType, scopes)
}

func (m *MockTokenGrantService) IssueResourceOwnerToken(ctx context.Context, clientID, clientSecret, grantType string, scopes types.Scope, user *users.UserLoginAttempt) (*token.TokenResponse, error) {
	return m.IssueResourceOwnerTokenFunc(ctx, clientID, clientSecret, grantType, scopes, user)
}

func (m *MockTokenGrantService) RefreshToken(ctx context.Context, clientID, clientSecret, grantType, refreshToken string, scopes types.Scope) (*token.TokenResponse, error) {
	return m.RefreshTokenFunc(ctx, clientID, clientSecret, grantType, refreshToken, scopes)
}
