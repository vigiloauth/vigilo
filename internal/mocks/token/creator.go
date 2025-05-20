package mocks

import (
	"context"
	"time"

	claims "github.com/vigiloauth/vigilo/v2/internal/domain/claims"
	token "github.com/vigiloauth/vigilo/v2/internal/domain/token"
	"github.com/vigiloauth/vigilo/v2/internal/types"
)

var _ token.TokenCreator = (*MockTokenCreator)(nil)

type MockTokenCreator struct {
	CreateAccessTokenFunc           func(ctx context.Context, subject string, audience string, scopes types.Scope, roles string, nonce string) (string, error)
	CreateRefreshTokenFunc          func(ctx context.Context, subject string, audience string, scopes types.Scope, roles string, nonce string) (string, error)
	CreateAccessTokenWithClaimsFunc func(ctx context.Context, subject string, audience string, scopes types.Scope, roles string, nonce string, claims *claims.ClaimsRequest) (string, error)
	CreateIDTokenFunc               func(ctx context.Context, userID string, clientID string, scopes types.Scope, nonce string, authTime time.Time) (string, error)
}

func (m *MockTokenCreator) CreateAccessToken(ctx context.Context, subject string, audience string, scopes types.Scope, roles string, nonce string) (string, error) {
	return m.CreateAccessTokenFunc(ctx, subject, audience, scopes, roles, nonce)
}

func (m *MockTokenCreator) CreateRefreshToken(ctx context.Context, subject string, audience string, scopes types.Scope, roles string, nonce string) (string, error) {
	return m.CreateRefreshTokenFunc(ctx, subject, audience, scopes, roles, nonce)
}

func (m *MockTokenCreator) CreateAccessTokenWithClaims(ctx context.Context, subject string, audience string, scopes types.Scope, roles string, nonce string, claims *claims.ClaimsRequest) (string, error) {
	return m.CreateAccessTokenWithClaimsFunc(ctx, subject, audience, scopes, roles, nonce, claims)
}

func (m *MockTokenCreator) CreateIDToken(ctx context.Context, userID string, clientID string, scopes types.Scope, nonce string, authTime time.Time) (string, error) {
	return m.CreateIDTokenFunc(ctx, userID, clientID, scopes, nonce, authTime)
}
