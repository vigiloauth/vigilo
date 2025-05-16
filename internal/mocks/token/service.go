package mocks

import (
	"context"
	"time"

	token "github.com/vigiloauth/vigilo/v2/internal/domain/token"
)

var _ token.TokenService = (*MockTokenService)(nil)

type MockTokenService struct {
	GenerateAccessTokenFunc  func(ctx context.Context, subject, audience, scopes, roles, nonce string) (string, error)
	GenerateRefreshTokenFunc func(ctx context.Context, subject, audience, scopes, roles, nonce string) (string, error)
	GenerateIDTokenFunc      func(ctx context.Context, userID, clientID, scopes, nonce string, authTime time.Time) (string, error)
	GetTokenFunc             func(ctx context.Context, token string) (*token.TokenData, error)
	DeleteTokenFunc          func(ctx context.Context, token string) error
	ValidateTokenFunc        func(ctx context.Context, token string) error
	BlacklistTokenFunc       func(ctx context.Context, token string) error
	DeleteExpiredTokensFunc  func(ctx context.Context) error
	ParseTokenFunc           func(ctx context.Context, tokenStr string) (*token.TokenClaims, error)
}

func (m *MockTokenService) GetTokenData(ctx context.Context, token string) (*token.TokenData, error) {
	return m.GetTokenFunc(ctx, token)
}

func (m *MockTokenService) GenerateAccessToken(ctx context.Context, subject, audience, scopes, roles, nonce string) (string, error) {
	return m.GenerateAccessTokenFunc(ctx, subject, audience, scopes, roles, nonce)
}

func (m *MockTokenService) GenerateRefreshToken(ctx context.Context, subject, audience, scopes, roles, nonce string) (string, error) {
	return m.GenerateRefreshTokenFunc(ctx, subject, audience, scopes, roles, nonce)
}

func (m *MockTokenService) DeleteToken(ctx context.Context, token string) error {
	return m.DeleteTokenFunc(ctx, token)
}

func (m *MockTokenService) ValidateToken(ctx context.Context, token string) error {
	return m.ValidateTokenFunc(ctx, token)
}

func (m *MockTokenService) BlacklistToken(ctx context.Context, token string) error {
	return m.BlacklistTokenFunc(ctx, token)
}

func (m *MockTokenService) DeleteExpiredTokens(ctx context.Context) error {
	return m.DeleteExpiredTokensFunc(ctx)
}

func (m *MockTokenService) ParseToken(ctx context.Context, tokenStr string) (*token.TokenClaims, error) {
	return m.ParseTokenFunc(ctx, tokenStr)
}

func (m *MockTokenService) GenerateIDToken(ctx context.Context, userID, clientID, scopes, nonce string, authTime time.Time) (string, error) {
	return m.GenerateIDTokenFunc(ctx, userID, clientID, scopes, nonce, authTime)
}
