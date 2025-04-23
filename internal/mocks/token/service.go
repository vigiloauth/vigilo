package mocks

import (
	"context"
	"time"

	token "github.com/vigiloauth/vigilo/internal/domain/token"
)

var _ token.TokenService = (*MockTokenService)(nil)

type MockTokenService struct {
	GenerateTokenFunc                  func(ctx context.Context, id, scopes string, duration time.Duration) (string, error)
	GenerateTokensWithAudienceFunc     func(ctx context.Context, userID, clientID, scopes string) (string, string, error)
	SaveTokenFunc                      func(ctx context.Context, token, id string, expiry time.Time) error
	ParseTokenFunc                     func(token string) (*token.TokenClaims, error)
	IsTokenBlacklistedFunc             func(ctx context.Context, token string) (bool, error)
	GetTokenFunc                       func(ctx context.Context, token string) (*token.TokenData, error)
	DeleteTokenFunc                    func(ctx context.Context, token string) error
	IsTokenExpiredFunc                 func(token string) bool
	ValidateTokenFunc                  func(ctx context.Context, token string) error
	DeleteTokenAsyncFunc               func(ctx context.Context, token string) <-chan error
	GenerateRefreshAndAccessTokensFunc func(ctx context.Context, subject, scopes string) (string, string, error)
	BlacklistTokenFunc                 func(ctx context.Context, token string) error
	DeleteExpiredTokensFunc            func(ctx context.Context) error
}

func (m *MockTokenService) GenerateToken(ctx context.Context, id, scopes string, duration time.Duration) (string, error) {
	return m.GenerateTokenFunc(ctx, id, scopes, duration)
}

func (m *MockTokenService) GenerateTokensWithAudience(ctx context.Context, userID, clientID, scopes string) (string, string, error) {
	return m.GenerateTokensWithAudienceFunc(ctx, userID, clientID, scopes)
}

func (m *MockTokenService) SaveToken(ctx context.Context, token, id string, expiry time.Time) error {
	return m.SaveTokenFunc(ctx, token, id, expiry)
}

func (m *MockTokenService) ParseToken(token string) (*token.TokenClaims, error) {
	return m.ParseTokenFunc(token)
}

func (m *MockTokenService) IsTokenBlacklisted(ctx context.Context, token string) (bool, error) {
	return m.IsTokenBlacklistedFunc(ctx, token)
}

func (m *MockTokenService) GetToken(ctx context.Context, token string) (*token.TokenData, error) {
	return m.GetTokenFunc(ctx, token)
}

func (m *MockTokenService) DeleteToken(ctx context.Context, token string) error {
	return m.DeleteTokenFunc(ctx, token)
}

func (m *MockTokenService) IsTokenExpired(token string) bool {
	return m.IsTokenExpiredFunc(token)
}

func (m *MockTokenService) ValidateToken(ctx context.Context, token string) error {
	return m.ValidateTokenFunc(ctx, token)
}

func (m *MockTokenService) DeleteTokenAsync(ctx context.Context, token string) <-chan error {
	return m.DeleteTokenAsyncFunc(ctx, token)
}

func (m *MockTokenService) GenerateRefreshAndAccessTokens(ctx context.Context, subject, scopes string) (string, string, error) {
	return m.GenerateRefreshAndAccessTokensFunc(ctx, subject, scopes)
}

func (m *MockTokenService) BlacklistToken(ctx context.Context, token string) error {
	return m.BlacklistTokenFunc(ctx, token)
}

func (m *MockTokenService) DeleteExpiredTokens(ctx context.Context) error {
	return m.DeleteExpiredTokensFunc(ctx)
}
