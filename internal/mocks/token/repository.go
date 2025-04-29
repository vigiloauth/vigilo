package mocks

import (
	"context"
	"time"

	token "github.com/vigiloauth/vigilo/v2/internal/domain/token"
)

var _ token.TokenRepository = (*MockTokenRepository)(nil)

type MockTokenRepository struct {
	SaveTokenFunc          func(ctx context.Context, token string, id string, expiration time.Time) error
	IsTokenBlacklistedFunc func(ctx context.Context, token string) (bool, error)
	GetTokenFunc           func(ctx context.Context, token string) (*token.TokenData, error)
	DeleteTokenFunc        func(ctx context.Context, token string) error
	BlacklistTokenFunc     func(ctx context.Context, token string) error
	ExistsByTokenIDFunc    func(ctx context.Context, tokenID string) (bool, error)
	GetExpiredTokensFunc   func(ctx context.Context) ([]*token.TokenData, error)
}

func (m *MockTokenRepository) SaveToken(ctx context.Context, token string, id string, expiration time.Time) error {
	return m.SaveTokenFunc(ctx, token, id, expiration)
}

func (m *MockTokenRepository) IsTokenBlacklisted(ctx context.Context, token string) (bool, error) {
	return m.IsTokenBlacklistedFunc(ctx, token)
}

func (m *MockTokenRepository) GetToken(ctx context.Context, token string) (*token.TokenData, error) {
	return m.GetTokenFunc(ctx, token)
}

func (m *MockTokenRepository) DeleteToken(ctx context.Context, token string) error {
	return m.DeleteTokenFunc(ctx, token)
}

func (m *MockTokenRepository) BlacklistToken(ctx context.Context, token string) error {
	return m.BlacklistTokenFunc(ctx, token)
}

func (m *MockTokenRepository) ExistsByTokenID(ctx context.Context, tokenID string) (bool, error) {
	return m.ExistsByTokenIDFunc(ctx, tokenID)
}

func (m *MockTokenRepository) GetExpiredTokens(ctx context.Context) ([]*token.TokenData, error) {
	return m.GetExpiredTokensFunc(ctx)
}
