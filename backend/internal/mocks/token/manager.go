package mocks

import (
	"context"

	tokens "github.com/vigiloauth/vigilo/v2/internal/domain/token"
)

var _ tokens.TokenManager = (*MockTokenManager)(nil)

type MockTokenManager struct {
	IntrospectFunc          func(ctx context.Context, tokenStr string) *tokens.TokenIntrospectionResponse
	RevokeFunc              func(ctx context.Context, tokenStr string) error
	GetTokenDataFunc        func(ctx context.Context, tokenStr string) (*tokens.TokenData, error)
	DeleteTokenFunc         func(ctx context.Context, token string) error
	BlacklistTokenFunc      func(ctx context.Context, token string) error
	DeleteExpiredTokensFunc func(ctx context.Context) error
}

func (m *MockTokenManager) Introspect(ctx context.Context, tokenStr string) *tokens.TokenIntrospectionResponse {
	return m.IntrospectFunc(ctx, tokenStr)
}

func (m *MockTokenManager) Revoke(ctx context.Context, tokenStr string) error {
	return m.RevokeFunc(ctx, tokenStr)
}

func (m *MockTokenManager) GetTokenData(ctx context.Context, tokenStr string) (*tokens.TokenData, error) {
	return m.GetTokenDataFunc(ctx, tokenStr)
}

func (m *MockTokenManager) DeleteToken(ctx context.Context, token string) error {
	return m.DeleteTokenFunc(ctx, token)
}

func (m *MockTokenManager) BlacklistToken(ctx context.Context, token string) error {
	return m.BlacklistTokenFunc(ctx, token)
}

func (m *MockTokenManager) DeleteExpiredTokens(ctx context.Context) error {
	return m.DeleteExpiredTokensFunc(ctx)
}
