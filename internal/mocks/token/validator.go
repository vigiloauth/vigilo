package mocks

import (
	"context"

	token "github.com/vigiloauth/vigilo/v2/internal/domain/token"
)

var _ token.TokenValidator = (*MockTokenValidator)(nil)

type MockTokenValidator struct {
	ValidateTokenFunc func(ctx context.Context, tokenStr string) error
}

func (m *MockTokenValidator) ValidateToken(ctx context.Context, tokenStr string) error {
	return m.ValidateTokenFunc(ctx, tokenStr)
}
