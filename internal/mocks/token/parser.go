package mocks

import (
	"context"

	token "github.com/vigiloauth/vigilo/v2/internal/domain/token"
)

var _ token.TokenParser = (*MockTokenParser)(nil)

type MockTokenParser struct {
	ParseTokenFunc func(ctx context.Context, tokenString string) (*token.TokenClaims, error)
}

func (m *MockTokenParser) ParseToken(ctx context.Context, tokenStr string) (*token.TokenClaims, error) {
	return m.ParseTokenFunc(ctx, tokenStr)
}
