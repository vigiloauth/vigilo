package mocks

import (
	"context"

	domain "github.com/vigiloauth/vigilo/v2/internal/domain/jwt"
	tokens "github.com/vigiloauth/vigilo/v2/internal/domain/token"
)

var _ domain.JWTService = (*MockJWTService)(nil)

type MockJWTService struct {
	ParseWithClaimsFunc func(ctx context.Context, tokenString string) (*tokens.TokenClaims, error)
}

func (m *MockJWTService) ParseWithClaims(ctx context.Context, tokenString string) (*tokens.TokenClaims, error) {
	return m.ParseWithClaimsFunc(ctx, tokenString)
}
