package mocks

import (
	"context"

	jwt "github.com/vigiloauth/vigilo/v2/internal/domain/jwt"
	tokens "github.com/vigiloauth/vigilo/v2/internal/domain/token"
)

var _ jwt.JWTService = (*MockJWTService)(nil)

type MockJWTService struct {
	ParseWithClaimsFunc func(ctx context.Context, tokenString string) (*tokens.TokenClaims, error)
	SignTokenFunc       func(ctx context.Context, claims *tokens.TokenClaims) (string, error)
}

func (m *MockJWTService) ParseWithClaims(ctx context.Context, tokenString string) (*tokens.TokenClaims, error) {
	return m.ParseWithClaimsFunc(ctx, tokenString)
}

func (m *MockJWTService) SignToken(ctx context.Context, claims *tokens.TokenClaims) (string, error) {
	return m.SignTokenFunc(ctx, claims)
}
