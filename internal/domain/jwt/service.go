package domain

import (
	"context"

	token "github.com/vigiloauth/vigilo/v2/internal/domain/token"
)

type JWTService interface {
	ParseWithClaims(ctx context.Context, tokenString string) (*token.TokenClaims, error)
	SignToken(ctx context.Context, claims *token.TokenClaims) (string, error)
}
