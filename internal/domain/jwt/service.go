package domain

import (
	"context"

	domain "github.com/vigiloauth/vigilo/v2/internal/domain/token"
)

type JWTService interface {
	ParseWithClaims(ctx context.Context, tokenString string) (*domain.TokenClaims, error)
}
