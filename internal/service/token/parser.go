package service

import (
	"context"

	"github.com/vigiloauth/vigilo/v2/idp/config"
	jwt "github.com/vigiloauth/vigilo/v2/internal/domain/jwt"
	token "github.com/vigiloauth/vigilo/v2/internal/domain/token"
	"github.com/vigiloauth/vigilo/v2/internal/errors"
	"github.com/vigiloauth/vigilo/v2/internal/utils"
)

var _ token.TokenParser = (*tokenParser)(nil)

type tokenParser struct {
	jwtService jwt.JWTService
	logger     *config.Logger
	module     string
}

func NewTokenParser(jwtService jwt.JWTService) token.TokenParser {
	return &tokenParser{
		jwtService: jwtService,
		logger:     config.GetServerConfig().Logger(),
		module:     "Token Parser",
	}
}

// ParseToken parses a JWT token string into TokenClaims.
//
// Parameters:
//   - ctx ctx.Context: Context for the request, containing the request ID for logging.
//   - tokenString string: The JWT token string to parse and validate.
//
// Returns:
//   - *token.TokenClaims: The parsed token claims if successful.
//   - error: An error if token parsing, decryption, or validation fails.
func (t *tokenParser) ParseToken(ctx context.Context, tokenString string) (*token.TokenClaims, error) {
	requestID := utils.GetRequestID(ctx)

	claims, err := t.jwtService.ParseWithClaims(ctx, tokenString)
	if err != nil {
		t.logger.Error(t.module, requestID, "[ParseToken]: Failed to parse token: %v", err)
		return nil, errors.Wrap(err, "", "failed to parse token with claims")
	}

	return claims, nil
}
