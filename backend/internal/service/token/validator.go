package service

import (
	"context"
	"time"

	"github.com/vigiloauth/vigilo/v2/idp/config"
	token "github.com/vigiloauth/vigilo/v2/internal/domain/token"
	"github.com/vigiloauth/vigilo/v2/internal/errors"
	"github.com/vigiloauth/vigilo/v2/internal/utils"
)

var _ token.TokenValidator = (*tokenValidator)(nil)

type tokenValidator struct {
	repo   token.TokenRepository
	parser token.TokenParser
	logger *config.Logger
	module string
}

func NewTokenValidator(
	tokenRepo token.TokenRepository,
	tokenParser token.TokenParser,
) token.TokenValidator {
	return &tokenValidator{
		repo:   tokenRepo,
		parser: tokenParser,
		logger: config.GetServerConfig().Logger(),
		module: "Token Validator",
	}
}

// ValidateToken checks to see if a token is blacklisted or expired.
//
// Parameters:
//   - ctx Context: The context for managing timeouts and cancellations.
//   - token string: The token string to check.
//
// Returns:
//   - error: An error if the token is blacklisted or expired.
func (t *tokenValidator) ValidateToken(ctx context.Context, tokenStr string) error {
	requestID := utils.GetRequestID(ctx)

	if t.isTokenExpired(ctx, tokenStr) {
		t.logger.Warn(t.module, requestID, "[ValidateToken]: Token '%s' is expired", utils.TruncateSensitive(tokenStr))
		return errors.New(errors.ErrCodeExpiredToken, "the token is expired")
	} else if t.isTokenBlacklisted(ctx, tokenStr) {
		t.logger.Warn(t.module, requestID, "[ValidateToken]: Token '%s' is blacklisted", utils.TruncateSensitive(tokenStr))
		return errors.New(errors.ErrCodeUnauthorized, "the token is blacklisted")
	}

	return nil
}

func (t *tokenValidator) isTokenExpired(ctx context.Context, tokenStr string) bool {
	requestID := utils.GetRequestID(ctx)

	claims, err := t.parser.ParseToken(ctx, tokenStr)
	if err != nil {
		t.logger.Warn(t.module, requestID, "[isTokenExpired]: Failed to parse token: %v", err)
		return true
	}

	return time.Now().Unix() > claims.ExpiresAt
}

func (t *tokenValidator) isTokenBlacklisted(ctx context.Context, tokenStr string) bool {
	requestID := utils.GetRequestID(ctx)
	hashedToken := utils.EncodeSHA256(tokenStr)

	isBlacklisted, err := t.repo.IsTokenBlacklisted(ctx, hashedToken)
	if err != nil {
		t.logger.Warn(t.module, requestID, "[isTokenBlacklisted]: An error occurred checking if the token was blacklisted: %v", err)
		return true
	}

	return isBlacklisted
}
