package service

import (
	"context"

	"github.com/vigiloauth/vigilo/v2/idp/config"
	"github.com/vigiloauth/vigilo/v2/internal/crypto"
	token "github.com/vigiloauth/vigilo/v2/internal/domain/token"
	"github.com/vigiloauth/vigilo/v2/internal/errors"
	"github.com/vigiloauth/vigilo/v2/internal/utils"
)

var _ token.TokenManager = (*tokenManager)(nil)

type tokenManager struct {
	repo      token.TokenRepository
	parser    token.TokenParser
	validator token.TokenValidator

	logger *config.Logger
	module string
}

func NewTokenManager(
	repo token.TokenRepository,
	parser token.TokenParser,
	validator token.TokenValidator,
) token.TokenManager {
	return &tokenManager{
		repo:      repo,
		parser:    parser,
		validator: validator,

		logger: config.GetServerConfig().Logger(),
		module: "Token Management Service",
	}
}

// Introspect checks the validity and metadata of the given token string.
//
// Parameters:
//   - ctx Context: The context for managing timeouts and cancellations.
//   - tokenStr string: The token to introspect.
//
// Returns:
//   - *TokenIntrospectionResponse: TokenIntrospectionResponse containing information about the token.
func (m *tokenManager) Introspect(ctx context.Context, tokenStr string) *token.TokenIntrospectionResponse {
	requestID := utils.GetRequestID(ctx)

	if _, err := m.repo.GetToken(ctx, tokenStr); err != nil {
		m.logger.Warn(m.module, requestID, "[Introspect]: An error occurred retrieving the requested token: %v", err)
		return &token.TokenIntrospectionResponse{Active: false}
	}

	tokenClaims, err := m.parser.ParseToken(ctx, tokenStr)
	if err != nil {
		m.logger.Error(m.module, requestID, "[Introspect]: An error occurred parsing the token: %v", err)
		return &token.TokenIntrospectionResponse{Active: false}
	}

	response := token.NewTokenIntrospectionResponse(tokenClaims)
	if err := m.validator.ValidateToken(ctx, tokenStr); err != nil {
		m.logger.Warn(m.module, requestID, "[Introspect]: Token is either blacklisted or expired... Setting active to false")
		response.Active = false
	}

	return response
}

// Revoke invalidates the given token string, rendering it unusable.
//
// Parameters:
//   - ctx Context: The context for managing timeouts and cancellations.
//   - tokenStr string: The token to introspect.
//
// Returns:
//   - error: An error if revocation fails.
func (m *tokenManager) Revoke(ctx context.Context, tokenStr string) error {
	requestID := utils.GetRequestID(ctx)
	hashedToken := crypto.EncodeSHA256(tokenStr)

	if err := m.repo.BlacklistToken(ctx, hashedToken); err != nil {
		m.logger.Error(m.module, requestID, "[Revoke]: Failed to blacklist token: %v", err)
		return errors.Wrap(err, "", "failed to revoke token")
	}

	return nil
}

// GetTokenData retrieves the token data from the token repository.
//
// Parameters:
//   - ctx Context: The context for managing timeouts and cancellations.
//   - token string: The token string to retrieve.
//
// Returns:
//   - *TokenData: The TokenData if the token is valid, or nil if not found or invalid.
//   - error: An error if the token is not found, expired, or the subject doesn't match.
func (m *tokenManager) GetTokenData(ctx context.Context, tokenStr string) (*token.TokenData, error) {
	requestID := utils.GetRequestID(ctx)
	hashedToken := crypto.EncodeSHA256(tokenStr)

	tokenData, err := m.repo.GetToken(ctx, hashedToken)
	if err != nil {
		m.logger.Error(m.module, requestID, "[GetTokenData]: Failed to retrieve token data: %v", err)
		return nil, errors.Wrap(err, "", "failed to retrieve token data")
	}

	return tokenData, nil
}

// BlacklistToken adds the specified token to the blacklist, preventing it from being used
// for further authentication or authorization. The token is marked as invalid, even if it
// has not yet expired.
//
// Parameters:
//   - ctx Context: The context for managing timeouts and cancellations.
//   - tokenStr string: The token to be blacklisted. This is the token that will no longer be valid for further use.
//
// Returns:
//   - error: An error if the token is not found in the token store or if it has already expired, in which case it cannot be blacklisted.
func (m *tokenManager) BlacklistToken(ctx context.Context, tokenStr string) error {
	requestID := utils.GetRequestID(ctx)
	hashedToken := crypto.EncodeSHA256(tokenStr)

	if err := m.repo.BlacklistToken(ctx, hashedToken); err != nil {
		m.logger.Error(m.module, requestID, "[BlacklistToken]: An error occurred while attempting to blacklist token: %v", err)
		return errors.Wrap(err, errors.ErrCodeInternalServerError, "failed to blacklist token")
	}

	return nil
}

// DeleteExpiredTokens retrieves expired tokens from the repository and deletes them.
//
// Parameters:
//   - ctx Context: The context for managing timeouts and cancellations.
//
// Returns:
//   - error: An error if retrieval or deletion fails.
func (m *tokenManager) DeleteExpiredTokens(ctx context.Context) error {
	requestID := utils.GetRequestID(ctx)

	tokens, err := m.repo.GetExpiredTokens(ctx)
	if err != nil {
		m.logger.Error(m.module, requestID, "[DeleteExpiredTokens]: Failed to retrieve expired tokens: %v", err)
		return errors.Wrap(err, "", "failed to retrieve expired tokens")
	}

	for _, token := range tokens {
		if err := m.repo.DeleteToken(ctx, token.Token); err != nil {
			m.logger.Error(m.module, requestID, "[DeleteExpiredTokens]: Failed to delete an expired token: %v", err)
			return errors.Wrap(err, errors.ErrCodeInternalServerError, "an error occurred deleting expired tokens")
		}
	}

	return nil
}

// DeleteToken removes a token from the token repository.
//
// Parameters:
//   - ctx Context: The context for managing timeouts and cancellations.
//   - tokenStr string: The token string to delete.
//
// Returns:
//   - error: An error if the token deletion fails.
func (m *tokenManager) DeleteToken(ctx context.Context, tokenStr string) error {
	requestID := utils.GetRequestID(ctx)
	hashedToken := crypto.EncodeSHA256(tokenStr)

	err := m.repo.DeleteToken(ctx, hashedToken)
	if err != nil {
		m.logger.Error(m.module, requestID, "[DeleteToken]: An error occurred deleting a token: %v", err)
		return errors.Wrap(err, "", "an error occurred deleting the given token")
	}

	return nil
}
