package service

import (
	"context"

	"github.com/vigiloauth/vigilo/v2/idp/config"
	token "github.com/vigiloauth/vigilo/v2/internal/domain/token"
	"github.com/vigiloauth/vigilo/v2/internal/errors"
	"github.com/vigiloauth/vigilo/v2/internal/utils"
)

var _ token.TokenManagementService = (*tokenManagementService)(nil)

type tokenManagementService struct {
	tokenService token.TokenService
	logger       *config.Logger
	module       string
}

func NewTokenManagementService(tokenService token.TokenService) token.TokenManagementService {
	return &tokenManagementService{
		tokenService: tokenService,
		logger:       config.GetServerConfig().Logger(),
		module:       "Token Management Service",
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
func (s *tokenManagementService) Introspect(ctx context.Context, tokenStr string) *token.TokenIntrospectionResponse {
	requestID := utils.GetRequestID(ctx)
	s.logger.Debug(s.module, requestID, "[Introspect]: Starting token introspection")

	tokenData, err := s.tokenService.GetTokenData(ctx, tokenStr)
	if err != nil {
		s.logger.Warn(s.module, requestID, "[Introspect]: An error occurred retrieving the requested token: %v", err)
		return &token.TokenIntrospectionResponse{Active: false}
	}
	s.logger.Debug(s.module, requestID, "[Introspect]: Successfully retrieved token data, ID: %s", utils.TruncateSensitive(tokenData.ID))

	tokenClaims, err := s.tokenService.ParseToken(ctx, tokenStr)
	if err != nil {
		s.logger.Error(s.module, requestID, "[Introspect]: An error occurred parsing the token: %v", err)
		return &token.TokenIntrospectionResponse{Active: false}
	}
	s.logger.Debug(s.module, requestID, "[Introspect]: Successfully parsed token claims, subject: %s", utils.TruncateSensitive(tokenClaims.Subject))

	response := token.NewTokenIntrospectionResponse(tokenClaims)
	if err := s.tokenService.ValidateToken(ctx, tokenStr); err != nil {
		s.logger.Warn(s.module, requestID, "[Introspect]: Token is either blacklisted or expired... Setting active to false")
		response.Active = false
	} else {
		s.logger.Debug(s.module, requestID, "[Introspect]: Token validation successful, token is active")
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
func (s *tokenManagementService) Revoke(ctx context.Context, tokenStr string) error {
	requestID := utils.GetRequestID(ctx)
	s.logger.Debug(s.module, requestID, "[Revoke]: Starting token revocation")

	if err := s.tokenService.BlacklistToken(ctx, tokenStr); err != nil {
		s.logger.Error(s.module, requestID, "[Revoke]: Failed to blacklist token: %v", err)
		return errors.Wrap(err, "", "failed to revoke token")
	}

	s.logger.Debug(s.module, requestID, "[Revoke]: Successfully blacklisted token")
	return nil
}
