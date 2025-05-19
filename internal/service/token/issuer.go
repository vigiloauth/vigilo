package service

import (
	"context"
	"time"

	"github.com/vigiloauth/vigilo/v2/idp/config"
	claims "github.com/vigiloauth/vigilo/v2/internal/domain/claims"
	token "github.com/vigiloauth/vigilo/v2/internal/domain/token"
	"github.com/vigiloauth/vigilo/v2/internal/errors"
	"github.com/vigiloauth/vigilo/v2/internal/types"
	"github.com/vigiloauth/vigilo/v2/internal/utils"
)

var _ token.TokenIssuer = (*tokenIssuer)(nil)

type tokenIssuer struct {
	tokenService token.TokenService
	logger       *config.Logger
	module       string
}

func NewTokenIssuer(tokenService token.TokenService) token.TokenIssuer {
	return &tokenIssuer{
		tokenService: tokenService,
		logger:       config.GetServerConfig().Logger(),
		module:       "Token Issuer",
	}
}

// IssueTokenPair generates a new access token and refresh token pair for a given user and client.
//
// Parameters:
//   - ctx context.Context: The context for managing timeouts and cancellations.
//   - userID string: The ID of the user for whom the token pair is being issued.
//   - clientID string: The ID of the client requesting the tokens.
//   - scopes types.Scope: The scopes to associate with the issued tokens.
//   - nonce string: A value used to associate a client session with an ID token for replay protection.
//   - claims *domain.ClaimsRequest: Optional custom claims to include in the tokens.
//
// Returns:
//   - string: The issued access token.
//   - string: The issued refresh token.
//   - error: An error if token issuance fails.
func (s *tokenIssuer) IssueTokenPair(
	ctx context.Context,
	userID string,
	clientID string,
	scopes types.Scope,
	nonce string,
	claims *claims.ClaimsRequest,
) (string, string, error) {
	requestID := utils.GetRequestID(ctx)
	s.logger.Debug(s.module, requestID, "[IssueTokenPair]: Starting token pair issuance for user: %s, client: %s",
		utils.TruncateSensitive(userID),
		utils.TruncateSensitive(clientID))

	s.logger.Debug(s.module, requestID, "[IssueTokenPair]: Requested scopes: %s", scopes.String())

	if claims != nil {
		s.logger.Debug(s.module, requestID, "[IssueTokenPair]: Custom claims requested")
	}

	accessToken, err := s.tokenService.GenerateAccessTokenWithClaims(
		ctx,
		userID,
		clientID,
		scopes, "",
		nonce,
		types.AccessTokenType,
		claims,
	)

	if err != nil {
		s.logger.Error(s.module, requestID, "[IssueTokenPair]: Failed to generate access token: %v", err)
		return "", "", errors.Wrap(err, "", "failed to generate access token")
	}
	s.logger.Debug(s.module, requestID, "[IssueTokenPair]: Successfully generated access token")

	refreshToken, err := s.tokenService.GenerateToken(
		ctx,
		userID,
		clientID,
		scopes, "",
		nonce,
		types.RefreshTokenType,
	)

	if err != nil {
		s.logger.Error(s.module, requestID, "[IssueTokenPair]: Failed to generate refresh token: %v", err)
		return "", "", errors.Wrap(err, "", "failed to generate refresh token")
	}
	s.logger.Debug(s.module, requestID, "[IssueTokenPair]: Successfully generated refresh token")

	s.logger.Debug(s.module, requestID, "[IssueTokenPair]: Successfully issued token pair")
	return accessToken, refreshToken, nil
}

// IssueIDToken creates an ID token for the specified user and client.
//
// The ID token is a JWT that contains claims about the authentication of the user.
// It includes information such as the user ID, client ID, scopes, and nonce for
// replay protection. The token is generated and then stored in the token store.
//
// Parameters:
//   - ctx context.Context: Context for the request, containing the request ID for logging.
//   - userID string: The unique identifier of the user.
//   - clientID string: The client application identifier requesting the token.
//   - scopes string: Space-separated list of requested scopes.
//   - nonce string: A random string used to prevent replay attacks.
//   - authTime *Time: Time at which the user was authenticated. The value of time can be nil as it only applies when a request with "max_age" was given
//
// Returns:
//   - string: The signed ID token as a JWT string.
//   - error: An error if token generation fails.
func (s *tokenIssuer) IssueIDToken(ctx context.Context, userID string, clientID string, scopes types.Scope, nonce string, authTime time.Time) (string, error) {
	requestID := utils.GetRequestID(ctx)

	IDToken, err := s.tokenService.GenerateIDToken(
		ctx,
		userID,
		clientID,
		scopes,
		nonce,
		authTime,
	)

	if err != nil {
		s.logger.Error(s.module, requestID, "[IssueIDToken]: Failed to issue ID Token: %v", err)
		return "", errors.Wrap(err, "", "failed to create ID Token")
	}

	return IDToken, nil
}
