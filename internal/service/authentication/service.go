package service

import (
	"context"
	"net/http"
	"strings"

	"github.com/vigiloauth/vigilo/v2/idp/config"
	"github.com/vigiloauth/vigilo/v2/internal/constants"
	auth "github.com/vigiloauth/vigilo/v2/internal/domain/authentication"
	client "github.com/vigiloauth/vigilo/v2/internal/domain/client"
	token "github.com/vigiloauth/vigilo/v2/internal/domain/token"
	user "github.com/vigiloauth/vigilo/v2/internal/domain/user"
	"github.com/vigiloauth/vigilo/v2/internal/errors"
	"github.com/vigiloauth/vigilo/v2/internal/types"
	"github.com/vigiloauth/vigilo/v2/internal/utils"
	"github.com/vigiloauth/vigilo/v2/internal/web"
)

var _ auth.AuthenticationService = (*authenticationService)(nil)

type authenticationService struct {
	tokenService  token.TokenService
	clientService client.ClientService
	userService   user.UserService

	logger *config.Logger
	module string
}

func NewAuthenticationService(
	tokenService token.TokenService,
	clientService client.ClientService,
	userService user.UserService,
) auth.AuthenticationService {
	return &authenticationService{
		tokenService:  tokenService,
		clientService: clientService,
		userService:   userService,
		logger:        config.GetServerConfig().Logger(),
		module:        "Authentication Service",
	}
}

// IssueClientCredentialsToken generates a token using the client credentials grant type.
// This flow is typically used for machine-to-machine authentication where no user is involved.
//
// Parameters:
//   - ctx Context: The context for managing timeouts and cancellations.
//   - clientID string: The registered client identifier.
//   - clientSecret string: The client's secret used for authentication.
//   - requestedGrantType string: The OAuth 2.0 grant type (should be "client_credentials").
//   - requestedScopes string: Space-delimited list of requested scopes.
//
// Returns:
//   - *TokenResponse: A TokenResponse containing the generated access token and related metadata, or an error if token issuance fails.
func (s *authenticationService) IssueClientCredentialsToken(ctx context.Context, clientID string, clientSecret string, grantType string, scopes types.Scope) (*token.TokenResponse, error) {
	requestID := utils.GetRequestID(ctx)

	if err := s.clientService.AuthenticateClient(ctx, clientID, clientSecret, grantType, scopes); err != nil {
		s.logger.Error(s.module, requestID, "[IssueClientCredentialsToken]: Failed to authenticate client: %v", err)
		return nil, errors.Wrap(err, "", "failed to authenticate client")
	}

	accessToken, err := s.tokenService.GenerateToken(ctx, "", clientID, scopes, "", "", types.AccessTokenType)
	if err != nil {
		s.logger.Error(s.module, requestID, "[IssueClientCredentialsToken]: An error occurred generating an access token: %v", err)
		return nil, errors.Wrap(err, "", "failed to issue tokens")
	}

	refreshToken, err := s.tokenService.GenerateToken(ctx, "", clientID, scopes, "", "", types.RefreshTokenType)
	if err != nil {
		s.logger.Error(s.module, requestID, "[IssueClientCredentialsToken]: An error occurred generating a refresh token: %v", err)
		return nil, errors.Wrap(err, "", "failed to issue tokens")
	}

	return &token.TokenResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresIn:    int(config.GetServerConfig().TokenConfig().AccessTokenDuration().Seconds()),
		TokenType:    token.BearerToken,
		Scope:        scopes,
	}, nil
}

// IssueResourceOwnerToken generates a token using the resource owner password credentials grant type.
// This flow is used when the user provides their credentials directly to the client application.
//
// Parameters:
//   - ctx Context: The context for managing timeouts and cancellations.
//   - clientID string: The registered client identifier.
//   - clientSecret string: The client's secret used for authentication.
//   - requestedGrantType string: The OAuth 2.0 grant type (should be "password").
//   - requestedScopes string: Space-delimited list of requested scopes.
//   - loginAttempt *UserLoginAttempts: User login details including username and password.
//
// Returns:
//   - *TokenResponse: A TokenResponse containing the generated access token and related metadata, or an error if token issuance fails.
func (s *authenticationService) IssueResourceOwnerToken(ctx context.Context, clientID string, clientSecret string, grantType string, scopes types.Scope, req *user.UserLoginAttempt) (*token.TokenResponse, error) {
	requestID := utils.GetRequestID(ctx)
	if err := s.clientService.AuthenticateClient(ctx, clientID, clientSecret, grantType, scopes); err != nil {
		s.logger.Error(s.module, requestID, "[IssueResourceOwnerToken]: Failed to authenticate client: %v", err)
		return nil, err
	}

	loginResponse, err := s.authenticateUser(ctx, req, clientID)
	if err != nil {
		s.logger.Error(s.module, requestID, "[IssueResourceOwnerToken]: Failed to authenticate user: %v", err)
		return nil, errors.Wrap(err, errors.ErrCodeInvalidGrant, "failed to authenticate user")
	}

	userRoles := strings.Join(loginResponse.Roles, " ")
	accessToken, err := s.tokenService.GenerateToken(ctx, loginResponse.UserID, clientID, scopes, userRoles, "", types.AccessTokenType)
	if err != nil {
		s.logger.Error(s.module, requestID, "[IssueResourceOwnerToken]: Failed to generate an access token: %v", err)
		return nil, err
	}

	refreshToken, err := s.tokenService.GenerateToken(ctx, loginResponse.UserID, clientID, scopes, userRoles, "", types.RefreshTokenType)
	if err != nil {
		s.logger.Error(s.module, requestID, "[IssueResourceOwnerToken]: Failed to generate a refresh token: %v", err)
		return nil, err
	}

	return &token.TokenResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresIn:    int(config.GetServerConfig().TokenConfig().AccessTokenDuration().Seconds()),
		TokenType:    token.BearerToken,
		Scope:        scopes,
	}, nil
}

// RefreshAccessToken generates a new access token using a previously issued refresh token.
// This method implements the OAuth 2.0 refresh token grant flow.
//
// Parameters:
//   - ctx Context: The context for managing timeouts and cancellations.
//   - clientID string: The registered client identifier.
//   - clientSecret string: The client's secret used for authentication.
//   - requestedGrantType string: The OAuth 2.0 grant type (should be "refresh_token").
//   - refreshToken string: The previously issued refresh token.
//   - requestedScopes string: The clients scopes.
//
// Returns:
//   - *TokenResponse: A TokenResponse containing the newly generated access token and related metadata, or an error if token refresh fails.
func (s *authenticationService) RefreshAccessToken(ctx context.Context, clientID string, clientSecret string, grantType string, refreshToken string, scopes types.Scope) (*token.TokenResponse, error) {
	requestID := utils.GetRequestID(ctx)
	if err := s.clientService.AuthenticateClient(ctx, clientID, clientSecret, grantType, scopes); err != nil {
		s.logger.Error(s.module, requestID, "[RefreshAccessToken]: Failed to authenticate client: %v", err)
		s.blacklistToken(ctx, refreshToken)
		return nil, err
	}

	if err := s.validateRefreshTokenAndMatchClient(ctx, clientID, refreshToken); err != nil {
		s.logger.Error(s.module, requestID, "[RefreshAccessToken]: Error validating refresh token: %v", err)
		s.blacklistToken(ctx, refreshToken)
		return nil, err
	}

	tokenData, err := s.tokenService.GetTokenData(ctx, refreshToken)
	if err != nil {
		s.blacklistToken(ctx, refreshToken)
		return nil, err
	}

	if scopes == "" {
		scopes = tokenData.TokenClaims.Scopes
	} else {
		requested := strings.Fields(scopes.String())
		original := strings.Fields(tokenData.TokenClaims.Scopes.String())
		if !utils.IsSubset(requested, original) {
			if err := s.tokenService.BlacklistToken(ctx, refreshToken); err != nil {
				s.logger.Warn(s.module, requestID, "[RefreshAccessToken]: Failed to blacklist old refresh token: %v", err)
			}
			return nil, errors.New(errors.ErrCodeInvalidRequest, "requested scopes exceed originally granted scopes")
		}
	}

	userID := tokenData.TokenClaims.Subject
	newAccessToken, err := s.tokenService.GenerateToken(ctx, userID, clientID, scopes, "", "", types.AccessTokenType)
	if err != nil {
		s.blacklistToken(ctx, refreshToken)
		return nil, errors.Wrap(err, "", "failed to generate new tokens")
	}

	newRefreshToken, err := s.tokenService.GenerateToken(ctx, userID, clientID, scopes, "", "", types.RefreshTokenType)
	if err != nil {
		s.blacklistToken(ctx, refreshToken)
		return nil, errors.Wrap(err, "", "failed to generate new tokens")
	}

	s.logger.Debug(s.module, requestID, "[RefreshAccessToken]: Attempting to blacklist old refresh token")
	s.blacklistToken(ctx, refreshToken)

	return &token.TokenResponse{
		AccessToken:  newAccessToken,
		RefreshToken: newRefreshToken,
		ExpiresIn:    int(config.GetServerConfig().TokenConfig().AccessTokenDuration().Seconds()),
		TokenType:    token.BearerToken,
	}, nil
}

// IntrospectToken verifies the validity of a given token by introspecting its details.
// This method checks whether the token is valid, expired, or revoked and returns the
// associated token information if it is valid.
//
// Parameters:
//   - ctx Context: The context for managing timeouts and cancellations.
//   - token string: The token to be introspected.
//
// Returns:
//   - *TokenIntrospectionResponse: A struct containing token details such as
//     validity, expiration, and any associated metadata. If the token is valid, this
//     response will include all relevant claims associated with the token.
func (s *authenticationService) IntrospectToken(ctx context.Context, tokenStr string) *token.TokenIntrospectionResponse {
	requestID := utils.GetRequestID(ctx)
	retrievedToken, err := s.tokenService.GetTokenData(ctx, tokenStr)
	if retrievedToken == nil || err != nil {
		return &token.TokenIntrospectionResponse{Active: false}
	}

	claims, err := s.tokenService.ParseToken(ctx, tokenStr)
	if err != nil {
		s.logger.Error(s.module, requestID, "[IntrospectToken]: Failed to parse token: %v", err)
		return &token.TokenIntrospectionResponse{Active: false}
	}

	response := token.NewTokenIntrospectionResponse(claims)
	if err := s.tokenService.ValidateToken(ctx, tokenStr); err != nil {
		s.logger.Debug(s.module, requestID, "[IntrospectToken]: Token is either blacklisted or expired... Setting active to false")
		response.Active = false
	} else {
		response.Active = true
	}

	return response
}

// AuthenticateClientRequest validates the provided Authorization header.
// It supports both "Basic" and "Bearer" authentication schemes.
//
// For "Basic" authentication, it decodes the base64-encoded credentials
// and checks that the client ID and secret are correctly formatted.
//
// For "Bearer" authentication, it validates the token structure and
// verifies its authenticity (e.g., signature, expiry, and claims).
//
// Parameters:
//   - ctx Context: The context for managing timeouts and cancellations.
//   - scope string: The clients scopes.
//
// Returns:
//   - error: Returns an error if the header is malformed, the credentials are invalid,
//     or the token fails validation.
func (s *authenticationService) AuthenticateClientRequest(ctx context.Context, r *http.Request, scope types.Scope) error {
	authHeader := r.Header.Get(constants.AuthorizationHeader)

	switch {
	case strings.HasPrefix(authHeader, constants.BasicAuthHeader):
		return s.authenticateWithBasicAuth(ctx, r, scope)
	case strings.HasPrefix(authHeader, constants.BearerAuthHeader):
		return s.authenticateWithBearerToken(ctx, r, scope)
	default:
		return errors.New(errors.ErrCodeInvalidClient, "failed to authorize client: missing authorization header")
	}
}

// RevokeToken handles revoking the given token. The token can either be an Access token or a Refresh token.
// This method has no return values since the content of the response should be ignored by clients.
// If an error occurs during the process, the errors will be logged.
//
// Parameters:
//   - ctx Context: The context for managing timeouts and cancellations.
//   - token string: The token to be revoked.
func (s *authenticationService) RevokeToken(ctx context.Context, tokenStr string) {
	requestID := utils.GetRequestID(ctx)
	retrievedToken, err := s.tokenService.GetTokenData(ctx, tokenStr)
	if retrievedToken == nil || err != nil {
		s.logger.Error(s.module, requestID, "[RevokeToken]: Failed to revoke token")
		if err != nil {
			s.logger.Error(s.module, requestID, "[RevokeToken]: Error: %v", err)
		}
		if err := s.tokenService.BlacklistToken(ctx, tokenStr); err != nil {
			s.logger.Error(s.module, requestID, "[RevokeToken]: Failed to blacklist token: %v", err)
		}

		return
	}

	if _, err := s.tokenService.ParseToken(ctx, tokenStr); err != nil {
		s.logger.Error(s.module, requestID, "[RevokeToken]: Failed to parse token: %v", err)
		if err := s.tokenService.BlacklistToken(ctx, tokenStr); err != nil {
			s.logger.Error(s.module, requestID, "[RevokeToken]: Failed to blacklist token: %v", err)
		}
		return
	}

	if err := s.tokenService.BlacklistToken(ctx, tokenStr); err != nil {
		s.logger.Error(s.module, requestID, "[RevokeToken]: Failed to blacklist token: %v", err)
		return
	}
}

func (s *authenticationService) validateRefreshTokenAndMatchClient(ctx context.Context, clientID, refreshToken string) error {
	if err := s.tokenService.ValidateToken(ctx, refreshToken); err != nil {
		return errors.Wrap(err, errors.ErrCodeInvalidGrant, "failed to validate refresh token")
	}

	claims, err := s.tokenService.ParseToken(ctx, refreshToken)
	if err != nil {
		return errors.New(errors.ErrCodeInvalidGrant, "failed to parse refresh token")
	}

	if claims.Audience != clientID {
		s.logger.Warn(s.module, utils.GetRequestID(ctx), "Token audience mismatch: expected %s, got %s", clientID, claims.Audience)
		return errors.New(errors.ErrCodeInvalidGrant, "refresh token was issued to a different client")
	}

	return nil
}

func (s *authenticationService) authenticateUser(ctx context.Context, req *user.UserLoginAttempt, clientID string) (*user.UserLoginResponse, error) {
	if _, err := s.userService.GetUserByUsername(ctx, req.Username); err != nil {
		s.logger.Error(s.module, "", "An error occurred retrieving user by username: %v", err)
		return nil, errors.Wrap(err, errors.ErrCodeInvalidGrant, "user not found")
	}

	loginAttempt := &user.UserLoginRequest{Username: req.Username, Password: req.Password}
	loginResponse, err := s.userService.AuthenticateUser(ctx, loginAttempt, clientID, "")
	if err != nil {
		return nil, err
	}

	return loginResponse, nil
}

func (s *authenticationService) authenticateWithBasicAuth(ctx context.Context, r *http.Request, scope types.Scope) error {
	clientID, clientSecret, err := web.ExtractClientBasicAuth(r)
	if err != nil {
		return err
	}

	if err := s.clientService.AuthenticateClient(ctx, clientID, clientSecret, "", scope); err != nil {
		return err
	}

	return nil
}

func (s *authenticationService) authenticateWithBearerToken(ctx context.Context, r *http.Request, scope types.Scope) error {
	bearerToken, err := web.ExtractBearerToken(r)
	if err != nil {
		return errors.Wrap(err, errors.ErrCodeInvalidGrant, "failed to extract bearer token")
	}

	if err := s.tokenService.ValidateToken(ctx, bearerToken); err != nil {
		return errors.Wrap(err, "", "failed to validate bearer token")
	}

	claims, err := s.tokenService.ParseToken(ctx, bearerToken)
	if err != nil {
		return errors.New(errors.ErrCodeInternalServerError, "failed to parse bearer token")
	}

	clientID := claims.StandardClaims.Audience
	if err := s.clientService.AuthenticateClient(ctx, clientID, "", "", scope); err != nil {
		return err
	}

	return nil
}

func (s *authenticationService) blacklistToken(ctx context.Context, token string) {
	if err := s.tokenService.BlacklistToken(ctx, token); err != nil {
		s.logger.Warn(s.module, utils.GetRequestID(ctx), "[RefreshAccessToken]: Failed to blacklist token: %v", err)
	}
}
