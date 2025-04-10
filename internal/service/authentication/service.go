package service

import (
	"net/http"
	"strings"

	"github.com/vigiloauth/vigilo/identity/config"
	"github.com/vigiloauth/vigilo/internal/common"
	auth "github.com/vigiloauth/vigilo/internal/domain/authentication"
	client "github.com/vigiloauth/vigilo/internal/domain/client"
	token "github.com/vigiloauth/vigilo/internal/domain/token"
	user "github.com/vigiloauth/vigilo/internal/domain/user"
	"github.com/vigiloauth/vigilo/internal/errors"
	"github.com/vigiloauth/vigilo/internal/web"
)

var _ auth.AuthenticationService = (*AuthenticationServiceImpl)(nil)

type AuthenticationServiceImpl struct {
	tokenService  token.TokenService
	clientService client.ClientService
	userService   user.UserService

	logger *config.Logger
	module string
}

func NewAuthenticationServiceImpl(
	tokenService token.TokenService,
	clientService client.ClientService,
	userService user.UserService,
) *AuthenticationServiceImpl {
	return &AuthenticationServiceImpl{
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
//
//	clientID: The registered client identifier
//	clientSecret: The client's secret used for authentication
//	requestedGrantType: The OAuth 2.0 grant type (should be "client_credentials")
//	requestedScopes: Space-delimited list of requested scopes
//
// Returns:
//
//	A TokenResponse containing the generated access token and related metadata, or an error if token issuance fails
func (s *AuthenticationServiceImpl) IssueClientCredentialsToken(clientID, clientSecret, requestedGrantType, requestedScopes string) (*token.TokenResponse, error) {
	if err := s.clientService.AuthenticateClient(clientID, clientSecret, requestedGrantType, requestedScopes); err != nil {
		s.logger.Error(s.module, "Failed to authenticate client: %v", err)
		return nil, errors.Wrap(err, "", "failed to authenticate client")
	}

	refreshToken, accessToken, err := s.tokenService.GenerateRefreshAndAccessTokens(clientID, requestedScopes)
	if err != nil {
		return nil, errors.Wrap(err, "", "failed to issue tokens")
	}

	return &token.TokenResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresIn:    int(config.GetServerConfig().TokenConfig().AccessTokenDuration().Seconds()),
		TokenType:    common.BearerAuthHeader,
		Scope:        requestedScopes,
	}, nil
}

// IssueResourceOwnerToken generates a token using the resource owner password credentials grant type.
// This flow is used when the user provides their credentials directly to the client application.
//
// Parameters:
//
//	clientID: The registered client identifier
//	clientSecret: The client's secret used for authentication
//	requestedGrantType: The OAuth 2.0 grant type (should be "password")
//	requestedScopes: Space-delimited list of requested scopes
//	loginAttempt: User login details including username and password
//
// Returns:
//
//	A TokenResponse containing the generated access token and related metadata, or an error if token issuance fails
func (s *AuthenticationServiceImpl) IssueResourceOwnerToken(clientID, clientSecret, requestedGrantType, requestedScopes string, req *user.UserLoginAttempt) (*token.TokenResponse, error) {
	if err := s.clientService.AuthenticateClient(clientID, clientSecret, requestedGrantType, requestedScopes); err != nil {
		s.logger.Error(s.module, "Failed to authenticate client: %v", err)
		return nil, err
	}

	loginResponse, err := s.authenticateUser(req, clientID, requestedScopes)
	if err != nil {
		s.logger.Error(s.module, "Failed to authenticate user: %v", err)
		return nil, errors.Wrap(err, errors.ErrCodeInvalidGrant, "failed to authenticate user")
	}

	accessToken, refreshToken, err := s.tokenService.GenerateTokensWithAudience(loginResponse.UserID, clientID, requestedScopes)
	if err != nil {
		s.logger.Error(s.module, "Failed to generate token pair: %v", err)
		return nil, err
	}

	return &token.TokenResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresIn:    int(config.GetServerConfig().TokenConfig().AccessTokenDuration().Seconds()),
		TokenType:    common.BearerAuthHeader,
		Scope:        requestedScopes,
	}, nil
}

// RefreshAccessToken generates a new access token using a previously issued refresh token.
// This method implements the OAuth 2.0 refresh token grant flow.
//
// Parameters:
//
//	clientID: The registered client identifier
//	clientSecret: The client's secret used for authentication
//	requestedGrantType: The OAuth 2.0 grant type (should be "refresh_token")
//	refreshToken: The previously issued refresh token
//	requestedScopes: The clients scopes
//
// Returns:
//
//	A TokenResponse containing the newly generated access token and related metadata, or an error if token refresh fails
func (s *AuthenticationServiceImpl) RefreshAccessToken(clientID, clientSecret, requestedGrantType, refreshToken, requestedScopes string) (*token.TokenResponse, error) {
	if err := s.clientService.AuthenticateClient(clientID, clientSecret, requestedGrantType, requestedScopes); err != nil {
		s.logger.Error(s.module, "[RefreshAccessToken] Failed to authenticate client: %v", err)
		return nil, err
	}

	valid, err := s.validateRefreshTokenAndMatchClient(clientID, refreshToken)
	if err != nil {
		s.logger.Error(s.module, "[RefreshAccessToken] Error validating refresh token: %v", err)
		return nil, err
	}
	if !valid {
		s.logger.Warn(s.module, "[RefreshAccessToken] Invalid refresh token. Blacklisting...")
		if err := s.tokenService.BlacklistToken(refreshToken); err != nil {
			s.logger.Error(s.module, "[RefreshAccessToken] Failed to blacklist refresh token: %v", err)
			return nil, err
		}

		return nil, errors.New(errors.ErrCodeInvalidGrant, "invalid refresh token")
	}

	newAccessToken, newRefreshToken, err := s.tokenService.GenerateRefreshAndAccessTokens(clientID, requestedScopes)
	if err != nil {
		s.logger.Error(s.module, "[RefreshAccessToken] Failed to generate new tokens: %v", err)
		if err := s.tokenService.BlacklistToken(refreshToken); err != nil {
			s.logger.Warn(s.module, "[RefreshAccessToken] Failed to blacklist old refresh token: %v", err)
		}

		return nil, errors.Wrap(err, "", "failed to generate new tokens")
	}

	if err := s.tokenService.BlacklistToken(refreshToken); err != nil {
		s.logger.Warn(s.module, "[RefreshAccessToken] Failed to blacklist old refresh token: %v", err)
	}

	return &token.TokenResponse{
		AccessToken:  newAccessToken,
		RefreshToken: newRefreshToken,
		ExpiresIn:    int(config.GetServerConfig().TokenConfig().AccessTokenDuration().Seconds()),
		TokenType:    common.BearerAuthHeader,
	}, nil
}

// IntrospectToken verifies the validity of a given token by introspecting its details.
// This method checks whether the token is valid, expired, or revoked and returns the
// associated token information if it is valid.
//
// Parameters:
//
//	token (string): The token to be introspected.
//
// Returns:
//
//	*TokenIntrospectionResponse: A struct containing token details such as
//	  validity, expiration, and any associated metadata. If the token is valid, this
//	  response will include all relevant claims associated with the token.
func (s *AuthenticationServiceImpl) IntrospectToken(tokenStr string) *token.TokenIntrospectionResponse {
	retrievedToken, err := s.tokenService.GetToken(tokenStr)
	if retrievedToken == nil || err != nil {
		return &token.TokenIntrospectionResponse{Active: false}
	}

	claims, err := s.tokenService.ParseToken(tokenStr)
	if err != nil {
		s.logger.Error(s.module, "Failed to parse token: %v", err)
		return &token.TokenIntrospectionResponse{Active: false}
	}

	response := token.NewTokenIntrospectionResponse(claims)
	if s.tokenService.IsTokenBlacklisted(tokenStr) || s.tokenService.IsTokenExpired(tokenStr) {
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
// Returns an error if the header is malformed, the credentials are invalid,
// or the token fails validation.
func (s *AuthenticationServiceImpl) AuthenticateClientRequest(r *http.Request) error {
	authHeader := r.Header.Get(common.Authorization)
	if strings.HasPrefix(authHeader, common.BasicAuthHeader) {
		clientID, clientSecret, err := web.ExtractClientBasicAuth(r)
		if err != nil {
			return err
		}

		if err := s.clientService.AuthenticateClient(clientID, clientSecret, client.ClientCredentials, client.ClientIntrospect); err != nil {
			return errors.Wrap(err, "", "failed to authenticate client")
		}

	} else if strings.HasPrefix(authHeader, common.BearerAuthHeader) {
		bearerToken, err := web.ExtractBearerToken(r)
		if err != nil {
			return errors.Wrap(err, errors.ErrCodeInvalidGrant, "failed to extract bearer token")
		}

		if err := s.tokenService.ValidateToken(bearerToken); err != nil {
			return errors.Wrap(err, "", "failed to validate bearer token")
		}

		claims, err := s.tokenService.ParseToken(bearerToken)
		if err != nil {
			return errors.New(errors.ErrCodeInternalServerError, "failed to parse bearer token")
		}

		clientID := claims.Subject
		if err := s.clientService.AuthenticateClient(clientID, "", client.ClientCredentials, client.ClientIntrospect); err != nil {
			return errors.Wrap(err, "", "failed to authenticate client")
		}

	} else {
		return errors.New(errors.ErrCodeInvalidClient, "failed to authorize client: missing authorization header")
	}

	return nil
}

func (s *AuthenticationServiceImpl) validateRefreshTokenAndMatchClient(clientID, refreshToken string) (bool, error) {
	if err := s.tokenService.ValidateToken(refreshToken); err != nil {
		return false, errors.Wrap(err, errors.ErrCodeInvalidGrant, "failed to validate refresh token")
	}

	claims, err := s.tokenService.ParseToken(refreshToken)
	if err != nil {
		return false, errors.New(errors.ErrCodeInternalServerError, "failed to parse refresh token")
	}

	if claims.Subject != clientID {
		s.logger.Warn(s.module, "[isValidRefreshToken] Token subject mismatch")
		return false, nil
	}

	return true, nil
}

func (s *AuthenticationServiceImpl) authenticateUser(req *user.UserLoginAttempt, clientID string, requestedScopes string) (*user.UserLoginResponse, error) {
	existingUser := s.userService.GetUserByUsername(req.Username)
	if existingUser == nil {
		return nil, errors.New(errors.ErrCodeInvalidGrant, "user not found")
	}

	scopes := strings.Split(requestedScopes, " ")
	for _, scope := range scopes {
		if !existingUser.HasScope(scope) {
			return nil, errors.New(errors.ErrCodeInsufficientScope, "user does not have the required scope(s)")
		}
	}

	loginAttempt := &user.UserLoginRequest{ID: existingUser.ID, Username: req.Username, Password: req.Password}
	loginResponse, err := s.userService.HandleOAuthLogin(loginAttempt, clientID, "", req.IPAddress, req.RequestMetadata, req.UserAgent)
	if err != nil {
		return nil, err
	}
	return loginResponse, nil
}
