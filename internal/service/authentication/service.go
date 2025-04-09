package service

import (
	"strings"

	"github.com/vigiloauth/vigilo/identity/config"
	"github.com/vigiloauth/vigilo/internal/common"
	auth "github.com/vigiloauth/vigilo/internal/domain/authentication"
	client "github.com/vigiloauth/vigilo/internal/domain/client"
	token "github.com/vigiloauth/vigilo/internal/domain/token"
	user "github.com/vigiloauth/vigilo/internal/domain/user"
	"github.com/vigiloauth/vigilo/internal/errors"
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

func (s *AuthenticationServiceImpl) IssueClientCredentialsToken(clientID, clientSecret, requestedGrantType, requestedScopes string) (*token.TokenResponse, error) {
	if err := s.clientService.AuthenticateClient(clientID, clientSecret, requestedGrantType, requestedScopes); err != nil {
		s.logger.Error(s.module, "Failed to authenticate client: %v", err)
		return nil, errors.Wrap(err, "", "failed to authenticate client")
	}

	accessToken, err := s.tokenService.GenerateToken(clientID, config.GetServerConfig().TokenConfig().AccessTokenDuration())
	if err != nil {
		s.logger.Error(s.module, "Failed to generate access token: %v", err)
		return nil, errors.Wrap(err, "", "failed to generate access token")
	}

	refreshToken, err := s.tokenService.GenerateToken(clientID, config.GetServerConfig().TokenConfig().RefreshTokenDuration())
	if err != nil {
		s.logger.Error(s.module, "Failed to generate refresh token: %v", err)
		return nil, errors.Wrap(err, "", "failed to generate refresh token")
	}

	return &token.TokenResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresIn:    int(config.GetServerConfig().TokenConfig().AccessTokenDuration().Seconds()),
		TokenType:    common.Bearer,
		Scope:        requestedScopes,
	}, nil
}

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

	accessToken, refreshToken, err := s.tokenService.GenerateTokenPair(loginResponse.UserID, clientID)
	if err != nil {
		s.logger.Error(s.module, "Failed to generate token pair: %v", err)
		return nil, err
	}

	return &token.TokenResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresIn:    int(config.GetServerConfig().TokenConfig().AccessTokenDuration().Seconds()),
		TokenType:    common.Bearer,
		Scope:        requestedScopes,
	}, nil
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
