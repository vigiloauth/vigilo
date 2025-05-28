package service

import (
	"context"
	"net/http"
	"strings"

	"github.com/vigiloauth/vigilo/v2/idp/config"
	authz "github.com/vigiloauth/vigilo/v2/internal/domain/authorization"
	client "github.com/vigiloauth/vigilo/v2/internal/domain/client"
	tokens "github.com/vigiloauth/vigilo/v2/internal/domain/token"
	users "github.com/vigiloauth/vigilo/v2/internal/domain/user"
	"github.com/vigiloauth/vigilo/v2/internal/errors"
	"github.com/vigiloauth/vigilo/v2/internal/types"
	"github.com/vigiloauth/vigilo/v2/internal/utils"
)

var _ tokens.TokenGrantProcessor = (*tokenGrantProcessor)(nil)

type tokenGrantProcessor struct {
	tokenIssuer         tokens.TokenIssuer
	tokenManager        tokens.TokenManager
	clientAuthenticator client.ClientAuthenticator
	userAuthenticator   users.UserAuthenticator
	authorization       authz.AuthorizationService

	tokenDuration int64
	logger        *config.Logger
	module        string
}

func NewTokenGrantProcessor(
	tokenIssuer tokens.TokenIssuer,
	tokenManager tokens.TokenManager,
	clientAuthenticator client.ClientAuthenticator,
	userAuthenticator users.UserAuthenticator,
	authorization authz.AuthorizationService,
) tokens.TokenGrantProcessor {
	return &tokenGrantProcessor{
		tokenIssuer:         tokenIssuer,
		tokenManager:        tokenManager,
		clientAuthenticator: clientAuthenticator,
		userAuthenticator:   userAuthenticator,
		authorization:       authorization,
		tokenDuration:       int64(config.GetServerConfig().TokenConfig().AccessTokenDuration().Seconds()),
		logger:              config.GetServerConfig().Logger(),
		module:              "Token Issuer",
	}
}

// IssueClientCredentialsToken issues a token using the Client Credentials grant type.
//
// Parameters:
//   - ctx context.Context: The context for managing timeouts and cancellations.
//   - clientID string: The ID of the client requesting the token.
//   - clientSecret string: The secret associated with the client.
//   - grantType string: The OAuth2 grant type being used (must be "client_credentials").
//   - scopes types.Scope: The scopes to associate with the issued token.
//
// Returns:
//   - *TokenResponse: The response containing the issued token.
//   - error: An error if token issuance fails.
func (s *tokenGrantProcessor) IssueClientCredentialsToken(
	ctx context.Context,
	clientID string,
	clientSecret string,
	grantType string,
	scopes types.Scope,
) (*tokens.TokenResponse, error) {
	requestID := utils.GetRequestID(ctx)

	req := &client.ClientAuthenticationRequest{
		ClientID:        clientID,
		ClientSecret:    clientSecret,
		RequestedGrant:  grantType,
		RequestedScopes: scopes,
	}

	if err := s.clientAuthenticator.AuthenticateClient(ctx, req); err != nil {
		s.logger.Error(s.module, requestID, "[IssueClientCredentialsToken]: Failed to authenticate client: %v", err)
		return nil, errors.Wrap(err, "", "failed to authenticate client")
	}

	accessToken, refreshToken, err := s.tokenIssuer.IssueTokenPair(ctx, "", clientID, scopes, "", "", nil)
	if err != nil {
		s.logger.Error(s.module, requestID, "[IssueClientCredentialsToken]: Failed to issue tokens: %v", err)
		return nil, errors.NewInternalServerError()
	}

	return &tokens.TokenResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		TokenType:    tokens.BearerToken,
		ExpiresIn:    s.tokenDuration,
		Scope:        scopes,
	}, nil
}

// IssueResourceOwnerToken issues a token using the Resource Owner Password Credentials grant type.
//
// Parameters:
//   - ctx context.Context: The context for managing timeouts and cancellations.
//   - clientID string: The ID of the client requesting the token.
//   - clientSecret string: The secret associated with the client.
//   - grantType string: The OAuth2 grant type being used (must be "password").
//   - scopes types.Scope: The scopes to associate with the issued token.
//   - user *users.UserLoginAttempt: The user's login attempt information including credentials.
//
// Returns:
//   - *TokenResponse: The response containing the issued token.
//   - error: An error if authentication or token issuance fails.
func (s *tokenGrantProcessor) IssueResourceOwnerToken(
	ctx context.Context,
	clientID string,
	clientSecret string,
	grantType string,
	scopes types.Scope,
	user *users.UserLoginRequest,
) (*tokens.TokenResponse, error) {
	requestID := utils.GetRequestID(ctx)

	req := &client.ClientAuthenticationRequest{
		ClientID:        clientID,
		ClientSecret:    clientSecret,
		RequestedGrant:  grantType,
		RequestedScopes: scopes,
	}

	if err := s.clientAuthenticator.AuthenticateClient(ctx, req); err != nil {
		s.logger.Error(s.module, requestID, "[IssueResourceOwnerToken]: Failed to authenticate client: %v", err)
		return nil, errors.Wrap(err, "", "failed to authenticate client")
	}

	authenticatedUser, err := s.userAuthenticator.AuthenticateUser(ctx, user)
	if err != nil {
		s.logger.Error(s.module, requestID, "[IssueResourceOwnerToken]: Failed to authenticate user: %v", err)
		return nil, errors.Wrap(err, "", "failed to authenticate user")
	}

	accessToken, refreshToken, err := s.tokenIssuer.IssueTokenPair(ctx, authenticatedUser.UserID, clientID, scopes, "", "", nil)
	if err != nil {
		s.logger.Error(s.module, requestID, "[IssueResourceOwnerToken]: Failed to issue tokens: %v", err)
		return nil, errors.NewInternalServerError()
	}

	return &tokens.TokenResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		TokenType:    tokens.BearerToken,
		ExpiresIn:    s.tokenDuration,
		Scope:        scopes,
	}, nil

}

// RefreshToken issues a new access token using a valid refresh token.
//
// Parameters:
//   - ctx context.Context: The context for managing timeouts and cancellations.
//   - clientID string: The ID of the client requesting the token.
//   - clientSecret string: The secret associated with the client.
//   - grantType string: The OAuth2 grant type being used (must be "refresh_token").
//   - refreshToken string: The refresh token used to obtain a new access token.
//   - scopes types.Scope: The scopes to associate with the new access token.
//
// Returns:
//   - *TokenResponse: The response containing the new access token (and optionally a new refresh token).
//   - error: An error if the refresh token is invalid or expired.
func (s *tokenGrantProcessor) RefreshToken(
	ctx context.Context,
	clientID string,
	clientSecret string,
	grantType string,
	refreshToken string,
	scopes types.Scope,
) (resp *tokens.TokenResponse, err error) {
	requestID := utils.GetRequestID(ctx)

	defer func() {
		if err != nil || resp != nil {
			if err := s.tokenManager.BlacklistToken(ctx, refreshToken); err != nil {
				s.logger.Error(s.module, requestID, "[RefreshToken]: Failed to blacklist token: %v", err)
			}
		}
	}()

	req := &client.ClientAuthenticationRequest{
		ClientID:        clientID,
		ClientSecret:    clientSecret,
		RequestedGrant:  grantType,
		RequestedScopes: scopes,
	}

	if err := s.clientAuthenticator.AuthenticateClient(ctx, req); err != nil {
		s.logger.Error(s.module, requestID, "[RefreshToken]: Failed to authenticate client: %v", err)
		return nil, errors.Wrap(err, "", "failed to authenticate client")
	}

	tokenData, err := s.tokenManager.GetTokenData(ctx, refreshToken)
	if err != nil {
		s.logger.Error(s.module, requestID, "[RefreshToken]: Failed to get token data: %v", err)
		return nil, errors.New(errors.ErrCodeInvalidGrant, "invalid token")
	}

	audience := tokenData.TokenClaims.Audience
	if clientID != audience {
		s.logger.Error(s.module, requestID, "[RefreshToken]: Client ID does not match with associated refresh token")
		return nil, errors.New(errors.ErrCodeInvalidGrant, "refresh token was issued to a different client")
	}

	if scopes == "" {
		scopes = tokenData.TokenClaims.Scopes
	} else {
		requested := strings.Fields(scopes.String())
		original := strings.Fields(tokenData.TokenClaims.Scopes.String())
		if !utils.IsSubset(requested, original) {
			return nil, errors.New(errors.ErrCodeInvalidRequest, "requested scopes exceed originally granted scopes")
		}
	}

	userID := tokenData.TokenClaims.Subject
	newAccessToken, newRefreshToken, err := s.tokenIssuer.IssueTokenPair(ctx, userID, clientID, scopes, "", "", nil)
	if err != nil {
		s.logger.Error(s.module, requestID, "[RefreshToken]: Failed to issue new access and refresh tokens: %v", err)
		return nil, errors.Wrap(err, "", "failed to issue new tokens")
	}

	return &tokens.TokenResponse{
		AccessToken:  newAccessToken,
		RefreshToken: newRefreshToken,
		TokenType:    tokens.BearerToken,
		ExpiresIn:    s.tokenDuration,
		Scope:        scopes,
	}, nil
}

// ExchangeAuthorizationCode creates access and refresh tokens based on a validated token exchange request.
//
// Parameters:
//   - ctx Context: The context for managing timeouts and cancellations.
//   - request *TokenRequest: The token request data.
//
// Returns:
//   - *token.TokenResponse: A fully formed token response with access and refresh tokens.
//   - error: An error if token generation fails.
func (s *tokenGrantProcessor) ExchangeAuthorizationCode(
	ctx context.Context,
	request *tokens.TokenRequest,
) (*tokens.TokenResponse, error) {
	requestID := utils.GetRequestID(ctx)

	authzCodeData, err := s.authorization.AuthorizeTokenExchange(ctx, request)
	if err != nil {
		s.logger.Error(s.module, requestID, "[ExchangeAuthorizationCode]: Failed to authorize token exchange: %v", err)
		return nil, errors.Wrap(err, "", "failed to authorize token exchange")
	}

	accessToken, refreshToken, err := s.tokenIssuer.IssueTokenPair(
		ctx,
		authzCodeData.UserID,
		authzCodeData.ClientID,
		authzCodeData.Scope, "",
		authzCodeData.Nonce,
		authzCodeData.ClaimsRequest,
	)

	authzCodeData.AccessTokenHash = accessToken
	if err := s.authorization.UpdateAuthorizationCode(ctx, authzCodeData); err != nil {
		s.logger.Error(s.module, requestID, "[ExchangeAuthorizationCode]: Failed to update authorization code data: %v", err)
		return nil, errors.Wrap(err, errors.ErrCodeInternalServerError, "something went wrong updating the authorization code")
	}

	if err != nil {
		s.logger.Error(s.module, requestID, "[ExchangeAuthorizationCode]: Failed to issue access and refresh tokens: %v", err)
		return nil, errors.Wrap(err, "", "failed to issue tokens")
	}

	IDToken, err := s.tokenIssuer.IssueIDToken(
		ctx,
		authzCodeData.UserID,
		authzCodeData.ClientID,
		authzCodeData.Scope,
		authzCodeData.Nonce,
		authzCodeData.ACRValues,
		authzCodeData.UserAuthenticationTime,
	)

	if err != nil {
		s.logger.Error(s.module, requestID, "[ExchangeAuthorizationCode]: Failed to issue ID token: %v", err)
		return nil, errors.Wrap(err, "", "failed to issue the ID token")
	}

	return &tokens.TokenResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		IDToken:      IDToken,
		TokenType:    tokens.BearerToken,
		ExpiresIn:    s.tokenDuration,
		Scope:        authzCodeData.Scope,
	}, nil
}

// IntrospectToken verifies the validity of a given token by introspecting its details.
// This method checks whether the token is valid, expired, or revoked and returns the
// associated token information if it is valid.
//
// Parameters:
//   - ctx Context: The context for managing timeouts and cancellations.
//   - r *http.Request: The request for client authentication.
//   - tokenStr string: The token to be introspected.
//
// Returns:
//   - *TokenIntrospectionResponse: A struct containing token details such as
//     validity, expiration, and any associated metadata. If the token is valid, this
//     response will include all relevant claims associated with the token.
//     error: An error if client authentication fails.
func (s *tokenGrantProcessor) IntrospectToken(
	ctx context.Context,
	r *http.Request,
	tokenStr string,
) (*tokens.TokenIntrospectionResponse, error) {
	requestID := utils.GetRequestID(ctx)

	if err := s.clientAuthenticator.AuthenticateRequest(ctx, r, types.TokenIntrospectScope); err != nil {
		s.logger.Error(s.module, requestID, "[Introspect Token]: Failed to authenticate client request: %v", err)
		return nil, errors.Wrap(err, "", "failed to authenticate client")
	}

	response := s.tokenManager.Introspect(ctx, tokenStr)
	return response, nil
}

// RevokeToken handles revoking the given token. The token can either be an Access token or a Refresh token.
// This method has no return values since the content of the response should be ignored by clients.
// If an error occurs during the process, the errors will be logged.
//
// Parameters:
//   - ctx Context: The context for managing timeouts and cancellations.
//   - r *http.Request: The request for client authentication.
//   - tokenStr string: The token to be revoked.
//
// Returns:
//   - error: An error if client authentication fails.
func (s *tokenGrantProcessor) RevokeToken(
	ctx context.Context,
	r *http.Request,
	tokenStr string,
) error {
	requestID := utils.GetRequestID(ctx)

	if err := s.clientAuthenticator.AuthenticateRequest(ctx, r, types.TokenRevokeScope); err != nil {
		s.logger.Error(s.module, requestID, "[RevokeToken]: Failed to authenticate client request: %v", err)
		return errors.Wrap(err, "", "failed to authenticate client")
	}

	if err := s.tokenManager.Revoke(ctx, tokenStr); err != nil {
		s.logger.Error(s.module, requestID, "[RevokeToken]: Failed to revoke token: %v", err)
		return errors.Wrap(err, "", "failed to revoke token")
	}

	return nil
}
