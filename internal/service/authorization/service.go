package service

import (
	"context"

	"github.com/vigiloauth/vigilo/v2/idp/config"
	authz "github.com/vigiloauth/vigilo/v2/internal/domain/authorization"
	authzCode "github.com/vigiloauth/vigilo/v2/internal/domain/authzcode"
	client "github.com/vigiloauth/vigilo/v2/internal/domain/client"
	token "github.com/vigiloauth/vigilo/v2/internal/domain/token"
	user "github.com/vigiloauth/vigilo/v2/internal/domain/user"
	consent "github.com/vigiloauth/vigilo/v2/internal/domain/userconsent"
	"github.com/vigiloauth/vigilo/v2/internal/errors"
	"github.com/vigiloauth/vigilo/v2/internal/types"
	"github.com/vigiloauth/vigilo/v2/internal/utils"
)

// Compile-time interface implementation check
var _ authz.AuthorizationService = (*authorizationService)(nil)

// authorizationService implements the AuthorizationService interface
// and coordinates authorization-related operations across multiple services.
type authorizationService struct {
	authzCodeService   authzCode.AuthorizationCodeManager
	userConsentService consent.UserConsentService
	clientManager      client.ClientManager
	clientValidator    client.ClientValidator
	userManager        user.UserManager
	tokenManager       token.TokenManager

	logger *config.Logger
	module string
}

func NewAuthorizationService(
	authzCodeService authzCode.AuthorizationCodeManager,
	userConsentService consent.UserConsentService,
	tokenManager token.TokenManager,
	clientManager client.ClientManager,
	clientValidator client.ClientValidator,
	userManager user.UserManager,
) authz.AuthorizationService {
	return &authorizationService{
		authzCodeService:   authzCodeService,
		userConsentService: userConsentService,
		tokenManager:       tokenManager,
		clientManager:      clientManager,
		clientValidator:    clientValidator,
		userManager:        userManager,
		logger:             config.GetServerConfig().Logger(),
		module:             "Authorization Service",
	}
}

// AuthorizeTokenExchange validates the token exchange request for an OAuth 2.0 authorization code grant.
//
// Parameters:
//   - ctx Context: The context for managing timeouts and cancellations.
//   - tokenRequest token.TokenRequest: The token exchange request containing client and authorization code details.
//
// Returns:
//   - *AuthorizationCodeData: The authorization code data if authorization is successful.
//   - error: An error if the token exchange request is invalid or fails authorization checks.
func (s *authorizationService) AuthorizeTokenExchange(
	ctx context.Context,
	tokenRequest *token.TokenRequest,
) (code *authzCode.AuthorizationCodeData, err error) {
	requestID := utils.GetRequestID(ctx)
	authzCodeData, err := s.authzCodeService.GetAuthorizationCode(ctx, tokenRequest.AuthorizationCode)
	if err != nil {
		return nil, errors.Wrap(err, "", "failed to retrieve authorization code")
	}

	defer func() {
		if err != nil || authzCodeData != nil {
			if err := s.markAuthorizationCodeAsUsed(ctx, authzCodeData); err != nil {
				s.logger.Error(s.module, requestID, "[AuthorizeTokenExchange]: Failed to mark authorization code as used: %v", err)
			}
		}
	}()

	if authzCodeData.Used {
		if authzCodeData.AccessTokenHash != "" {
			s.revokeAccessToken(ctx, authzCodeData.AccessTokenHash)
		}
		return nil, errors.New(errors.ErrCodeInvalidGrant, "authorization code has already been used")
	}

	if err := s.validateClient(ctx, authzCodeData, tokenRequest); err != nil {
		s.logger.Error(s.module, requestID, "[AuthorizeTokenExchange]: Failed to validate client=[%s]: %v", tokenRequest.ClientID, err)
		return nil, errors.Wrap(err, "", "failed to validate client")
	}

	if err := s.handlePKCEValidation(authzCodeData, tokenRequest); err != nil {
		return nil, err
	}

	return authzCodeData, nil
}

// AuthorizeUserInfoRequest validates whether the provided access token claims grant sufficient
// permission to access the /userinfo endpoint.
//
// This method is responsible for performing authorization checks and retrieving the user only. It does not validate the token itself (assumes
// the token has already been validated by the time this method is called).
//
// Parameters:
//   - ctx context.Context: The context for managing timeouts and cancellations.
//   - claims *TokenClaims: The token claims extracted from the a valid access token. These claims should include the
//     'scope' field, which will be used to verify whether the client is authorized for the request.
//
// Returns:
//   - error: An error if authorization fails, otherwise nil.
func (s *authorizationService) AuthorizeUserInfoRequest(ctx context.Context, claims *token.TokenClaims) (*user.User, error) {
	requestID := utils.GetRequestID(ctx)
	s.logger.Debug(s.module, requestID, "[AuthorizeUserInfoRequest]: Starting user info authorization request")

	if claims == nil {
		s.logger.Error(s.module, requestID, "[AuthorizeUserInfoRequest]: Token claims provided are nil")
		return nil, errors.New(errors.ErrCodeEmptyInput, "token claims provided are empty")
	}

	requestedScopes := types.ParseScopesString(claims.Scopes.String())
	if !types.ContainsScope(requestedScopes, types.OpenIDScope) {
		return nil, errors.New(errors.ErrCodeInsufficientScope, "bearer access token has insufficient privileges")
	}

	userID := claims.Subject
	retrievedUser, err := s.userManager.GetUserByID(ctx, userID)
	if err != nil {
		s.logger.Error(s.module, requestID, "[AuthorizeUserInfoRequest]: An error occurred retrieving the user: %v", err)
		return nil, errors.Wrap(err, "", "an error occurred retrieving the specified user")
	}

	if err := s.validateClientScopes(ctx, claims.Audience, requestedScopes); err != nil {
		s.logger.Error(s.module, requestID, "[AuthorizeUserInfoRequest]: An error occurred retrieving and validating the client: %v", err)
		return nil, errors.Wrap(err, "", "an error occurred validating the client's scopes")
	}

	return retrievedUser, nil
}

// UpdateAuthorizationCode updates the authorization code data in the database.
//
// Parameters:
//   - ctx context.Context: The context for managing timeouts and cancellations.
//   - authData *AuthorizationCodeData: The authorization code data to update.
//
// Returns:
//   - error: An error if the update fails, otherwise nil.
func (s *authorizationService) UpdateAuthorizationCode(ctx context.Context, authData *authzCode.AuthorizationCodeData) error {
	if err := s.authzCodeService.UpdateAuthorizationCode(ctx, authData); err != nil {
		s.logger.Error(s.module, utils.GetRequestID(ctx), "[UpdateAuthorizationCode]: Failed to update code: %v", err)
		return errors.Wrap(err, "", "failed to update authorization code")
	}

	return nil
}

func (s *authorizationService) validateClientScopes(ctx context.Context, clientID string, requestedScopes []types.Scope) error {
	retrievedClient, err := s.clientManager.GetClientByID(ctx, clientID)
	if err != nil {
		return errors.Wrap(err, errors.ErrCodeUnauthorized, "invalid client credentials")
	}

	if !retrievedClient.CanRequestScopes {
		for _, scope := range requestedScopes {
			if !retrievedClient.HasScope(scope) {
				return errors.New(errors.ErrCodeInsufficientScope, "bearer access token has insufficient privileges")
			}
		}
	}

	return nil
}

func (s *authorizationService) validateClient(ctx context.Context, code *authzCode.AuthorizationCodeData, tokenRequest *token.TokenRequest) error {
	requestID := utils.GetRequestID(ctx)
	s.logger.Debug(s.module, requestID, "Starting client validation process")

	client, err := s.clientManager.GetClientByID(ctx, tokenRequest.ClientID)
	if err != nil {
		s.logger.Error(s.module, requestID, "An error occurred retrieving the client by ID: %v", err)
		return errors.New(errors.ErrCodeInvalidClient, "invalid client")
	}

	if client.IsConfidential() && !client.SecretsMatch(tokenRequest.ClientSecret) {
		s.logger.Error(s.module, requestID, "Failed to validate client: client secret from token request does not match with a registered client")
		return errors.New(errors.ErrCodeInvalidClient, "invalid client credentials")
	}

	if code.ClientID != tokenRequest.ClientID {
		s.logger.Error(s.module, requestID, "Failed to validate client: client ID from token request does not match with a registered client")
		return errors.New(errors.ErrCodeInvalidGrant, "authorization code client ID and request client ID do no match")
	}

	return nil
}

func (s *authorizationService) handlePKCEValidation(authzCodeData *authzCode.AuthorizationCodeData, tokenRequest *token.TokenRequest) error {
	if authzCodeData.CodeChallenge == "" {
		s.logger.Debug(s.module, "", "PKCE is not required for this request. Skipping validation")
		return nil
	}

	if tokenRequest.CodeVerifier == "" {
		s.logger.Error(s.module, "", "Missing code verifier for PKCE")
		return errors.New(errors.ErrCodeInvalidRequest, "missing code verifier for PKCE")
	} else if err := tokenRequest.ValidateCodeVerifier(); err != nil {
		s.logger.Error(s.module, "", "Failed to validate code verifier: %v", err)
		return errors.Wrap(err, "", "an error occurred validating the provided code verifier")
	}

	return nil
}

func (s *authorizationService) revokeAccessToken(ctx context.Context, token string) {
	if err := s.tokenManager.BlacklistToken(ctx, token); err != nil {
		s.logger.Error(s.module, utils.GetRequestID(ctx), "[revokeAccessToken]: Failed to blacklist token: %v", err)
	}
}

func (s *authorizationService) markAuthorizationCodeAsUsed(ctx context.Context, authzCodeData *authzCode.AuthorizationCodeData) error {
	authzCodeData.Used = true
	if err := s.authzCodeService.UpdateAuthorizationCode(ctx, authzCodeData); err != nil {
		s.logger.Error(s.module, utils.GetRequestID(ctx), "[AuthorizeTokenExchange]: Failed to mark code as used: %v", err)
		return errors.Wrap(err, "", "failed to mark the authorization code as used")
	}

	return nil
}
