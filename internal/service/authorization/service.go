package service

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"

	"github.com/vigiloauth/vigilo/idp/config"
	"github.com/vigiloauth/vigilo/internal/constants"
	authz "github.com/vigiloauth/vigilo/internal/domain/authorization"
	authzCode "github.com/vigiloauth/vigilo/internal/domain/authzcode"
	client "github.com/vigiloauth/vigilo/internal/domain/client"
	session "github.com/vigiloauth/vigilo/internal/domain/session"
	token "github.com/vigiloauth/vigilo/internal/domain/token"
	user "github.com/vigiloauth/vigilo/internal/domain/user"
	consent "github.com/vigiloauth/vigilo/internal/domain/userconsent"
	"github.com/vigiloauth/vigilo/internal/errors"
	"github.com/vigiloauth/vigilo/internal/utils"
	"github.com/vigiloauth/vigilo/internal/web"
)

// Compile-time interface implementation check
var _ authz.AuthorizationService = (*authorizationService)(nil)

// authorizationService implements the AuthorizationService interface
// and coordinates authorization-related operations across multiple services.
type authorizationService struct {
	authzCodeService   authzCode.AuthorizationCodeService
	userConsentService consent.UserConsentService
	tokenService       token.TokenService
	clientService      client.ClientService
	userService        user.UserService
	sessionService     session.SessionService

	logger *config.Logger
	module string
}

// NewAuthorizationService creates a new instance of AuthorizationServiceImpl.
//
// Parameters:
//   - codeService AuthorizationCodeService: Handles authorization code-related operations
//   - consentService UserConsentService: Manages user consent for authorization requests
//   - tokenService TokenService: Responsible for token generation and management
//   - clientService ClientService: Provides client-related functionality
//
// Returns:
//   - A configured AuthorizationServiceImpl instance
func NewAuthorizationService(
	authzCodeService authzCode.AuthorizationCodeService,
	userConsentService consent.UserConsentService,
	tokenService token.TokenService,
	clientService client.ClientService,
	userService user.UserService,
	sessionService session.SessionService,
) authz.AuthorizationService {
	return &authorizationService{
		authzCodeService:   authzCodeService,
		userConsentService: userConsentService,
		tokenService:       tokenService,
		clientService:      clientService,
		userService:        userService,
		sessionService:     sessionService,
		logger:             config.GetServerConfig().Logger(),
		module:             "Authorization Service",
	}
}

// AuthorizeClient handles the authorization logic for a client request.
//
// Parameters:
//   - ctx Context: The context for managing timeouts and cancellations.
//   - authorizationRequest *ClientAuthorizationRequest: The client authorization request.
//   - consentApproved: A boolean indicating whether the user has already approved consent for the requested scopes.
//
// Returns:
//   - string: The redirect URL, or an empty string if authorization failed.
//   - error: An error message, if any.
//
// This method performs the following steps:
//  1. Checks if the user is authenticated.
//  2. Verifies user consent if required or if already approved.
//  3. Generates an authorization code if authorization is successful.
//  4. Constructs the redirect URL with the authorization code or error parameters.
//  5. Returns the success status, redirect URL and any error messages.
//
// Errors:
//   - Returns an error message if the user is not authenticated, consent is denied, or authorization code generation fails.
func (s *authorizationService) AuthorizeClient(ctx context.Context, request *client.ClientAuthorizationRequest, consentApproved bool) (string, error) {
	requestID := utils.GetRequestID(ctx)

	retrievedClient, err := s.clientService.GetClientByID(ctx, request.ClientID)
	if err != nil {
		s.logger.Error(s.module, requestID, "[AuthorizeClient]: Failed to retrieve client by ID: %v", err)
		return "", err
	} else if retrievedClient == nil {
		s.logger.Error(s.module, requestID, "[AuthorizeClient]: Invalid client ID=[%s]", request.ClientID)
		return "", errors.New(errors.ErrCodeUnauthorizedClient, "invalid client ID")
	}
	request.Client = retrievedClient

	if err := request.Validate(); err != nil {
		s.logger.Error(s.module, requestID, "[AuthorizeClient]: Failed to validate request: %v", err)
		return "", err
	}

	if err := s.handleUserConsent(ctx, request, consentApproved); err != nil {
		return "", err
	}

	code, err := s.generateAuthorizationCode(ctx, request)
	if err != nil {
		return "", err
	}

	redirectURL := s.buildRedirectURL(request.RedirectURI, code, request.State)
	s.logger.Info(s.module, requestID, "[AuthorizeClient]: Client=[%s] successfully authorized, redirectURL=[%s]",
		utils.TruncateSensitive(request.ClientID),
		utils.SanitizeURL(redirectURL),
	)

	return redirectURL, nil
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
func (s *authorizationService) AuthorizeTokenExchange(ctx context.Context, tokenRequest *token.TokenRequest) (*authzCode.AuthorizationCodeData, error) {
	requestID := utils.GetRequestID(ctx)

	authzCodeData, err := s.validateAuthorizationCode(ctx, tokenRequest)
	if err != nil {
		return nil, err
	}

	if err := s.validateClient(ctx, authzCodeData, tokenRequest); err != nil {
		s.revokeAuthorizationCode(ctx, authzCodeData.Code)
		s.logger.Error(s.module, requestID, "[AuthorizeTokenExchange]: Failed to validate client=[%s]: %v", utils.TruncateSensitive(tokenRequest.ClientID), err)
		return nil, errors.Wrap(err, "", "failed to validate client")
	}

	if err := s.handlePKCEValidation(authzCodeData, tokenRequest); err != nil {
		s.revokeAuthorizationCode(ctx, authzCodeData.Code)
		return nil, err
	}

	s.revokeAuthorizationCode(ctx, authzCodeData.Code)
	s.logger.Info(s.module, requestID, "[AuthorizeTokenExchange]: Client=[%s] successfully authorized", utils.TruncateSensitive(tokenRequest.ClientID))
	return authzCodeData, nil
}

// GenerateTokens creates access and refresh tokens based on a validated token exchange request.
//
// Parameters:
//   - ctx Context: The context for managing timeouts and cancellations.
//   - authCodeData *authz.AuthorizationCodeData: The authorization code data.
//
// Returns:
//   - *token.TokenResponse: A fully formed token response with access and refresh tokens.
//   - error: An error if token generation fails.
func (s *authorizationService) GenerateTokens(ctx context.Context, authCodeData *authzCode.AuthorizationCodeData) (*token.TokenResponse, error) {
	accessToken, refreshToken, err := s.tokenService.GenerateTokensWithAudience(ctx, authCodeData.UserID, authCodeData.ClientID, authCodeData.Scope, "")
	if err != nil {
		return nil, errors.Wrap(err, errors.ErrCodeInternalServerError, "failed to generate tokens")
	}

	response := &token.TokenResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		TokenType:    token.BearerToken,
		ExpiresIn:    int(config.GetServerConfig().TokenConfig().AccessTokenDuration()),
		Scope:        authCodeData.Scope,
	}

	return response, nil
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
//   - r *http.Request: The HTTP request containing the cookies.

// Returns:
//   - error: An error if authorization fails, otherwise nil.
func (s *authorizationService) AuthorizeUserInfoRequest(ctx context.Context, claims *token.TokenClaims, r *http.Request) (*user.User, error) {
	requestID := utils.GetRequestID(ctx)
	if claims == nil {
		s.logger.Error(s.module, requestID, "[AuthorizeUserInfoRequest]: Token claims provided are nil")
		return nil, errors.NewInternalServerError()
	}

	userID := claims.StandardClaims.Subject
	requestedScopes := strings.Split(claims.Scopes, " ")

	if len(requestedScopes) == 0 || !slices.Contains(requestedScopes, constants.OIDC) {
		return nil, errors.New(errors.ErrCodeInsufficientScope, "bearer access token has insufficient privileges")
	}

	if !s.sessionService.IsUserSessionPresent(r, userID) && !slices.Contains(requestedScopes, constants.UserOfflineAccess) {
		return nil, errors.New(errors.ErrCodeInsufficientScope, "bearer access token has insufficient privileges")
	}

	retrievedUser, err := s.validateUserScopes(ctx, userID, requestedScopes)
	if err != nil {
		s.logger.Error(s.module, requestID, "[AuthorizeUserInfoRequest]: An error occurred retrieving and validating the user: %v", err)
		return nil, err
	}

	if err := s.validateClientScopes(ctx, claims.StandardClaims.Audience, requestedScopes); err != nil {
		s.logger.Error(s.module, requestID, "[AuthorizeUserInfoRequest]: An error occurred retrieving and validating the client: %v", err)
		return nil, err
	}

	return retrievedUser, nil
}

func (s *authorizationService) validateUserScopes(ctx context.Context, userID string, requestedScopes []string) (*user.User, error) {
	retrievedUser, err := s.userService.GetUserByID(ctx, userID)
	if err != nil {
		return nil, errors.NewInternalServerError()
	} else if retrievedUser == nil {
		return nil, errors.New(errors.ErrCodeUnauthorized, "invalid token subject")
	}

	for _, scope := range requestedScopes {
		if !retrievedUser.HasScope(scope) {
			return nil, errors.New(errors.ErrCodeInsufficientScope, "bearer access token has insufficient privileges")
		}
	}

	return retrievedUser, nil
}

func (s *authorizationService) validateClientScopes(ctx context.Context, clientID string, requestedScopes []string) error {
	retrievedClient, err := s.clientService.GetClientByID(ctx, clientID)
	if err != nil {
		return errors.NewInternalServerError()
	} else if retrievedClient == nil {
		return errors.New(errors.ErrCodeUnauthorized, "invalid token audience")
	}

	for _, scope := range requestedScopes {
		if !retrievedClient.HasScope(scope) {
			return errors.New(errors.ErrCodeInsufficientScope, "bearer access token has insufficient privileges")
		}
	}

	return nil
}

func (s *authorizationService) validateClient(ctx context.Context, code *authzCode.AuthorizationCodeData, tokenRequest *token.TokenRequest) error {
	client, err := s.clientService.GetClientByID(ctx, tokenRequest.ClientID)
	if err != nil {
		s.logger.Error(s.module, "", "Failed to retrieve client by ID: %v", err)
		return err
	} else if client == nil {
		return errors.New(errors.ErrCodeInvalidClient, "invalid client")
	}
	if client.IsConfidential() && !client.SecretsMatch(tokenRequest.ClientSecret) {
		s.logger.Error(s.module, "", "Failed to validate client: client secret from token request does not match with registered client")
		return errors.New(errors.ErrCodeInvalidClient, "invalid client credentials")
	}
	if code.ClientID != tokenRequest.ClientID {
		s.logger.Error(s.module, "", "Failed to validate client: client ID from token request does not match with registered client")
		return errors.New(errors.ErrCodeInvalidGrant, "authorization code client ID and request client ID do no match")
	}

	return nil
}

func (s *authorizationService) buildConsentURL(clientID, redirectURI, scope, state string) string {
	URL := fmt.Sprintf("%s?client_id=%s&redirect_uri=%s&scope=%s",
		web.OAuthEndpoints.UserConsent,
		url.QueryEscape(clientID),
		url.QueryEscape(redirectURI),
		url.QueryEscape(scope),
	)

	if state != "" {
		s.logger.Debug(s.module, "Adding state=[%s] to consent url=[%s]",
			utils.TruncateSensitive(state),
			utils.SanitizeURL(URL),
		)
		URL = fmt.Sprintf("%s&state=%s", URL, url.QueryEscape(state))
	}

	return URL
}

func (s *authorizationService) buildRedirectURL(redirectURI, code, state string) string {
	redirectURL := fmt.Sprintf("%s?code=%s", redirectURI, url.QueryEscape(code))
	if state != "" {
		s.logger.Debug(s.module, "Adding state=[%s] to redirect url=[%s]",
			utils.TruncateSensitive(state),
			utils.SanitizeURL(redirectURL),
		)
		redirectURL = fmt.Sprintf("%s&state=%s", redirectURL, url.QueryEscape(state))
	}

	return redirectURL
}

func (s *authorizationService) validateAuthorizationCode(ctx context.Context, tokenRequest *token.TokenRequest) (*authzCode.AuthorizationCodeData, error) {
	authzCodeData, err := s.authzCodeService.ValidateAuthorizationCode(ctx, tokenRequest.AuthorizationCode, tokenRequest.ClientID, tokenRequest.RedirectURI)
	if err != nil {
		s.revokeAuthorizationCode(ctx, tokenRequest.AuthorizationCode)
		s.logger.Error(s.module, "", "Failed to validate authorization code: %v", err)
		return nil, errors.Wrap(err, "", "failed to validate authorization code")
	}
	return authzCodeData, nil
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
		return err
	}

	if err := s.authzCodeService.ValidatePKCE(authzCodeData, tokenRequest.CodeVerifier); err != nil {
		s.logger.Error(s.module, "", "PKCE validation failed: %v", err)
		return errors.Wrap(err, errors.ErrCodeInvalidGrant, "PKCE validation failed")
	}

	return nil
}

func (s *authorizationService) revokeAuthorizationCode(ctx context.Context, code string) {
	if err := s.authzCodeService.RevokeAuthorizationCode(ctx, code); err != nil {
		s.logger.Error(s.module, "", "Failed to revoke authorization code: %v", err)
	}
}

func (s *authorizationService) handleUserConsent(ctx context.Context, request *client.ClientAuthorizationRequest, consentApproved bool) error {
	consentRequired, err := s.userConsentService.CheckUserConsent(ctx, request.UserID, request.ClientID, request.Scope)
	if err != nil {
		s.logger.Error(s.module, "", "Failed to check user consent, user=[%s]: %v", utils.TruncateSensitive(request.UserID), err)
		return errors.NewAccessDeniedError()
	}

	if consentRequired {
		if !consentApproved {
			consentURL := s.buildConsentURL(request.ClientID, request.RedirectURI, request.Scope, request.State)
			s.logger.Info(s.module, "", "Consent required, redirecting to consent URL=[%s]", utils.SanitizeURL(consentURL))
			return errors.NewConsentRequiredError(consentURL)
		}
	} else if consentApproved {
		s.logger.Error(s.module, "", "Consent not required but was approved, user=[%s]", utils.TruncateSensitive(request.UserID))
		return errors.NewAccessDeniedError()
	}

	return nil
}

func (s *authorizationService) generateAuthorizationCode(ctx context.Context, request *client.ClientAuthorizationRequest) (string, error) {
	code, err := s.authzCodeService.GenerateAuthorizationCode(ctx, request)
	if err != nil {
		s.logger.Error(s.module, "", "Failed to generate authorization code: %v", err)
		return "", errors.Wrap(err, "", "failed to generate authorization code")
	}
	return code, nil
}
