package service

import (
	"fmt"
	"net/url"

	"github.com/vigiloauth/vigilo/identity/config"
	authz "github.com/vigiloauth/vigilo/internal/domain/authorization"
	authzCode "github.com/vigiloauth/vigilo/internal/domain/authzcode"
	client "github.com/vigiloauth/vigilo/internal/domain/client"
	token "github.com/vigiloauth/vigilo/internal/domain/token"
	consent "github.com/vigiloauth/vigilo/internal/domain/userconsent"
	"github.com/vigiloauth/vigilo/internal/errors"
	"github.com/vigiloauth/vigilo/internal/web"
)

// Compile-time interface implementation check
var _ authz.AuthorizationService = (*AuthorizationServiceImpl)(nil)

// AuthorizationServiceImpl implements the AuthorizationService interface
// and coordinates authorization-related operations across multiple services.
type AuthorizationServiceImpl struct {
	authzCodeService   authzCode.AuthorizationCodeService
	userConsentService consent.UserConsentService
	tokenService       token.TokenService
	clientService      client.ClientService
}

// NewAuthorizationServiceImpl creates a new instance of AuthorizationServiceImpl.
//
// Parameters:
//   - codeService AuthorizationCodeService: Handles authorization code-related operations
//   - consentService UserConsentService: Manages user consent for authorization requests
//   - tokenService TokenService: Responsible for token generation and management
//   - clientService ClientService: Provides client-related functionality
//
// Returns:
//   - A configured AuthorizationServiceImpl instance
func NewAuthorizationServiceImpl(
	authzCodeService authzCode.AuthorizationCodeService,
	userConsentService consent.UserConsentService,
	tokenService token.TokenService,
	clientService client.ClientService,
) *AuthorizationServiceImpl {
	return &AuthorizationServiceImpl{
		authzCodeService:   authzCodeService,
		userConsentService: userConsentService,
		tokenService:       tokenService,
		clientService:      clientService,
	}
}

// AuthorizeClient handles the authorization logic for a client request.
//
// Parameters:
//
//   - userID: The ID of the user attempting to authorize the client.
//   - clientID: The ID of the client requesting authorization.
//   - redirectURI: The URI to redirect the user to after authorization.
//   - scope: The requested authorization scopes.
//   - state: An optional state parameter for maintaining request state between the client and the authorization server.
//   - consentApproved: A boolean indicating whether the user has already approved consent for the requested scopes.
//
// Returns:
//
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
//
//   - Returns an error message if the user is not authenticated, consent is denied, or authorization code generation fails.
func (s *AuthorizationServiceImpl) AuthorizeClient(
	userID string,
	clientID string,
	redirectURI string,
	scope string,
	state string,
	consentApproved bool,
) (string, error) {
	consentRequired, err := s.userConsentService.CheckUserConsent(userID, clientID, scope)
	if err != nil {
		return "", errors.NewAccessDeniedError()
	}

	if !consentApproved && consentRequired {
		consentURL := s.buildConsentURL(clientID, redirectURI, scope, state)
		return "", errors.NewConsentRequiredError(consentURL)
	}

	if consentApproved && !consentRequired {
		return "", errors.NewAccessDeniedError()
	}

	code, err := s.authzCodeService.GenerateAuthorizationCode(userID, clientID, redirectURI, scope)
	if err != nil {
		wrappedErr := errors.Wrap(err, "", "failed to generate authorization code")
		return "", wrappedErr
	}

	return s.buildRedirectURL(redirectURI, code, state), nil
}

// AuthorizeTokenExchange validates the token exchange request for an OAuth 2.0 authorization code grant.
//
// Parameters:
//
//	tokenRequest *TokenRequest: The token exchange request containing client and authorization code details.
//
// Returns:
//
//	*AuthorizationCodeData: The authorization code data if authorization is successful.
//	error: An error if the token exchange request is invalid or fails authorization checks.
func (s *AuthorizationServiceImpl) AuthorizeTokenExchange(tokenRequest *token.TokenRequest) (*authzCode.AuthorizationCodeData, error) {
	authzCodeData, err := s.authzCodeService.ValidateAuthorizationCode(tokenRequest.AuthorizationCode, tokenRequest.ClientID, tokenRequest.RedirectURI)
	if err != nil {
		return nil, errors.Wrap(err, "", "failed to validate authorization code")
	}

	if err := s.validateClient(*tokenRequest); err != nil {
		return nil, errors.Wrap(err, "", "failed to validate client")
	}

	return authzCodeData, nil
}

// GenerateTokens creates access and refresh tokens based on a validated token exchange request.
//
// Parameters:
//
//	authCodeData *AuthorizationCodeData: The authorization code data.
//
// Returns:
//
//	*token.TokenResponse: A fully formed token response with access and refresh tokens.
//	error: An error if token generation fails.
func (s *AuthorizationServiceImpl) GenerateTokens(authCodeData *authzCode.AuthorizationCodeData) (*token.TokenResponse, error) {
	accessToken, refreshToken, err := s.tokenService.GenerateTokenPair(authCodeData.UserID, authCodeData.ClientID)
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

// validateClient performs client validation for token requests.
//
// Parameters:
//
//   - tokenRequest TokenRequest: The token request containing client details
//
// Returns:
//
//   - error: An error if client validation fails, nil otherwise
func (s *AuthorizationServiceImpl) validateClient(tokenRequest token.TokenRequest) error {
	client := s.clientService.GetClientByID(tokenRequest.ClientID)
	if client == nil {
		return errors.New(errors.ErrCodeInvalidClient, "invalid client")
	}

	if client.Secret != tokenRequest.ClientSecret {
		return errors.New(errors.ErrCodeInvalidClient, "invalid client credentials")
	}

	code := s.authzCodeService.GetAuthorizationCode(tokenRequest.AuthorizationCode)
	if code.ClientID != tokenRequest.ClientID {
		return errors.New(errors.ErrCodeInvalidGrant, "client_id mismatch")
	}

	return nil
}

// buildConsentURL constructs a URL for user consent during the OAuth flow.
//
// Parameters:
//
//   - clientID string: The ID of the OAuth client
//   - redirectURI string: The URI to redirect after consent
//   - scope string: The requested authorization scope
//   - state string: An optional state parameter for CSRF protection
//
// Returns:
//
//   - string: A fully constructed consent URL
func (s *AuthorizationServiceImpl) buildConsentURL(clientID, redirectURI, scope, state string) string {
	URL := fmt.Sprintf("%s?client_id=%s&redirect_uri=%s&scope=%s",
		web.OAuthEndpoints.UserConsent,
		url.QueryEscape(clientID),
		url.QueryEscape(redirectURI),
		url.QueryEscape(scope),
	)

	if state != "" {
		URL = fmt.Sprintf("%s&state=%s", URL, url.QueryEscape(state))
	}

	return URL
}

// buildRedirectURL creates a redirect URL with authorization code and optional state.
//
// Parameters:
//
//   - redirectURI string: The base redirect URI
//   - code string: The authorization code
//   - state string: An optional state parameter for CSRF protection
//
// Returns:
//
//   - string: A fully constructed redirect URL
func (s *AuthorizationServiceImpl) buildRedirectURL(redirectURI, code, state string) string {
	redirectURL := fmt.Sprintf("%s?code=%s", redirectURI, url.QueryEscape(code))
	if state != "" {
		redirectURL = fmt.Sprintf("%s&state=%s", redirectURL, url.QueryEscape(state))
	}

	return redirectURL
}
