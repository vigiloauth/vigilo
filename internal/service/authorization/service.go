package service

import (
	"context"
	"net/url"
	"slices"
	"strings"

	"github.com/vigiloauth/vigilo/v2/idp/config"
	"github.com/vigiloauth/vigilo/v2/internal/constants"
	authz "github.com/vigiloauth/vigilo/v2/internal/domain/authorization"
	authzCode "github.com/vigiloauth/vigilo/v2/internal/domain/authzcode"
	client "github.com/vigiloauth/vigilo/v2/internal/domain/client"
	token "github.com/vigiloauth/vigilo/v2/internal/domain/token"
	user "github.com/vigiloauth/vigilo/v2/internal/domain/user"
	consent "github.com/vigiloauth/vigilo/v2/internal/domain/userconsent"
	"github.com/vigiloauth/vigilo/v2/internal/errors"
	"github.com/vigiloauth/vigilo/v2/internal/utils"
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
) authz.AuthorizationService {
	return &authorizationService{
		authzCodeService:   authzCodeService,
		userConsentService: userConsentService,
		tokenService:       tokenService,
		clientService:      clientService,
		userService:        userService,
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
	s.logger.Info(s.module, requestID, "[AuthorizeClient] Starting authorization process.")

	retrievedClient, err := s.clientService.GetClientByID(ctx, request.ClientID)
	if err != nil {
		s.logger.Error(s.module, requestID, "[AuthorizeClient]: Failed to retrieve client by ID: %v", err)
		return "", errors.New(errors.ErrCodeUnauthorizedClient, "invalid client credentials")
	}

	request.Client = retrievedClient
	if err := request.Validate(); err != nil {
		s.logger.Error(s.module, requestID, "[AuthorizeClient]: Failed to validate request: %v", err)
		return "", err
	}
	s.logger.Debug(s.module, requestID, "[AuthorizeClient] Authorization request parameters validated successfully")

	s.logger.Debug(s.module, requestID, "[AuthorizeClient] Checking user consent status")
	if err := s.handleUserConsent(ctx, request, consentApproved); err != nil {
		return "", err
	}

	s.logger.Debug(s.module, requestID, "[AuthorizeClient] Generating authorization code")
	code, err := s.generateAuthorizationCode(ctx, request)
	if err != nil {
		return "", err
	}
	s.logger.Debug(s.module, requestID, "[AuthorizeClient] Authorization code generated successfully: %s", utils.TruncateSensitive(code))

	redirectURL := s.buildRedirectURL(request.RedirectURI, code, request.State, request.Nonce)
	s.logger.Info(s.module, requestID, "[AuthorizeClient]: Client successfully authorized")
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
	s.logger.Debug(s.module, requestID, "[AuthorizeTokenExchange]: Starting authorization process...")

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
	requestID := utils.GetRequestID(ctx)
	s.logger.Info(s.module, requestID, "[GenerateTokens] Start token generation. UserID: %s, ClientID: %s, Scope: %s, Nonce: %s",
		utils.TruncateSensitive(authCodeData.UserID),
		utils.TruncateSensitive(authCodeData.ClientID),
		authCodeData.Scope,
		utils.TruncateSensitive(authCodeData.Nonce),
	)

	accessToken, refreshToken, err := s.tokenService.GenerateTokensWithAudience(ctx, authCodeData.UserID, authCodeData.ClientID, authCodeData.Scope, "")
	if err != nil {
		s.logger.Error(s.module, requestID, "[GenerateTokens]: Failed to generate tokens: %v", err)
		return nil, errors.Wrap(err, errors.ErrCodeInternalServerError, "failed to generate tokens")
	}
	s.logger.Debug(s.module, requestID, "[GenerateTokens] Successfully generated Access token (%s) and Refresh token (%s)",
		utils.TruncateSensitive(accessToken),
		utils.TruncateSensitive(refreshToken),
	)

	s.logger.Debug(s.module, requestID, "[GenerateTokens] Attempting to generate ID token: Nonce: %s", authCodeData.Nonce)
	idToken, err := s.tokenService.GenerateIDToken(ctx, authCodeData.UserID, authCodeData.ClientID, "", authCodeData.Nonce)

	if err != nil {
		s.logger.Error(s.module, requestID, "[GenerateTokens]: Failed to generate ID token: %v", err)
		return nil, errors.Wrap(err, errors.ErrCodeInternalServerError, "failed to generate ID token")
	}
	s.logger.Debug(s.module, requestID, "[GenerateTokens] Successfully generated ID token: %s", utils.TruncateSensitive(idToken))

	// --- TEMPORARILY SKIP ENCRYPTION FOR BASIC CERTIFICATION TESTS ---
	// client, err := s.clientService.GetClientByID(ctx, authCodeData.ClientID)
	// if err != nil {
	//     s.logger.Error(s.module, requestID, "[GenerateTokens]: Failed to retrieve client: %v", err)
	//     return nil, errors.New(errors.ErrCodeInvalidClient, "failed to retrieve client")
	// }
	//
	// if client.IsConfidential() {
	// 	accessToken, refreshToken, idToken, err := s.encryptClientTokens(ctx, accessToken, refreshToken, idToken)
	// 	if err != nil {
	// 		s.logger.Error(s.module, requestID, "[GenerateTokens]: Failed to encrypt tokens for confidential client: %v", err)
	// 		return nil, errors.Wrap(err, errors.ErrCodeInternalServerError, "failed to encrypt tokens")
	// 	}
	// }
	// --- END SKIP ENCRYPTION ---

	response := &token.TokenResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		IDToken:      idToken,
		TokenType:    token.BearerToken,
		ExpiresIn:    int(config.GetServerConfig().TokenConfig().AccessTokenDuration()),
		Scope:        authCodeData.Scope,
	}

	s.logger.Info(s.module, requestID, "[GenerateTokens] Token generation complete. Returning TokenResponse (AccessToken present: %t, RefreshToken present: %t, IDToken present: %t, ExpiresIn: %d, Scope: %s)",
		response.AccessToken != "",
		response.RefreshToken != "",
		response.IDToken != "",
		response.ExpiresIn,
		response.Scope,
	)

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
//
// Returns:
//   - error: An error if authorization fails, otherwise nil.
func (s *authorizationService) AuthorizeUserInfoRequest(ctx context.Context, claims *token.TokenClaims) (*user.User, error) {
	requestID := utils.GetRequestID(ctx)
	if claims == nil {
		s.logger.Error(s.module, requestID, "[AuthorizeUserInfoRequest]: Token claims provided are nil")
		return nil, errors.NewInternalServerError()
	}

	userID := claims.StandardClaims.Subject
	requestedScopes := strings.Split(claims.Scopes, " ")

	if len(requestedScopes) == 0 || !slices.Contains(requestedScopes, constants.OpenIDScope) {
		return nil, errors.New(errors.ErrCodeInsufficientScope, "bearer access token has insufficient privileges")
	}

	retrievedUser, err := s.userService.GetUserByID(ctx, userID)
	if err != nil {
		s.logger.Error(s.module, requestID, "[AuthorizeUserInfoRequest]: An error occurred retrieving the user: %v", err)
		return nil, err
	}

	if err := s.validateClientScopes(ctx, claims.StandardClaims.Audience, requestedScopes); err != nil {
		s.logger.Error(s.module, requestID, "[AuthorizeUserInfoRequest]: An error occurred retrieving and validating the client: %v", err)
		return nil, err
	}

	return retrievedUser, nil
}

func (s *authorizationService) validateClientScopes(ctx context.Context, clientID string, requestedScopes []string) error {
	retrievedClient, err := s.clientService.GetClientByID(ctx, clientID)
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

	client, err := s.clientService.GetClientByID(ctx, tokenRequest.ClientID)
	if err != nil {
		s.logger.Error(s.module, requestID, "An error occurred retrieving the client by ID: %v", err)
		return err
	} else if client == nil {
		s.logger.Warn(s.module, requestID, "Client does not exist with the given ID: %v", tokenRequest.ClientID)
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

func (s *authorizationService) buildConsentURL(req *client.ClientAuthorizationRequest) string {
	queryParams := url.Values{}
	queryParams.Add(constants.ClientIDReqField, req.ClientID)
	queryParams.Add(constants.RedirectURIReqField, req.RedirectURI)
	queryParams.Add(constants.ScopeReqField, req.Scope)
	queryParams.Add(constants.ResponseTypeReqField, req.ResponseType)

	if req.State != "" {
		queryParams.Add(constants.StateReqField, req.State)
	}
	if req.Nonce != "" {
		queryParams.Add(constants.NonceReqField, req.Nonce)
	}

	if req.Display != "" && constants.ValidAuthenticationDisplays[req.Display] {
		queryParams.Add(constants.DisplayReqField, req.Display)
	} else {
		queryParams.Add(constants.DisplayReqField, constants.DisplayPage)
	}

	return "/consent?" + queryParams.Encode()
}

func (s *authorizationService) buildRedirectURL(redirectURI, code, state, nonce string) string {
	queryParams := url.Values{}
	queryParams.Add(constants.CodeURLValue, code)

	if state != "" {
		queryParams.Add(constants.StateReqField, state)
	}
	if nonce != "" {
		queryParams.Add(constants.NonceReqField, nonce)
	}

	return redirectURI + "?" + queryParams.Encode()
}

func (s *authorizationService) validateAuthorizationCode(ctx context.Context, tokenRequest *token.TokenRequest) (*authzCode.AuthorizationCodeData, error) {
	authzCodeData, err := s.authzCodeService.ValidateAuthorizationCode(ctx, tokenRequest.AuthorizationCode, tokenRequest.ClientID, tokenRequest.RedirectURI)
	if err != nil {
		s.revokeAuthorizationCode(ctx, tokenRequest.AuthorizationCode)
		s.logger.Error(s.module, "", "Failed to validate authorization code: %v", err)
		return nil, errors.Wrap(err, "", "failed to validate authorization code")
	}

	s.logger.Debug(s.module, utils.GetRequestID(ctx), "[ValidateAuthorizationCode]: Nonce: %s", authzCodeData.Nonce)
	s.logger.Debug(s.module, utils.GetRequestID(ctx), "Successfully validated the authorization code")
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
	requestID := utils.GetRequestID(ctx)
	userGaveConsent, err := s.userConsentService.CheckUserConsent(ctx, request.UserID, request.ClientID, request.Scope)
	if err != nil {
		s.logger.Error(s.module, requestID, "Failed to check user consent, user=[%s]: %v", utils.TruncateSensitive(request.UserID), err)
		return errors.NewAccessDeniedError()
	}

	if !userGaveConsent {
		if !consentApproved {
			consentURL := s.buildConsentURL(request)
			s.logger.Info(s.module, requestID, "Consent required, redirecting to consent URL=[%s]", utils.SanitizeURL(consentURL))
			return errors.NewConsentRequiredError(consentURL)
		}
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

func (s *authorizationService) encryptClientTokens(ctx context.Context, accessToken, refreshToken, idToken string) (string, string, string, error) {
	requestID := utils.GetRequestID(ctx)

	accessToken, err := s.tokenService.EncryptToken(ctx, accessToken)
	if err != nil {
		s.logger.Error(s.module, requestID, "[GenerateTokens]: Failed to encrypt access token: %v", err)
		return "", "", "", errors.Wrap(err, errors.ErrCodeInternalServerError, "failed to encrypt access token")
	}

	refreshToken, err = s.tokenService.EncryptToken(ctx, refreshToken)
	if err != nil {
		s.logger.Error(s.module, requestID, "[GenerateTokens]: Failed to encrypt refresh token: %v", err)
		return "", "", "", errors.Wrap(err, errors.ErrCodeInternalServerError, "failed to encrypt refresh token")
	}

	idToken, err = s.tokenService.EncryptToken(ctx, idToken)
	if err != nil {
		s.logger.Error(s.module, requestID, "[GenerateTokens]: Failed to encrypt ID token: %v", err)
		return "", "", "", errors.Wrap(err, errors.ErrCodeInternalServerError, "failed to encrypt ID token")
	}

	return accessToken, refreshToken, idToken, nil
}
