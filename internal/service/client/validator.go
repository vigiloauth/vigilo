package service

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/vigiloauth/vigilo/v2/idp/config"
	"github.com/vigiloauth/vigilo/v2/internal/constants"
	clients "github.com/vigiloauth/vigilo/v2/internal/domain/client"
	tokens "github.com/vigiloauth/vigilo/v2/internal/domain/token"
	"github.com/vigiloauth/vigilo/v2/internal/errors"
	"github.com/vigiloauth/vigilo/v2/internal/types"
	"github.com/vigiloauth/vigilo/v2/internal/utils"
)

var _ clients.ClientValidator = (*clientValidator)(nil)

type clientValidator struct {
	repo      clients.ClientRepository
	manager   tokens.TokenManager
	validator tokens.TokenValidator
	parser    tokens.TokenParser

	logger                *config.Logger
	module                string
	sectorURIFetchTimeout time.Duration
}

func NewClientValidator(
	repo clients.ClientRepository,
	manager tokens.TokenManager,
	validator tokens.TokenValidator,
	parser tokens.TokenParser,
) clients.ClientValidator {
	return &clientValidator{
		repo:                  repo,
		manager:               manager,
		validator:             validator,
		parser:                parser,
		logger:                config.GetServerConfig().Logger(),
		module:                "Client Request Validator",
		sectorURIFetchTimeout: 5 * time.Second,
	}
}

func (c *clientValidator) ValidateRegistrationRequest(ctx context.Context, req *clients.ClientRegistrationRequest) error {
	requestID := utils.GetRequestID(ctx)

	if req.Name == "" {
		c.logger.Warn(c.module, requestID, "[ValidateRegistrationRequest]: client_name is empty")
		return errors.New(errors.ErrCodeInvalidClientMetadata, "client_name is empty")
	}
	if err := c.validateApplicationType(requestID, req); err != nil {
		c.logger.Error(c.module, requestID, "[ValidateClientRegistrationRequest]: An error occurred validating the application type: %v", err)
		return err
	}
	if err := c.validateTokenEndpointAuthMethod(requestID, req); err != nil {
		c.logger.Error(c.module, requestID, "[ValidateClientRegistrationRequest]: An error occurred validating the token endpoint auth method: %v", err)
		return err
	}

	c.determineClientType(req)
	if err := c.validateGrantAndResponseTypes(requestID, req); err != nil {
		c.logger.Error(c.module, requestID, "[ValidateClientRegistrationRequest]: An error occurred validating grant and response types: %v", err)
		return err
	}
	if err := c.validateURIS(requestID, req); err != nil {
		c.logger.Error(c.module, requestID, "[ValidateClientRegistrationRequest]: An error occurred validating client URIS: %v", err)
		return errors.Wrap(err, "", "the value of one or more redirection URIs is invalid")
	}
	if err := c.validateScopes(requestID, req); err != nil {
		c.logger.Error(c.module, requestID, "[ValidateClientRegistrationRequest]: An error occurred validating scopes: %v", err)
		return err
	}

	return nil
}

func (c *clientValidator) ValidateUpdateRequest(ctx context.Context, req *clients.ClientUpdateRequest) error {
	requestID := utils.GetRequestID(ctx)
	if err := c.validateGrantType(requestID, req); err != nil {
		c.logger.Error(c.module, requestID, "[ValidateClientUpdateRequest]: An error occurred validating grant types: %v", err)
		return err
	}
	if err := c.validateURIS(requestID, req); err != nil {
		c.logger.Error(c.module, requestID, "[ValidateClientUpdateRequest]: An error occurred validating client URIS: %v", err)
		return err
	}
	if err := c.validateScopes(requestID, req); err != nil {
		c.logger.Error(c.module, requestID, "[ValidateClientUpdateRequest]: An error occurred validating scopes: %v", err)
		return err
	}
	if err := c.validateResponseTypes(requestID, req); err != nil {
		c.logger.Error(c.module, requestID, "[ValidateClientUpdateRequest]: An error occurred validating response types: %v", err)
		return err
	}

	return nil
}

func (c *clientValidator) ValidateAuthorizationRequest(ctx context.Context, req *clients.ClientAuthorizationRequest) error {
	requestID := utils.GetRequestID(ctx)

	if !req.Client.HasRedirectURI(req.RedirectURI) {
		return errors.New(errors.ErrCodeInvalidRedirectURI, "the client provided an unregistered redirect URI")
	}

	if !req.Client.HasGrantType(constants.AuthorizationCodeGrantType) {
		c.logger.Error(c.module, requestID, "Failed to validate client authorization: client does not have the required grant types")
		return errors.New(errors.ErrCodeInvalidGrant, "authorization code grant is required for this request")
	}

	if !req.Client.HasResponseType(constants.CodeResponseType) || !req.Client.HasResponseType(req.ResponseType) {
		c.logger.Error(c.module, requestID, "Failed to validate client authorization request: client does not have the code response type")
		return errors.New(errors.ErrCodeInvalidClient, "code response type is required to receive an authorization code")
	}

	if req.Client.Type == types.PublicClient && req.CodeChallenge == "" {
		return errors.New(errors.ErrCodeInvalidRequest, "public clients are required to use PKCE")
	}

	if req.CodeChallenge != "" {
		if req.CodeChallengeMethod == "" {
			c.logger.Warn(c.module, requestID, "Code challenge method was not provided, defaulting to 'plain'")
			req.CodeChallengeMethod = types.PlainCodeChallengeMethod
		}

		if err := c.validateCodeChallengeMethod(requestID, req.CodeChallengeMethod); err != nil {
			c.logger.Error(c.module, requestID, "Failed to validate authorization request: %v", err)
			return err
		}

		if err := c.validateCodeChallenge(requestID, req.CodeChallenge); err != nil {
			c.logger.Error(c.module, requestID, "Failed to validate authorization request: %v", err)
			return err
		}
	}

	return nil
}

func (c *clientValidator) ValidateRedirectURI(ctx context.Context, redirectURI string, client *clients.Client) error {
	requestID := utils.GetRequestID(ctx)

	parsedURI, err := utils.ParseURI(requestID)
	if err != nil {
		return errors.Wrap(err, "", "invalid redirect URI format")
	}

	if err := utils.ValidateRedirectURIScheme(parsedURI); err != nil {
		return errors.Wrap(err, "", "failed to validate URL scheme")
	}

	switch client.Type {
	case types.PublicClient:
		if err := utils.ValidatePublicURIScheme(parsedURI); err != nil {
			return errors.Wrap(err, "", "failed to validate public client redirect URI")
		}
	case types.ConfidentialClient:
		if err := utils.ValidateConfidentialURIScheme(parsedURI); err != nil {
			return errors.Wrap(err, "", "failed to valid confidential client redirect URI")
		}
	default:
		c.logger.Error(c.module, requestID, "[ValidateRedirectURI]: Invalid client type '%s'", client.Type.String())
		return errors.New(errors.ErrCodeInvalidClient, "invalid client type: must be confidential or public")
	}

	if !client.HasRedirectURI(redirectURI) {
		c.logger.Error(c.module, requestID, "[ValidateRedirectURI]: Client=[%s] does not have requested redirect URI=[%s]",
			utils.TruncateSensitive(client.ID),
			utils.SanitizeURL(redirectURI),
		)
		return errors.New(errors.ErrCodeInvalidRequest, "invalid redirect_uri")
	}

	return nil
}

func (c *clientValidator) ValidateClientAndRegistrationAccessToken(
	ctx context.Context,
	clientID string,
	registrationAccessToken string,
) (err error) {
	requestID := utils.GetRequestID(ctx)
	defer func() {
		if err != nil {
			if err := c.manager.BlacklistToken(ctx, registrationAccessToken); err != nil {
				c.logger.Warn(c.module, requestID, "[ValidateClientAndRegistrationAccessToken]: Failed to blacklist registration access token: %v", err)
			}
		}
	}()

	client, err := c.repo.GetClientByID(ctx, clientID)
	if err != nil {
		return errors.New(errors.ErrCodeUnauthorized, "invalid client credentials")
	}

	if err := c.validator.ValidateToken(ctx, registrationAccessToken); err != nil {
		c.logger.Error(c.module, requestID, "[ValidateClientAndRegistrationAccessToken]: Failed to validate registration access token: %v", err)
		return errors.Wrap(err, "", "invalid registration access token")
	}

	tokenClaims, err := c.parser.ParseToken(ctx, registrationAccessToken)
	if err != nil {
		c.logger.Error(c.module, requestID, "[ValidateClientAndRegistrationAccessToken]: Failed to parse registration access token: %v", err)
		return errors.Wrap(err, "", "invalid registration access token")
	}

	if client.ID != tokenClaims.Subject {
		c.logger.Error(c.module, requestID, "[ValidateClientAndRegistrationAccessToken]: the registration access token subject does not match with the client ID in the request")
		return errors.New(errors.ErrCodeUnauthorized, "the registration access token subject does not match with the client ID in the request")
	}

	return nil
}

func (c *clientValidator) validateApplicationType(requestID string, req *clients.ClientRegistrationRequest) error {
	if req.ApplicationType == "" {
		c.logger.Debug(c.module, requestID, "No application type given, will be determined dynamically")
		return nil
	}

	if !constants.ValidApplicationTypes[req.ApplicationType] {
		c.logger.Error(c.module, requestID, "Invalid application type provided: %v", req.ApplicationType)
		return errors.New(
			errors.ErrCodeInvalidClientMetadata,
			fmt.Sprintf("invalid application type: %s", req.ApplicationType),
		)
	}

	return nil
}

func (c *clientValidator) validateTokenEndpointAuthMethod(requestID string, req *clients.ClientRegistrationRequest) error {
	if req.TokenEndpointAuthMethod == "" {
		c.logger.Warn(c.module, requestID, "No token endpoint auth method provided")
		return nil
	}

	if !types.SupportedTokenEndpointAuthMethods[req.TokenEndpointAuthMethod] {
		return errors.New(
			errors.ErrCodeInvalidClientMetadata,
			fmt.Sprintf("invalid token endpoint auth method: %s", req.TokenEndpointAuthMethod),
		)
	}

	return nil
}

func (c *clientValidator) determineClientType(req *clients.ClientRegistrationRequest) {
	if req.TokenEndpointAuthMethod == "" && req.ApplicationType == "" {
		req.Type = types.ConfidentialClient
		req.TokenEndpointAuthMethod = types.ClientSecretBasicTokenAuth
		req.ApplicationType = constants.WebApplicationType
		return
	}

	if req.TokenEndpointAuthMethod == "" {
		switch req.ApplicationType {
		case constants.WebApplicationType:
			req.Type = types.ConfidentialClient
			return
		case constants.NativeApplicationType:
			req.Type = types.PublicClient
			return
		}
	}

	switch req.TokenEndpointAuthMethod {
	case types.NoTokenAuth:
		req.Type = types.PublicClient
		return
	case types.ClientSecretBasicTokenAuth, types.ClientSecretPostTokenAuth:
		req.Type = types.ConfidentialClient
		return
	}
}

func (c *clientValidator) validateGrantAndResponseTypes(requestID string, req *clients.ClientRegistrationRequest) error {
	if len(req.GrantTypes) == 0 {
		c.logger.Error(c.module, requestID, "No grant types were requested")
		return errors.New(errors.ErrCodeInvalidClientMetadata, "at least one grant_type must be requested")
	}
	if len(req.ResponseTypes) == 0 && (utils.Contains(req.GrantTypes, constants.AuthorizationCodeGrantType) || utils.Contains(req.GrantTypes, constants.ImplicitGrantType)) {
		return errors.New(errors.ErrCodeInvalidClientMetadata, "response_types are required for authorization_code or implicit grant types")
	}

	if req.Type == types.PublicClient {
		if utils.Contains(req.GrantTypes, constants.ClientCredentialsGrantType) {
			c.logger.Warn(c.module, requestID, "Validation failed: Public client requested client_credentials grant")
			return errors.New(errors.ErrCodeInvalidClientMetadata, "public clients cannot request the client_credentials grant")
		}
		if utils.Contains(req.GrantTypes, constants.PasswordGrantType) {
			c.logger.Warn(c.module, requestID, "Validation failed: Public client requested password grant")
			return errors.New(errors.ErrCodeInvalidClientMetadata, "public clients cannot request the password grant")
		}

		if req.Type == types.PublicClient && utils.Contains(req.GrantTypes, constants.AuthorizationCodeGrantType) {
			req.RequiresPKCE = true
		}
	}

	requestsAuthCodeGrant := utils.Contains(req.GrantTypes, constants.AuthorizationCodeGrantType)
	requestsImplicitGrant := utils.Contains(req.GrantTypes, constants.ImplicitGrantType)

	requestsCodeResponseType := utils.ContainsResponseType(req.ResponseTypes, constants.CodeResponseType)
	requestsIDTokenResponseType := utils.ContainsResponseType(req.ResponseTypes, constants.IDTokenResponseType)
	requestsTokenResponseType := utils.ContainsResponseType(req.ResponseTypes, constants.TokenResponseType)

	if requestsAuthCodeGrant || requestsImplicitGrant {
		if !requestsCodeResponseType && !requestsIDTokenResponseType && !requestsTokenResponseType {
			c.logger.Warn(c.module, requestID, "Validation failed: Auth Code/Implicit grants requested without corresponding response types.")
			return errors.New(errors.ErrCodeInvalidClientMetadata, "client requesting authorization_code or implicit grants must include 'code', 'id_token', or 'token' in response_types")
		}
	}

	if requestsAuthCodeGrant && !requestsCodeResponseType {
		c.logger.Warn(c.module, requestID, "Validation failed: Auth Code grant requested without 'code' response type.")
		return errors.New(errors.ErrCodeInvalidClientMetadata, "client requesting authorization_code grant must include 'code' in response_types")
	}

	if requestsCodeResponseType && !requestsAuthCodeGrant {
		c.logger.Warn(c.module, requestID, "Validation failed: 'code' response type requested without Auth Code grant.")
		return errors.New(errors.ErrCodeInvalidClientMetadata, "client requesting response_types including 'code' must include authorization_code grant")
	}

	usesImplicitResponseTypes := requestsIDTokenResponseType || requestsTokenResponseType
	requestsImplicitFlowWithoutCode := usesImplicitResponseTypes && !requestsCodeResponseType

	if requestsImplicitGrant && !requestsImplicitFlowWithoutCode && !requestsAuthCodeGrant { // Requests Implicit grant, but no implicit-only response types, and no Auth Code grant for hybrid
		c.logger.Warn(c.module, requestID, "Validation failed: Implicit grant requested without corresponding response types or hybrid.")
		return errors.New(errors.ErrCodeInvalidClientMetadata, "client requesting implicit grant must include 'id_token', 'token', or both in response_types (or request a hybrid flow)")
	}

	if requestsImplicitFlowWithoutCode && !requestsImplicitGrant { // Requests implicit-only response types, but no Implicit grant requested
		c.logger.Warn(c.module, requestID, "Validation failed: Implicit flow response types requested without Implicit grant.")
		return errors.New(errors.ErrCodeInvalidClientMetadata, "client requesting response_types including 'id_token' or 'token' (without 'code') must include implicit grant")
	}

	if utils.Contains(req.GrantTypes, constants.RefreshTokenGrantType) {
		if !requestsAuthCodeGrant && !utils.Contains(req.GrantTypes, constants.PasswordGrantType) {
			c.logger.Warn(c.module, requestID, "Validation failed: Refresh Token grant requested without a valid issuing grant.")
			return errors.New(errors.ErrCodeInvalidClientMetadata, "refresh_token grant requires a grant type capable of issuing refresh tokens (e.g., authorization_code or password)")
		}
	}

	return nil
}

func (c *clientValidator) validateURIS(requestID string, req clients.ClientRequest) error {
	if req.GetType() == types.ConfidentialClient && req.HasGrantType(constants.AuthorizationCodeGrantType) && len(req.GetRedirectURIS()) == 0 {
		return errors.New(errors.ErrCodeInvalidClientMetadata, "redirect URI(s) are required for confidential clients using the authorization code grant type")
	}

	if req.GetType() == types.PublicClient && len(req.GetRedirectURIS()) == 0 {
		c.logger.Warn(c.module, requestID, "Validation failed: redirect_uris is empty for public client")
		return errors.New(errors.ErrCodeInvalidClientMetadata, "redirect URI(s) are required for public clients")
	}

	if req.GetJwksURI() != "" {
		if _, err := url.ParseRequestURI(req.GetJwksURI()); err != nil {
			c.logger.Warn(c.module, requestID, "Invalid jwks_uri provided: %s", req.GetJwksURI())
			return errors.New(errors.ErrCodeInvalidClientMetadata, "invalid jwks_uri format")

		}
	}

	if err := c.validateSectorIdentifierURI(requestID, req.GetRedirectURIS(), req.GetSectorIdentifierURI()); err != nil {
		c.logger.Error(c.module, requestID, "Failed to validate sector identifier URI: %v", err)
		return err
	}

	if req.GetLogoURI() != "" {
		if _, err := url.ParseRequestURI(req.GetLogoURI()); err != nil {
			c.logger.Warn(c.module, requestID, "Invalid logo_uri: %s", req.GetLogoURI())
			return errors.New(errors.ErrCodeInvalidClientMetadata, "invalid logo_uri format")
		}
	}

	mobileSchemePattern := regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9+.-]*:\/\/`)
	for _, uri := range req.GetRedirectURIS() {
		if uri == "" {
			c.logger.Warn(c.module, requestID, "Empty redirect_uri found")
			return errors.New(errors.ErrCodeInvalidRedirectURI, "'redirect_uri' is empty")
		}
		if strings.HasPrefix(uri, "http://localhost") || strings.HasPrefix(uri, "http://127.0.0.1") {
			continue
		}
		if utils.ContainsWildcard(uri) {
			c.logger.Warn(c.module, requestID, "Redirect URI contains wildcard: %s", uri)
			return errors.New(errors.ErrCodeInvalidRedirectURI, "redirect URIs cannot have wildcards")
		}

		parsedURI, err := url.Parse(uri)
		if err != nil {
			c.logger.Warn(c.module, requestID, "Malformed redirect URI: %s", uri)
			return errors.New(errors.ErrCodeInvalidRedirectURI, fmt.Sprintf("malformed redirect URI: %s", uri))
		}

		switch req.GetType() {
		case types.ConfidentialClient:
			if parsedURI.Scheme != "https" {
				c.logger.Warn(c.module, requestID, "Confidential client redirect URI is not using HTTPS: %s", uri)
				return errors.New(errors.ErrCodeInvalidRedirectURI, "confidential clients must use HTTPS")
			}
			if net.ParseIP(parsedURI.Hostname()) != nil && !utils.IsLoopbackIP(parsedURI.Hostname()) {
				c.logger.Warn(c.module, requestID, "Confidential client redirect URI is using IP address: %s", uri)
				return errors.New(errors.ErrCodeInvalidRedirectURI, "IP address not allowed as redirect URI hosts")
			}
			if parsedURI.Fragment != "" {
				c.logger.Warn(c.module, requestID, "Confidential client redirect URI contains fragment: %s", uri)
				return errors.New(errors.ErrCodeInvalidRedirectURI, "fragment component not allowed")
			}

		case types.PublicClient:
			isMobileScheme := mobileSchemePattern.MatchString(uri) && parsedURI.Scheme != "http" && parsedURI.Scheme != "https"
			if isMobileScheme {
				if len(parsedURI.Scheme) < 4 {
					c.logger.Warn(c.module, requestID, "Mobile URI scheme is too short: %s", uri)
					return errors.New(errors.ErrCodeInvalidRedirectURI, "mobile URI scheme is too short")
				}
			} else if parsedURI.Scheme != "https" {
				c.logger.Warn(c.module, requestID, "Public client redirect URI is not using HTTPS: %s", uri)
				return errors.New(errors.ErrCodeInvalidRedirectURI, "public clients must use HTTPS")
			}
		}
	}

	return nil
}

func (c *clientValidator) validateScopes(requestID string, req clients.ClientRequest) error {
	if len(req.GetScopes()) == 0 {
		return nil
	}

	for _, scope := range req.GetScopes() {
		if _, ok := types.SupportedScopes[scope]; !ok {
			c.logger.Warn(c.module, requestID, "Unsupported scope: %s", scope.String())
			return errors.New(errors.ErrCodeInvalidClientMetadata, fmt.Sprintf("scope '%s' is not supported", scope))
		}
	}

	if !utils.Contains(req.GetScopes(), types.OpenIDScope) {
		requestedScopes := req.GetScopes()
		newScopes := append(requestedScopes, types.OpenIDScope)
		req.SetScopes(newScopes)
		c.logger.Info(c.module, requestID, "Adding default 'oidc' scope to client")
	}

	return nil
}

func (c *clientValidator) validateSectorIdentifierURI(requestID string, redirectURIs []string, sectorIdentifierURI string) error {
	if sectorIdentifierURI == "" {
		return nil
	}

	parsedURI, err := url.Parse(sectorIdentifierURI)
	if err != nil {
		c.logger.Warn(c.module, requestID, "Malformed sector identifier URI: %s", sectorIdentifierURI)
		return errors.New(errors.ErrCodeInvalidClientMetadata, fmt.Sprintf("malformed sector identifier URI: %s", sectorIdentifierURI))
	}
	if parsedURI.Scheme != "https" {
		return errors.New(errors.ErrCodeInvalidClientMetadata, "sector identifier URI must use HTTPS")
	}

	client := http.Client{
		Timeout: c.sectorURIFetchTimeout,
	}
	resp, err := client.Get(sectorIdentifierURI)
	if err != nil {
		c.logger.Warn(c.module, requestID, "Failed to fetch sector identifier URI (%s): %v", sectorIdentifierURI, err)
		return errors.Wrap(err, errors.ErrCodeInvalidClientMetadata, "failed to fetch sector identifier URI")
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			c.logger.Error(c.module, requestID, "[validateSectorIdentifierURI]: Failed to close io.Closer: %v", err)
		}
	}()

	if resp.StatusCode != http.StatusOK {
		c.logger.Warn(c.module, requestID, "Sector identifier URI (%s) returned non-200 status: %d", sectorIdentifierURI, resp.StatusCode)
		return errors.New(errors.ErrCodeInvalidClientMetadata, fmt.Sprintf("sector identifier URI returned non-200 status: %d", resp.StatusCode))
	}

	contentType := resp.Header.Get("Content-Type")
	if !strings.Contains(contentType, "application/json") {
		c.logger.Warn(c.module, requestID, "Sector identifier URI (%s) returned unexpected Content-Type: %s", sectorIdentifierURI, contentType)
		return errors.New(errors.ErrCodeInvalidClientMetadata, fmt.Sprintf("sector identifier URI returned unexpected Content-Type: %s", contentType))
	}

	var fetchedRedirectURIs []string
	if err := json.NewDecoder(resp.Body).Decode(&fetchedRedirectURIs); err != nil {
		c.logger.Warn(c.module, requestID, "Failed to decode JSON from sector identifier URI (%s): %v", sectorIdentifierURI, err)
		return errors.Wrap(err, errors.ErrCodeInvalidClientMetadata, "failed to decode JSON from sector identifier URI")
	}

	if len(fetchedRedirectURIs) == 0 {
		c.logger.Warn(c.module, requestID, "Sector identifier URI (%s) returned an empty array", sectorIdentifierURI)
		return errors.New(errors.ErrCodeInvalidClientMetadata, "sector identifier URI returned an empty array")
	}

	for _, providedURI := range redirectURIs {
		found := false
		for _, fetchedURI := range fetchedRedirectURIs {
			if providedURI == fetchedURI {
				found = true
				break
			}
		}
		if !found {
			c.logger.Warn(c.module, requestID, "Redirect URI '%s' not found in sector identifier URI (%s)", providedURI, sectorIdentifierURI)
			return errors.New(errors.ErrCodeInvalidClientMetadata, fmt.Sprintf("redirect URI '%s' not found in sector identifier URI (%s)", providedURI, sectorIdentifierURI))
		}
	}

	return nil
}

func (c *clientValidator) validateGrantType(requestID string, req clients.ClientRequest) error {
	if len(req.GetGrantTypes()) == 0 {
		c.logger.Warn(c.module, requestID, "Grant type validation failed: grant_types is empty")
		return errors.New(errors.ErrCodeInvalidClientMetadata, "grant_types is empty")
	}

	validGrantTypes := constants.SupportedGrantTypes
	for _, grantType := range req.GetGrantTypes() {
		if _, ok := validGrantTypes[grantType]; !ok {
			c.logger.Warn(c.module, requestID, "Unsupported grant type provided: %s", grantType)
			return errors.New(errors.ErrCodeInvalidClientMetadata, fmt.Sprintf("grant type %s is not supported", grantType))
		}

		if req.GetType() == types.PublicClient {
			if grantType == constants.ClientCredentialsGrantType || grantType == constants.PasswordGrantType {
				return errors.New(errors.ErrCodeInvalidClientMetadata, fmt.Sprintf("grant type %s is not supported for public clients", grantType))
			}
		}

		if grantType == constants.RefreshTokenGrantType && len(req.GetGrantTypes()) == 0 {
			return errors.New(errors.ErrCodeInvalidClientMetadata, fmt.Sprintf("%s requires another grant type", grantType))
		}
	}

	return nil
}

func (c *clientValidator) validateResponseTypes(requestID string, req clients.ClientRequest) error {
	if len(req.GetResponseTypes()) == 0 {
		c.logger.Warn(c.module, requestID, "Response type validation failed: response_types is empty")
		return errors.New(errors.ErrCodeInvalidClientMetadata, "response_types is empty")
	}

	for _, responseType := range req.GetResponseTypes() {
		if _, ok := constants.SupportedResponseTypes[responseType]; !ok {
			c.logger.Warn(c.module, requestID, "Unsupported response type: %s", responseType)
			return errors.New(errors.ErrCodeInvalidClientMetadata, fmt.Sprintf("response type '%s' is not supported", responseType))
		}
	}

	// Validate compatibility with grant types
	authCodeOrDeviceCode := utils.Contains(req.GetGrantTypes(), constants.AuthorizationCodeGrantType) || utils.Contains(req.GetGrantTypes(), constants.DeviceCodeGrantType)
	implicitFlow := utils.Contains(req.GetGrantTypes(), constants.ImplicitGrantType)
	idToken := utils.Contains(req.GetResponseTypes(), constants.IDTokenResponseType)
	code := utils.Contains(req.GetResponseTypes(), constants.CodeResponseType)
	token := utils.Contains(req.GetResponseTypes(), constants.TokenResponseType)

	if authCodeOrDeviceCode && !code {
		c.logger.Warn(c.module, requestID, "Incompatible response type: 'code' is required for grant types 'authorization_code' or 'device_code'")
		return errors.New(errors.ErrCodeInvalidClientMetadata, "code response type is required for the authorization code or device code grant type")
	}

	if implicitFlow && !token {
		c.logger.Warn(c.module, requestID, "Incompatible response type: 'token' is required for the 'implicit' grant type")
		return errors.New(errors.ErrCodeInvalidClientMetadata, "token response type is required for the implicit flow grant type")
	}

	if idToken && !authCodeOrDeviceCode && !implicitFlow {
		c.logger.Warn(c.module, requestID, "Incompatible response type: 'id_token' requires 'authorization_code' or 'implicit' grant type")
		return errors.New(errors.ErrCodeInvalidClientMetadata, "ID token response type is only allowed with the authorization code, device code or implicit flow grant types")
	}

	return nil
}

func (c *clientValidator) validateCodeChallengeMethod(requestID string, codeChallengeMethod types.CodeChallengeMethod) error {
	if _, ok := types.SupportedCodeChallengeMethods[codeChallengeMethod]; !ok {
		c.logger.Error(c.module, requestID, "Failed to validate authorization request: invalid code challenge method: %s", codeChallengeMethod)
		return errors.New(
			errors.ErrCodeInvalidRequest,
			fmt.Sprintf("invalid code challenge method: '%s'. Valid methods are 'plain' and 'SHA-256'", codeChallengeMethod),
		)
	}

	return nil
}

func (c *clientValidator) validateCodeChallenge(requestID, codeChallenge string) error {
	codeChallengeLength := len(codeChallenge)
	if codeChallengeLength < 43 || codeChallengeLength > 128 {
		c.logger.Error(c.module, requestID, "Failed to validate code challenge: code challenge does not meet length requirements")
		return errors.New(
			errors.ErrCodeInvalidRequest,
			fmt.Sprintf("invalid code challenge length (%d): must be between 43 and 128 characters", codeChallengeLength),
		)
	}

	validCodeChallengeRegex := regexp.MustCompile(`^[A-Za-z0-9._~-]+$`)
	if !validCodeChallengeRegex.MatchString(codeChallenge) {
		c.logger.Error(c.module, requestID, "Failed to validate code challenge: contains invalid characters")
		return errors.New(errors.ErrCodeInvalidRequest, "invalid characters: only A-Z, a-z, 0-9, '-', and '_' are allowed (Base64 URL encoding)")
	}

	return nil
}
