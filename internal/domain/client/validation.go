package domain

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/vigiloauth/vigilo/v2/idp/config"
	"github.com/vigiloauth/vigilo/v2/internal/constants"
	"github.com/vigiloauth/vigilo/v2/internal/errors"
	"github.com/vigiloauth/vigilo/v2/internal/types"
)

var logger = config.GetServerConfig().Logger()

const (
	module                string        = "Client Validation"
	sectorURIFetchTimeout time.Duration = 5 * time.Second
)

// ValidateClientRegistrationRequest checks if the ClientRegistrationRequest contains valid values.
func ValidateClientRegistrationRequest(req *ClientRegistrationRequest) error {
	logger.Debug(module, "", "Starting validation for client registration request")

	if req.Name == "" {
		logger.Warn(module, "", "Validation failed: client_name is empty")
		return errors.New(errors.ErrCodeInvalidClientMetadata, "client_name is empty")
	}
	if err := validateApplicationType(req); err != nil {
		logger.Error(module, "", "[ValidateClientRegistrationRequest]: An error occurred validating the application type: %v", err)
		return err
	}
	if err := validateTokenEndpointAuthMethod(req); err != nil {
		logger.Error(module, "", "[ValidateClientRegistrationRequest]: An error occurred validating the token endpoint auth method: %v", err)
		return err
	}

	determineClientType(req)
	if err := validateGrantAndResponseTypes(req); err != nil {
		logger.Error(module, "", "[ValidateClientRegistrationRequest]: An error occurred validating grant and response types: %v", err)
		return err
	}
	if err := validateURIS(req); err != nil {
		logger.Error(module, "", "[ValidateClientRegistrationRequest]: An error occurred validating client URIS: %v", err)
		return errors.Wrap(err, "", "the value of one or more redirection URIs is invalid")
	}
	if err := validateScopes(req); err != nil {
		logger.Error(module, "", "[ValidateClientRegistrationRequest]: An error occurred validating scopes: %v", err)
		return err
	}

	logger.Debug(module, "", "No errors while validating client registration request")
	return nil
}

// ValidateClientUpdateRequest checks if the ClientUpdateRequest contains valid values.
func ValidateClientUpdateRequest(req *ClientUpdateRequest) error {
	if err := validateGrantType(req); err != nil {
		logger.Error(module, "", "[ValidateClientUpdateRequest]: An error occurred validating grant types: %v", err)
		return err
	}
	if err := validateURIS(req); err != nil {
		logger.Error(module, "", "[ValidateClientUpdateRequest]: An error occurred validating client URIS: %v", err)
		return err
	}
	if err := validateScopes(req); err != nil {
		logger.Error(module, "", "[ValidateClientUpdateRequest]: An error occurred validating scopes: %v", err)
		return err
	}
	if err := validateResponseTypes(req); err != nil {
		logger.Error(module, "", "[ValidateClientUpdateRequest]: An error occurred validating response types: %v", err)
		return err
	}

	return nil
}

// ValidateClientAuthorizationRequest checks if the ClientAuthorizationRequest contains valid values.
func ValidateClientAuthorizationRequest(req *ClientAuthorizationRequest) error {
	if !req.Client.HasGrantType(constants.AuthorizationCodeGrantType) {
		logger.Error(module, "", "Failed to validate client authorization: client does not have the required grant types")
		return errors.New(errors.ErrCodeInvalidGrant, "authorization code grant is required for this request")
	}

	if req.Client.RequiresPKCE && req.CodeChallenge == "" {
		logger.Error(module, "", "Failed to validate client authorization request: client did not provide a code challenge for the PKCE grant type")
		return errors.New(errors.ErrCodeInvalidRequest, "code_challenge is required for PKCE")
	} else if !req.Client.RequiresPKCE && req.CodeChallenge != "" {
		logger.Error(module, "", "Failed to validate request: client provided a code challenge but does not have the PKCE grant type")
		return errors.New(errors.ErrCodeInvalidRequest, "PKCE is required when providing a code challenge")
	}

	if !req.Client.HasResponseType(constants.CodeResponseType) || !req.Client.HasResponseType(req.ResponseType) {
		logger.Error(module, "", "Failed to validate client authorization request: client does not have the code response type")
		return errors.New(errors.ErrCodeInvalidClient, "code response type is required to receive an authorization code")
	}

	if req.CodeChallenge != "" {
		if req.CodeChallengeMethod == "" {
			logger.Warn(module, "", "Code challenge method was not provided, defaulting to 'plain'")
			req.CodeChallengeMethod = types.PlainCodeChallengeMethod
		}

		if err := validateCodeChallengeMethod(req.CodeChallengeMethod); err != nil {
			logger.Error(module, "", "Failed to validate authorization request: %v", err)
			return err
		}

		if err := validateCodeChallenge(req.CodeChallenge); err != nil {
			logger.Error(module, "", "Failed to validate authorization request: %v", err)
			return err
		}
	}

	return nil
}

func determineClientType(req *ClientRegistrationRequest) {
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

func validateTokenEndpointAuthMethod(req *ClientRegistrationRequest) error {
	if req.TokenEndpointAuthMethod == "" {
		logger.Warn(module, "", "No token endpoint auth method provided")
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

func validateApplicationType(req *ClientRegistrationRequest) error {
	if req.ApplicationType == "" {
		logger.Debug(module, "", "No application type given, will be determined dynamically")
		return nil
	}

	if !constants.ValidApplicationTypes[req.ApplicationType] {
		logger.Error(module, "", "Invalid application type provided: %v", req.ApplicationType)
		return errors.New(
			errors.ErrCodeInvalidClientMetadata,
			fmt.Sprintf("invalid application type: %s", req.ApplicationType),
		)
	}

	return nil
}

// Function to replace or modify validateGrantAndResponseTypes
func validateGrantAndResponseTypes(req *ClientRegistrationRequest) error {
	if len(req.GrantTypes) == 0 {
		logger.Error(module, "", "No grant types were requested")
		return errors.New(errors.ErrCodeInvalidClientMetadata, "at least one grant_type must be requested")
	}
	if len(req.ResponseTypes) == 0 && (contains(req.GrantTypes, constants.AuthorizationCodeGrantType) || contains(req.GrantTypes, constants.ImplicitGrantType)) {
		return errors.New(errors.ErrCodeInvalidClientMetadata, "response_types are required for authorization_code or implicit grant types")
	}

	if req.Type == types.PublicClient {
		if contains(req.GrantTypes, constants.ClientCredentialsGrantType) {
			logger.Warn(module, "", "Validation failed: Public client requested client_credentials grant")
			return errors.New(errors.ErrCodeInvalidClientMetadata, "public clients cannot request the client_credentials grant")
		}
		if contains(req.GrantTypes, constants.PasswordGrantType) {
			logger.Warn(module, "", "Validation failed: Public client requested password grant")
			return errors.New(errors.ErrCodeInvalidClientMetadata, "public clients cannot request the password grant")
		}

		if req.Type == types.PublicClient && contains(req.GrantTypes, constants.AuthorizationCodeGrantType) {
			req.RequiresPKCE = true
		}
	}

	requestsAuthCodeGrant := contains(req.GrantTypes, constants.AuthorizationCodeGrantType)
	requestsImplicitGrant := contains(req.GrantTypes, constants.ImplicitGrantType)

	requestsCodeResponseType := containsResponseType(req.ResponseTypes, constants.CodeResponseType)
	requestsIDTokenResponseType := containsResponseType(req.ResponseTypes, constants.IDTokenResponseType)
	requestsTokenResponseType := containsResponseType(req.ResponseTypes, constants.TokenResponseType)

	if requestsAuthCodeGrant || requestsImplicitGrant {
		if !requestsCodeResponseType && !requestsIDTokenResponseType && !requestsTokenResponseType {
			logger.Warn(module, "", "Validation failed: Auth Code/Implicit grants requested without corresponding response types.")
			return errors.New(errors.ErrCodeInvalidClientMetadata, "client requesting authorization_code or implicit grants must include 'code', 'id_token', or 'token' in response_types")
		}
	}

	if requestsAuthCodeGrant && !requestsCodeResponseType {
		logger.Warn(module, "", "Validation failed: Auth Code grant requested without 'code' response type.")
		return errors.New(errors.ErrCodeInvalidClientMetadata, "client requesting authorization_code grant must include 'code' in response_types")
	}

	if requestsCodeResponseType && !requestsAuthCodeGrant {
		logger.Warn(module, "", "Validation failed: 'code' response type requested without Auth Code grant.")
		return errors.New(errors.ErrCodeInvalidClientMetadata, "client requesting response_types including 'code' must include authorization_code grant")
	}

	usesImplicitResponseTypes := requestsIDTokenResponseType || requestsTokenResponseType
	requestsImplicitFlowWithoutCode := usesImplicitResponseTypes && !requestsCodeResponseType

	if requestsImplicitGrant && !requestsImplicitFlowWithoutCode && !requestsAuthCodeGrant { // Requests Implicit grant, but no implicit-only response types, and no Auth Code grant for hybrid
		logger.Warn(module, "", "Validation failed: Implicit grant requested without corresponding response types or hybrid.")
		return errors.New(errors.ErrCodeInvalidClientMetadata, "client requesting implicit grant must include 'id_token', 'token', or both in response_types (or request a hybrid flow)")
	}

	if requestsImplicitFlowWithoutCode && !requestsImplicitGrant { // Requests implicit-only response types, but no Implicit grant requested
		logger.Warn(module, "", "Validation failed: Implicit flow response types requested without Implicit grant.")
		return errors.New(errors.ErrCodeInvalidClientMetadata, "client requesting response_types including 'id_token' or 'token' (without 'code') must include implicit grant")
	}

	if contains(req.GrantTypes, constants.RefreshTokenGrantType) {
		if !requestsAuthCodeGrant && !contains(req.GrantTypes, constants.PasswordGrantType) {
			logger.Warn(module, "", "Validation failed: Refresh Token grant requested without a valid issuing grant.")
			return errors.New(errors.ErrCodeInvalidClientMetadata, "refresh_token grant requires a grant type capable of issuing refresh tokens (e.g., authorization_code or password)")
		}
	}

	return nil
}

// validateGrantType checks if the provided grant types are valid.
func validateGrantType(req ClientRequest) error {
	if len(req.GetGrantTypes()) == 0 {
		logger.Warn(module, "", "Grant type validation failed: grant_types is empty")
		return errors.New(errors.ErrCodeInvalidClientMetadata, "grant_types is empty")
	}

	validGrantTypes := constants.SupportedGrantTypes
	for _, grantType := range req.GetGrantTypes() {
		if _, ok := validGrantTypes[grantType]; !ok {
			logger.Warn(module, "", "Unsupported grant type provided: %s", grantType)
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

// validateURIS checks if redirect URIs are well-formed and secure.
func validateURIS(req ClientRequest) error {
	if req.GetType() == types.ConfidentialClient && req.HasGrantType(constants.AuthorizationCodeGrantType) && len(req.GetRedirectURIS()) == 0 {
		return errors.New(errors.ErrCodeInvalidClientMetadata, "redirect URI(s) are required for confidential clients using the authorization code grant type")
	}

	if req.GetType() == types.PublicClient && len(req.GetRedirectURIS()) == 0 {
		logger.Warn(module, "", "Validation failed: redirect_uris is empty for public client")
		return errors.New(errors.ErrCodeInvalidClientMetadata, "redirect URI(s) are required for public clients")
	}

	if req.GetJwksURI() != "" {
		if _, err := url.ParseRequestURI(req.GetJwksURI()); err != nil {
			logger.Warn(module, "", "Invalid jwks_uri provided: %s", req.GetJwksURI())
			return errors.New(errors.ErrCodeInvalidClientMetadata, "invalid jwks_uri format")

		}
	}

	if err := validateSectorIdentifierURI(req.GetRedirectURIS(), req.GetSectorIdentifierURI()); err != nil {
		logger.Error(module, "", "Failed to validate sector identifier URI: %v", err)
		return err
	}

	if req.GetLogoURI() != "" {
		if _, err := url.ParseRequestURI(req.GetLogoURI()); err != nil {
			logger.Warn(module, "", "Invalid logo_uri: %s", req.GetLogoURI())
			return errors.New(errors.ErrCodeInvalidClientMetadata, "invalid logo_uri format")
		}
	}

	mobileSchemePattern := regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9+.-]*:\/\/`)
	for _, uri := range req.GetRedirectURIS() {
		if uri == "" {
			logger.Warn(module, "", "Empty redirect_uri found")
			return errors.New(errors.ErrCodeInvalidRedirectURI, "'redirect_uri' is empty")
		}
		if strings.HasPrefix(uri, "http://localhost") || strings.HasPrefix(uri, "http://127.0.0.1") {
			continue
		}
		if containsWildcard(uri) {
			logger.Warn(module, "", "Redirect URI contains wildcard: %s", uri)
			return errors.New(errors.ErrCodeInvalidRedirectURI, "redirect URIs cannot have wildcards")
		}

		parsedURI, err := url.Parse(uri)
		if err != nil {
			logger.Warn(module, "", "Malformed redirect URI: %s", uri)
			return errors.New(errors.ErrCodeInvalidRedirectURI, fmt.Sprintf("malformed redirect URI: %s", uri))
		}

		switch req.GetType() {
		case types.ConfidentialClient:
			if parsedURI.Scheme != "https" {
				logger.Warn(module, "", "Confidential client redirect URI is not using HTTPS: %s", uri)
				return errors.New(errors.ErrCodeInvalidRedirectURI, "confidential clients must use HTTPS")
			}
			if net.ParseIP(parsedURI.Hostname()) != nil && !isLoopbackIP(parsedURI.Hostname()) {
				logger.Warn(module, "", "Confidential client redirect URI is using IP address: %s", uri)
				return errors.New(errors.ErrCodeInvalidRedirectURI, "IP address not allowed as redirect URI hosts")
			}
			if parsedURI.Fragment != "" {
				logger.Warn(module, "", "Confidential client redirect URI contains fragment: %s", uri)
				return errors.New(errors.ErrCodeInvalidRedirectURI, "fragment component not allowed")
			}

		case types.PublicClient:
			isMobileScheme := mobileSchemePattern.MatchString(uri) && parsedURI.Scheme != "http" && parsedURI.Scheme != "https"
			if isMobileScheme {
				if len(parsedURI.Scheme) < 4 {
					logger.Warn(module, "", "Mobile URI scheme is too short: %s", uri)
					return errors.New(errors.ErrCodeInvalidRedirectURI, "mobile URI scheme is too short")
				}
			} else if parsedURI.Scheme != "https" {
				logger.Warn(module, "", "Public client redirect URI is not using HTTPS: %s", uri)
				return errors.New(errors.ErrCodeInvalidRedirectURI, "public clients must use HTTPS")
			}
		}
	}

	return nil
}

// validateScopes ensures all provided scopes are valid.
func validateScopes(req ClientRequest) error {
	if len(req.GetScopes()) == 0 {
		return nil
	}

	for _, scope := range req.GetScopes() {
		if _, ok := types.SupportedScopes[scope]; !ok {
			logger.Warn(module, "Unsupported scope: %s", scope.String())
			return errors.New(errors.ErrCodeInvalidClientMetadata, fmt.Sprintf("scope '%s' is not supported", scope))
		}
	}

	if !contains(req.GetScopes(), types.OpenIDScope) {
		requestedScopes := req.GetScopes()
		newScopes := append(requestedScopes, types.OpenIDScope)
		req.SetScopes(newScopes)
		logger.Info(module, "", "Adding default 'oidc' scope to client")
	}

	return nil
}

// validateResponseTypes ensures all provided response types are valid and compatible with grant types.
func validateResponseTypes(req ClientRequest) error {
	if len(req.GetResponseTypes()) == 0 {
		logger.Warn(module, "", "Response type validation failed: response_types is empty")
		return errors.New(errors.ErrCodeInvalidClientMetadata, "response_types is empty")
	}

	for _, responseType := range req.GetResponseTypes() {
		if _, ok := constants.SupportedResponseTypes[responseType]; !ok {
			logger.Warn(module, "", "Unsupported response type: %s", responseType)
			return errors.New(errors.ErrCodeInvalidClientMetadata, fmt.Sprintf("response type '%s' is not supported", responseType))
		}
	}

	// Validate compatibility with grant types
	authCodeOrDeviceCode := contains(req.GetGrantTypes(), constants.AuthorizationCodeGrantType) || contains(req.GetGrantTypes(), constants.DeviceCodeGrantType)
	implicitFlow := contains(req.GetGrantTypes(), constants.ImplicitGrantType)
	idToken := contains(req.GetResponseTypes(), constants.IDTokenResponseType)
	code := contains(req.GetResponseTypes(), constants.CodeResponseType)
	token := contains(req.GetResponseTypes(), constants.TokenResponseType)

	if authCodeOrDeviceCode && !code {
		logger.Warn(module, "", "Incompatible response type: 'code' is required for grant types 'authorization_code' or 'device_code'")
		return errors.New(errors.ErrCodeInvalidClientMetadata, "code response type is required for the authorization code or device code grant type")
	}

	if implicitFlow && !token {
		logger.Warn(module, "", "Incompatible response type: 'token' is required for the 'implicit' grant type")
		return errors.New(errors.ErrCodeInvalidClientMetadata, "token response type is required for the implicit flow grant type")
	}

	if idToken && !(authCodeOrDeviceCode || implicitFlow) {
		logger.Warn(module, "", "Incompatible response type: 'id_token' requires 'authorization_code' or 'implicit' grant type")
		return errors.New(errors.ErrCodeInvalidClientMetadata, "ID token response type is only allowed with the authorization code, device code or implicit flow grant types")
	}

	return nil
}

// validateCodeChallenge makes sure the code challenge is long enough and that it does not contain invalid characters.
func validateCodeChallenge(codeChallenge string) error {
	codeChallengeLength := len(codeChallenge)
	if codeChallengeLength < 43 || codeChallengeLength > 128 {
		logger.Error(module, "", "Failed to validate code challenge: code challenge does not meet length requirements")
		return errors.New(
			errors.ErrCodeInvalidRequest,
			fmt.Sprintf("invalid code challenge length (%d): must be between 43 and 128 characters", codeChallengeLength),
		)
	}

	validCodeChallengeRegex := regexp.MustCompile(`^[A-Za-z0-9._~-]+$`)
	if !validCodeChallengeRegex.MatchString(codeChallenge) {
		logger.Error(module, "", "Failed to validate code challenge: contains invalid characters")
		return errors.New(errors.ErrCodeInvalidRequest, "invalid characters: only A-Z, a-z, 0-9, '-', and '_' are allowed (Base64 URL encoding)")
	}

	return nil
}

// validateCodeChallengeMethod makes sure the code challenge method is valid.
func validateCodeChallengeMethod(codeChallengeMethod types.CodeChallengeMethod) error {
	if _, ok := types.SupportedCodeChallengeMethods[codeChallengeMethod]; !ok {
		logger.Error(module, "", "Failed to validate authorization request: invalid code challenge method: %s", codeChallengeMethod)
		return errors.New(
			errors.ErrCodeInvalidRequest,
			fmt.Sprintf("invalid code challenge method: '%s'. Valid methods are 'plain' and 'SHA-256'", codeChallengeMethod),
		)
	}

	return nil
}

func validateSectorIdentifierURI(redirectURIs []string, sectorIdentifierURI string) error {
	if sectorIdentifierURI == "" {
		return nil
	}

	parsedURI, err := url.Parse(sectorIdentifierURI)
	if err != nil {
		logger.Warn(module, "", "Malformed sector identifier URI: %s", sectorIdentifierURI)
		return errors.New(errors.ErrCodeInvalidClientMetadata, fmt.Sprintf("malformed sector identifier URI: %s", sectorIdentifierURI))
	}
	if parsedURI.Scheme != "https" {
		return errors.New(errors.ErrCodeInvalidClientMetadata, "sector identifier URI must use HTTPS")
	}

	client := http.Client{
		Timeout: sectorURIFetchTimeout,
	}
	resp, err := client.Get(sectorIdentifierURI)
	if err != nil {
		logger.Warn(module, "", "Failed to fetch sector identifier URI (%s): %v", sectorIdentifierURI, err)
		return errors.Wrap(err, errors.ErrCodeInvalidClientMetadata, "failed to fetch sector identifier URI")
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		logger.Warn(module, "", "Sector identifier URI (%s) returned non-200 status: %d", sectorIdentifierURI, resp.StatusCode)
		return errors.New(errors.ErrCodeInvalidClientMetadata, fmt.Sprintf("sector identifier URI returned non-200 status: %d", resp.StatusCode))
	}

	contentType := resp.Header.Get("Content-Type")
	if !strings.Contains(contentType, "application/json") {
		logger.Warn(module, "", "Sector identifier URI (%s) returned unexpected Content-Type: %s", sectorIdentifierURI, contentType)
		return errors.New(errors.ErrCodeInvalidClientMetadata, fmt.Sprintf("sector identifier URI returned unexpected Content-Type: %s", contentType))
	}

	var fetchedRedirectURIs []string
	if err := json.NewDecoder(resp.Body).Decode(&fetchedRedirectURIs); err != nil {
		logger.Warn(module, "", "Failed to decode JSON from sector identifier URI (%s): %v", sectorIdentifierURI, err)
		return errors.Wrap(err, errors.ErrCodeInvalidClientMetadata, "failed to decode JSON from sector identifier URI")
	}

	if len(fetchedRedirectURIs) == 0 {
		logger.Warn(module, "", "Sector identifier URI (%s) returned an empty array", sectorIdentifierURI)
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
			logger.Warn(module, "", "Redirect URI '%s' not found in sector identifier URI (%s)", providedURI, sectorIdentifierURI)
			return errors.New(errors.ErrCodeInvalidClientMetadata, fmt.Sprintf("redirect URI '%s' not found in sector identifier URI (%s)", providedURI, sectorIdentifierURI))
		}
	}

	return nil
}

// contains checks if a slice contains a specific element.
func contains[T comparable](slice []T, element T) bool {
	return slices.Contains(slice, element)
}

// checks if a string contains a wildcard
func containsWildcard(uri string) bool {
	return strings.Contains(uri, "*")
}

// isLoopbackIP checks if the given IP is a loopback address.
func isLoopbackIP(host string) bool {
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// Helper to check if a slice of space-separated response type strings contains a specific component (e.g., "code", "id_token", "token").
func containsResponseType(responseTypes []string, component string) bool {
	for _, responseTypeCombo := range responseTypes {
		components := strings.Fields(responseTypeCombo)
		if slices.Contains(components, component) {
			return true
		}
	}

	return false
}
