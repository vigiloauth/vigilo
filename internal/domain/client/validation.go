package domain

import (
	"fmt"
	"net"
	"net/url"
	"regexp"
	"slices"
	"strings"

	"github.com/vigiloauth/vigilo/v2/idp/config"
	"github.com/vigiloauth/vigilo/v2/internal/constants"
	"github.com/vigiloauth/vigilo/v2/internal/errors"
)

var logger = config.GetServerConfig().Logger()

const module string = "Client Validation"

// ValidateClientRegistrationRequest checks if the ClientRegistrationRequest contains valid values.
func ValidateClientRegistrationRequest(req *ClientRegistrationRequest) error {
	logger.Debug(module, "", "Starting validation for client registration request")
	errorCollection := errors.NewErrorCollection()

	if req.Name == "" {
		err := errors.New(errors.ErrCodeEmptyInput, "client_name is empty")
		errorCollection.Add(err)
		logger.Warn(module, "", "Validation failed: client_name is empty")
	}

	if req.Type == Public && req.Secret != "" {
		err := errors.New(errors.ErrCodeInvalidClientMetadata, "client_secret is not allowed for public clients")
		errorCollection.Add(err)
		logger.Warn(module, "", "Validation failed: client_secret provided for a public client")
	}

	if !contains(req.GrantTypes, constants.PKCE) {
		if req.Type == Public {
			logger.Warn(module, "", "Validation failed: Public client is not using PKCE")
			return errors.New(errors.ErrCodeInvalidRequest, "PKCE is required for public clients")
		} else if req.Type == Confidential {
			logger.Warn(module, "", "It is recommended for confidential clients to use PKCE")
		}
	}

	if req.TokenEndpointAuthMethod != "" && !slices.Contains(req.GrantTypes, constants.ClientCredentials) {
		err := errors.New(errors.ErrCodeInvalidClientMetadata, "token_endpoint_auth_method is required for the client_credentials grant")
		errorCollection.Add(err)
		logger.Warn(module, "", "Validation failed: token_endpoint_auth_method provided without client_credentials grant")
	}

	validateClientType(req, errorCollection)
	validateGrantType(req, errorCollection)
	validateURIS(req, errorCollection)
	validateScopes(req, errorCollection)
	validateResponseTypes(req, errorCollection)

	if errorCollection.HasErrors() {
		logger.Error(module, "", "Validation failed with errors for client registration request: %v", errorCollection.Errors())
		return errorCollection
	}

	logger.Debug(module, "", "No errors while validating client registration request")
	return nil
}

// ValidateClientUpdateRequest checks if the ClientUpdateRequest contains valid values.
func ValidateClientUpdateRequest(req *ClientUpdateRequest) error {
	errorCollection := errors.NewErrorCollection()

	validateGrantType(req, errorCollection)
	validateURIS(req, errorCollection)
	validateScopes(req, errorCollection)
	validateResponseTypes(req, errorCollection)

	if errorCollection.HasErrors() {
		logger.Error(module, "", "Validation failed with errors for client update request: %v", errorCollection.Errors())
		return errorCollection
	}

	return nil
}

// ValidateClientAuthorizationRequest checks if the ClientAuthorizationRequest contains valid values.
func ValidateClientAuthorizationRequest(req *ClientAuthorizationRequest) error {
	if !req.Client.HasGrantType(constants.AuthorizationCode) {
		logger.Error(module, "", "Failed to validate client authorization: client does not have the required grant types")
		return errors.New(errors.ErrCodeInvalidGrant, "authorization code grant is required for this request")
	}

	if !req.Client.IsConfidential() && !req.Client.RequiresPKCE() {
		return errors.New(errors.ErrCodeInvalidGrant, "public clients are required to use PKCE")
	}

	if req.Client.RequiresPKCE() && req.CodeChallenge == "" {
		logger.Error(module, "", "Failed to validate client authorization request: client did not provide a code challenge for the PKCE grant type")
		return errors.New(errors.ErrCodeInvalidRequest, "code_challenge is required for PKCE")
	} else if !req.Client.RequiresPKCE() && req.CodeChallenge != "" {
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
			req.CodeChallengeMethod = Plain
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

// validateClientType ensures the client type is either Confidential or Public.
func validateClientType(req ClientRequest, errorCollection *errors.ErrorCollection) {
	if req.GetType() != Confidential && req.GetType() != Public {
		logger.Warn(module, "", "Invalid client type provided: %s", req.GetType())
		err := errors.New(errors.ErrCodeInvalidClient, "client must be public or confidential")
		errorCollection.Add(err)
	}
}

// validateGrantType checks if the provided grant types are valid.
func validateGrantType(req ClientRequest, errorCollection *errors.ErrorCollection) {
	if len(req.GetGrantTypes()) == 0 {
		logger.Warn(module, "", "Grant type validation failed: grant_types is empty")
		err := errors.New(errors.ErrCodeEmptyInput, "grant_types is empty")
		errorCollection.Add(err)
		return
	}

	validGrantTypes := constants.SupportedGrantTypes
	for _, grantType := range req.GetGrantTypes() {
		if _, ok := validGrantTypes[grantType]; !ok {
			logger.Warn(module, "", "Unsupported grant type provided: %s", grantType)
			err := errors.New(errors.ErrCodeInvalidClientMetadata, fmt.Sprintf("grant type %s is not supported", grantType))
			errorCollection.Add(err)
			continue
		}

		if req.GetType() == Public {
			if grantType == constants.ClientCredentials || grantType == constants.PasswordGrant {
				err := errors.New(errors.ErrCodeInvalidClientMetadata, fmt.Sprintf("grant type %s is not supported for public clients", grantType))
				errorCollection.Add(err)
			}
		}

		if grantType == constants.RefreshToken && len(req.GetGrantTypes()) == 0 {
			err := errors.New(errors.ErrCodeInvalidClientMetadata, fmt.Sprintf("%s requires another grant type", grantType))
			errorCollection.Add(err)
		}
	}
}

// validateURIS checks if redirect URIs are well-formed and secure.
func validateURIS(req ClientRequest, errorCollection *errors.ErrorCollection) {
	if req.GetType() == Confidential && req.HasGrantType(constants.AuthorizationCode) && len(req.GetRedirectURIS()) == 0 {
		err := errors.New(errors.ErrCodeInvalidGrant, "redirect URI(s) are required for confidential clients using the authorization code grant type")
		errorCollection.Add(err)
		return
	}

	if req.GetType() == Public && len(req.GetRedirectURIS()) == 0 {
		logger.Warn(module, "", "Validation failed: redirect_uris is empty for public client")
		err := errors.New(errors.ErrCodeEmptyInput, "redirect URI(s) are required for public clients")
		errorCollection.Add(err)
		return
	}

	if req.GetJwksURI() != "" {
		if _, err := url.ParseRequestURI(req.GetJwksURI()); err != nil {
			logger.Warn(module, "", "Invalid jwks_uri provided: %s", req.GetJwksURI())
			err = errors.New(errors.ErrCodeInvalidClientMetadata, "invalid jwks_uri format")
			errorCollection.Add(err)
		}
	}

	if req.GetLogoURI() != "" {
		if _, err := url.ParseRequestURI(req.GetLogoURI()); err != nil {
			logger.Warn(module, "", "Invalid logo_uri: %s", req.GetLogoURI())
			err = errors.New(errors.ErrCodeInvalidClientMetadata, "invalid logo_uri format")
			errorCollection.Add(err)
		}
	}

	mobileSchemePattern := regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9+.-]*:\/\/`)
	for _, uri := range req.GetRedirectURIS() {
		if uri == "" {
			err := errors.New(errors.ErrCodeInvalidRedirectURI, "'redirect_uri' is empty")
			errorCollection.Add(err)
			logger.Warn(module, "", "Empty redirect_uri found")
			continue
		}
		if strings.HasPrefix(uri, "http://localhost") || strings.HasPrefix(uri, "http://127.0.0.1") {
			continue
		}
		if containsWildcard(uri) {
			err := errors.New(errors.ErrCodeInvalidRedirectURI, "redirect URIs cannot have wildcards")
			errorCollection.Add(err)
			logger.Warn(module, "Redirect URI contains wildcard: %s", uri)
			continue
		}

		parsedURI, err := url.Parse(uri)
		if err != nil {
			err := errors.New(errors.ErrCodeInvalidRedirectURI, fmt.Sprintf("malformed redirect URI: %s", uri))
			errorCollection.Add(err)
			logger.Warn(module, "Malformed redirect URI: %s", uri)
			continue
		}

		switch req.GetType() {
		case Confidential:
			if parsedURI.Scheme != "https" {
				err := errors.New(errors.ErrCodeInvalidRedirectURI, "confidential clients must use HTTPS")
				errorCollection.Add(err)
				logger.Warn(module, "Confidential client redirect URI is not using HTTPS: %s", uri)
			}
			if net.ParseIP(parsedURI.Hostname()) != nil && !isLoopbackIP(parsedURI.Hostname()) {
				err := errors.New(errors.ErrCodeInvalidRedirectURI, "IP address not allowed as redirect URI hosts")
				errorCollection.Add(err)
				logger.Warn(module, "Confidential client redirect URI is using IP address: %s", uri)
			}
			if parsedURI.Fragment != "" {
				err := errors.New(errors.ErrCodeInvalidRedirectURI, "fragment component not allowed")
				errorCollection.Add(err)
				logger.Warn(module, "Confidential client redirect URI contains fragment: %s", uri)
			}

		case Public:
			isMobileScheme := mobileSchemePattern.MatchString(uri) && parsedURI.Scheme != "http" && parsedURI.Scheme != "https"
			if isMobileScheme {
				if len(parsedURI.Scheme) < 4 {
					err := errors.New(errors.ErrCodeInvalidRedirectURI, "mobile URI scheme is too short")
					errorCollection.Add(err)
					logger.Warn(module, "Mobile URI scheme is too short: %s", uri)
				}
			} else if parsedURI.Scheme != "https" {
				err := errors.New(errors.ErrCodeInvalidRedirectURI, "public clients must use HTTPS")
				errorCollection.Add(err)
				logger.Warn(module, "Public client redirect URI is not using HTTPS: %s", uri)
			}
		}
	}
}

// validateScopes ensures all provided scopes are valid.
func validateScopes(req ClientRequest, errorCollection *errors.ErrorCollection) {
	if len(req.GetScopes()) == 0 {
		req.SetScopes([]string{constants.ClientRead})
		logger.Info(module, "", "Default scope 'client:read' applied")
		return
	}

	for _, scope := range req.GetScopes() {
		if _, ok := constants.SupportedScopes[scope]; !ok {
			err := errors.New(errors.ErrCodeInsufficientScope, fmt.Sprintf("scope '%s' is not supported", scope))
			errorCollection.Add(err)
			logger.Warn(module, "Unsupported scope: %s", scope)
		}
	}
}

// validateResponseTypes ensures all provided response types are valid and compatible with grant types.
func validateResponseTypes(req ClientRequest, errorCollection *errors.ErrorCollection) {
	if len(req.GetResponseTypes()) == 0 {
		logger.Warn(module, "", "Response type validation failed: response_types is empty")
		err := errors.New(errors.ErrCodeEmptyInput, "response_types is empty")
		errorCollection.Add(err)
		return
	}

	for _, responseType := range req.GetResponseTypes() {
		if _, ok := constants.SupportedResponseTypes[responseType]; !ok {
			logger.Warn(module, "", "Unsupported response type: %s", responseType)
			err := errors.New(errors.ErrCodeInvalidResponseType, fmt.Sprintf("response type '%s' is not supported", responseType))
			errorCollection.Add(err)
			continue
		}
	}

	// Validate compatibility with grant types
	authCodeOrDeviceCode := contains(req.GetGrantTypes(), constants.AuthorizationCode) || contains(req.GetGrantTypes(), constants.DeviceCode)
	implicitFlow := contains(req.GetGrantTypes(), constants.ImplicitFlow)
	pkce := contains(req.GetGrantTypes(), constants.PKCE)
	idToken := contains(req.GetResponseTypes(), constants.IDTokenResponseType)
	code := contains(req.GetResponseTypes(), constants.CodeResponseType)
	token := contains(req.GetResponseTypes(), constants.TokenResponseType)

	if authCodeOrDeviceCode && !code {
		logger.Warn(module, "", "Incompatible response type: 'code' is required for grant types 'authorization_code' or 'device_code'")
		err := errors.New(errors.ErrCodeInvalidResponseType, "code response type is required for the authorization code or device code grant type")
		errorCollection.Add(err)
	}

	if implicitFlow && !token {
		logger.Warn(module, "", "Incompatible response type: 'token' is required for the 'implicit' grant type")
		err := errors.New(errors.ErrCodeInvalidResponseType, "token response type is required for the implicit flow grant type")
		errorCollection.Add(err)
	}

	if pkce && !code {
		logger.Warn(module, "", "Incompatible response type: 'code' is required for the 'PKCE' grant type")
		err := errors.New(errors.ErrCodeInvalidResponseType, "code response type is required when PKCE is being used")
		errorCollection.Add(err)
	}

	if idToken && !(authCodeOrDeviceCode || implicitFlow) {
		logger.Warn(module, "", "Incompatible response type: 'id_token' requires 'authorization_code' or 'implicit' grant type")
		err := errors.New(errors.ErrCodeInvalidResponseType, "ID token response type is only allowed with the authorization code, device code or implicit flow grant types")
		errorCollection.Add(err)
	}
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
func validateCodeChallengeMethod(codeChallengeMethod string) error {
	if _, ok := ValidCodeChallengeMethods[codeChallengeMethod]; !ok {
		logger.Error(module, "", "Failed to validate authorization request: invalid code challenge method: %s", codeChallengeMethod)
		return errors.New(
			errors.ErrCodeInvalidRequest,
			fmt.Sprintf("invalid code challenge method: '%s'. Valid methods are 'plain' and 'SHA-256'", codeChallengeMethod),
		)
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
