package domain

import (
	"fmt"
	"net"
	"net/url"
	"regexp"
	"slices"
	"strings"

	"github.com/vigiloauth/vigilo/internal/errors"
)

// Validate checks if the ClientRegistrationRequest contains valid values.
func ValidateClientRegistrationRequest(req *ClientRegistrationRequest) error {
	errorCollection := errors.NewErrorCollection()

	if req.Name == "" {
		err := errors.New(errors.ErrCodeEmptyInput, "'client_name' is empty")
		errorCollection.Add(err)
	}

	if req.Type == Public && req.Secret != "" {
		err := errors.New(errors.ErrCodeInvalidClientMetadata, "'client_secret' must not be provided for public clients")
		errorCollection.Add(err)
	}

	if req.TokenEndpointAuthMethod != "" && !slices.Contains(req.GrantTypes, ClientCredentials) {
		err := errors.New(errors.ErrCodeInvalidClientMetadata, "'token_endpoint_auth' is required for 'client_credentials' grant")
		errorCollection.Add(err)
	}

	validateClientType(req, errorCollection)
	validateGrantType(req, errorCollection)
	validateURIS(req, errorCollection)
	validateScopes(req, errorCollection)
	validateResponseTypes(req, errorCollection)

	if errorCollection.HasErrors() {
		return errorCollection
	}

	return nil
}

func ValidateClientUpdateRequest(req *ClientUpdateRequest) error {
	errorCollection := errors.NewErrorCollection()

	validateGrantType(req, errorCollection)
	validateURIS(req, errorCollection)
	validateScopes(req, errorCollection)
	validateResponseTypes(req, errorCollection)

	if errorCollection.HasErrors() {
		return errorCollection
	}

	return nil
}

// validateClientType ensures the client type is either Confidential or Public.
func validateClientType(req ClientRequest, errorCollection *errors.ErrorCollection) {
	if req.GetType() != Confidential && req.GetType() != Public {
		err := errors.New(errors.ErrCodeInvalidClient, "client must be 'public' or 'confidential'")
		errorCollection.Add(err)
	}
}

// validateGrantType checks if the provided grant types are valid.
func validateGrantType(req ClientRequest, errorCollection *errors.ErrorCollection) {
	if len(req.GetGrantTypes()) == 0 {
		err := errors.New(errors.ErrCodeEmptyInput, "'grant_types' is empty")
		errorCollection.Add(err)
		return
	}

	validGrantTypes := ValidGrantTypes
	for _, grantType := range req.GetGrantTypes() {
		if _, ok := validGrantTypes[grantType]; !ok {
			err := errors.New(
				errors.ErrCodeInvalidClientMetadata,
				fmt.Sprintf("grant type '%s' is not supported", grantType))
			errorCollection.Add(err)
			continue
		}
		if req.GetType() == Public {
			if grantType == ClientCredentials || grantType == PasswordGrant {
				err := errors.New(
					errors.ErrCodeInvalidClientMetadata,
					fmt.Sprintf("grant type '%s' is not supported for public clients", grantType))
				errorCollection.Add(err)
			}
		}
		if grantType == RefreshToken && len(req.GetGrantTypes()) == 0 {
			err := errors.New(errors.ErrCodeInvalidClientMetadata, fmt.Sprintf("'%s' requires another grant type", grantType))
			errorCollection.Add(err)
		}
	}
}

// validateURIS checks if redirect URIs are well-formed and secure.
func validateURIS(req ClientRequest, errorCollection *errors.ErrorCollection) {
	if len(req.GetRedirectURIS()) == 0 {
		err := errors.New(errors.ErrCodeEmptyInput, "'redirect_uris' is empty")
		errorCollection.Add(err)
		return
	}

	if req.GetJwksURI() != "" {
		if _, err := url.ParseRequestURI(req.GetJwksURI()); err != nil {
			err = errors.New(errors.ErrCodeInvalidClientMetadata, "invalid jwks_uri format")
			errorCollection.Add(err)
		}
	}
	if req.GetLogoURI() != "" {
		if _, err := url.ParseRequestURI(req.GetLogoURI()); err != nil {
			err = errors.New(errors.ErrCodeInvalidClientMetadata, "invalid logo_uri format")
			errorCollection.Add(err)
		}
	}

	mobileSchemePattern := regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9+.-]*:\/\/`)
	for _, uri := range req.GetRedirectURIS() {
		if uri == "" {
			err := errors.New(errors.ErrCodeInvalidRedirectURI, "'redirect_uri' is empty")
			errorCollection.Add(err)
			continue
		}
		if strings.HasPrefix(uri, "http://localhost") || strings.HasPrefix(uri, "http://127.0.0.1") {
			continue
		}
		if containsWildcard(uri) {
			err := errors.New(errors.ErrCodeInvalidRedirectURI, "redirect URIs cannot have wildcards")
			errorCollection.Add(err)
			continue
		}

		parsedURI, err := url.Parse(uri)
		if err != nil {
			err := errors.New(errors.ErrCodeInvalidRedirectURI, fmt.Sprintf("malformed redirect URI: %s", uri))
			errorCollection.Add(err)
			continue
		}

		switch req.GetType() {
		case Confidential:
			if parsedURI.Scheme != "https" {
				err := errors.New(errors.ErrCodeInvalidRedirectURI, "confidential clients must use HTTPS")
				errorCollection.Add(err)
			}
			if net.ParseIP(parsedURI.Hostname()) != nil && !isLoopbackIP(parsedURI.Hostname()) {
				err := errors.New(errors.ErrCodeInvalidRedirectURI, "IP address not allowed as redirect URI hosts")
				errorCollection.Add(err)
			}
			if parsedURI.Fragment != "" {
				err := errors.New(errors.ErrCodeInvalidRedirectURI, "fragment component not allowed")
				errorCollection.Add(err)
			}

		case Public:
			isMobileScheme := mobileSchemePattern.MatchString(uri) && parsedURI.Scheme != "http" && parsedURI.Scheme != "https"
			if isMobileScheme {
				if len(parsedURI.Scheme) < 4 {
					err := errors.New(errors.ErrCodeInvalidRedirectURI, "mobile URI scheme is too short")
					errorCollection.Add(err)
				}
			} else if parsedURI.Scheme != "https" {
				err := errors.New(errors.ErrCodeInvalidRedirectURI, "public clients must use HTTPS")
				errorCollection.Add(err)
			}
		}
	}
}

// validateScopes ensures all provided scopes are valid.
func validateScopes(req ClientRequest, errorCollection *errors.ErrorCollection) {
	if len(req.GetScopes()) == 0 {
		req.SetScopes([]string{ClientRead})
		return
	}

	for _, scope := range req.GetScopes() {
		if _, ok := ValidScopes[scope]; !ok {
			err := errors.New(errors.ErrCodeInsufficientScope, fmt.Sprintf("scope '%s' is not supported", scope))
			errorCollection.Add(err)
		}
	}
}

// validateResponseTypes ensures all provided response types are valid and compatible with grant types.
func validateResponseTypes(req ClientRequest, errorCollection *errors.ErrorCollection) {
	if len(req.GetResponseTypes()) == 0 {
		err := errors.New(errors.ErrCodeEmptyInput, "'response_types' is empty")
		errorCollection.Add(err)
		return
	}

	for _, responseType := range req.GetResponseTypes() {
		if _, ok := ValidResponseTypes[responseType]; !ok {
			err := errors.New(
				errors.ErrCodeInvalidResponseType,
				fmt.Sprintf("response type '%s' is not supported", responseType))
			errorCollection.Add(err)
			continue
		}
	}

	// Validate compatibility with grant types
	authCodeOrDeviceCode := contains(req.GetGrantTypes(), AuthorizationCode) || contains(req.GetGrantTypes(), DeviceCode)
	implicitFlow := contains(req.GetGrantTypes(), ImplicitFlow)
	clientCredsOrPasswordOrRefresh := contains(req.GetGrantTypes(), ClientCredentials) || contains(req.GetGrantTypes(), PasswordGrant) || contains(req.GetGrantTypes(), RefreshToken)
	pkce := contains(req.GetGrantTypes(), PKCE)
	idToken := contains(req.GetResponseTypes(), IDTokenResponseType)
	code := contains(req.GetResponseTypes(), CodeResponseType)
	token := contains(req.GetResponseTypes(), TokenResponseType)

	if authCodeOrDeviceCode && !code {
		err := errors.New(
			errors.ErrCodeInvalidResponseType,
			"code response type is required for the authorization code or device code grant type")
		errorCollection.Add(err)
	}

	if implicitFlow && !token {
		err := errors.New(
			errors.ErrCodeInvalidResponseType,
			"token response type is required for the implicit flow grant type")
		errorCollection.Add(err)
	}

	if clientCredsOrPasswordOrRefresh && len(req.GetResponseTypes()) > 0 {
		err := errors.New(
			errors.ErrCodeInvalidResponseType,
			"response types are not allowed for the client credentials, password grant, or refresh token grant types")
		errorCollection.Add(err)
	}

	if pkce && !code {
		err := errors.New(
			errors.ErrCodeInvalidResponseType,
			"code response type is required when PKCE is being used")
		errorCollection.Add(err)
	}

	if idToken && !(authCodeOrDeviceCode || implicitFlow) {
		err := errors.New(
			errors.ErrCodeInvalidResponseType,
			"ID token response type is only allowed with the authorization code, device code or implicit flow grant types")
		errorCollection.Add(err)
	}
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
