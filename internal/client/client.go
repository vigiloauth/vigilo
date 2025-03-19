package client

import (
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strings"
	"time"

	"slices"

	"github.com/vigiloauth/vigilo/internal/errors"
)

// Client represents an OAuth client with its attributes and authentication details.
type Client struct {
	Name                    string
	ID                      string
	Secret                  string
	Type                    ClientType
	RedirectURIS            []string
	GrantTypes              []GrantType
	Scopes                  []Scope
	ResponseTypes           []ResponseType
	CreatedAt               time.Time
	UpdatedAt               time.Time
	TokenEndpointAuthMethod string
}

// ClientRegistrationRequest represents a request to register a new OAuth client.
type ClientRegistrationRequest struct {
	Name                    string         `json:"client_name"`
	RedirectURIS            []string       `json:"redirect_uris"`
	Type                    ClientType     `json:"client_type"`
	Secret                  string         `json:"client_secret,omitempty"`
	GrantTypes              []GrantType    `json:"grant_types"`
	Scopes                  []Scope        `json:"scopes,omitempty"`
	ResponseTypes           []ResponseType `json:"response_types"`
	TokenEndpointAuthMethod string         `json:"token_endpoint_auth_method,omitempty"`
}

// ClientRegistrationResponse represents a response after registering an OAuth client.
type ClientRegistrationResponse struct {
	ID                      string         `json:"client_id"`
	Name                    string         `json:"client_name"`
	Secret                  string         `json:"client_secret,omitempty"`
	Type                    ClientType     `json:"client_type"`
	RedirectURIS            []string       `json:"redirect_uris"`
	GrantTypes              []GrantType    `json:"grant_types"`
	Scopes                  []Scope        `json:"scopes,omitempty"`
	ResponseTypes           []ResponseType `json:"response_types"`
	CreatedAt               time.Time      `json:"created_at"`
	UpdatedAt               time.Time      `json:"updated_at"`
	TokenEndpointAuthMethod string         `json:"token_endpoint_auth_method,omitempty"`
}

// ClientSecretRegenerateResponse represents the response when regenerating a client secret.
type ClientSecretRegenerateResponse struct {
	ClientID     string    `json:"client_id"`
	ClientSecret string    `json:"client_secret"`
	UpdatedAt    time.Time `json:"updated_at"`
}

// ClientType represents the type of an OAuth client.
type ClientType string

// GrantType represents different types of OAuth grant mechanisms.
type GrantType string

// Scope represents the authorization scopes available to an OAuth client.
type Scope string

// ResponseType represents the response types available to an OAuth client.
type ResponseType string

const (
	// Predefined grant types.
	AuthorizationCode GrantType = "authorization_code"
	PKCE              GrantType = "pkce"
	ClientCredentials GrantType = "client_credentials"
	DeviceCode        GrantType = "device_code"
	RefreshToken      GrantType = "refresh_token"
	ImplicitFlow      GrantType = "implicit_flow"
	PasswordGrant     GrantType = "password_grant"

	// Predefined scopes.
	Read  Scope = "read"
	Write Scope = "write"

	// Predefined client types.
	Confidential ClientType = "confidential"
	Public       ClientType = "public"

	// Predefined response types.
	CodeResponseType    ResponseType = "code"
	TokenResponseType   ResponseType = "token"
	IDTokenResponseType ResponseType = "id_token"
)

// String converts a ClientType to its string representation.
func (ct ClientType) String() string { return string(ct) }

// String converts a GrantType to its string representation.
func (gt GrantType) String() string { return string(gt) }

// String converts a Scope to its string representation.
func (s Scope) String() string { return string(s) }

// String converts a ResponseType to its string representation.
func (r ResponseType) String() string { return string(r) }

// Validate checks if the ClientRegistrationRequest contains valid values.
func (req *ClientRegistrationRequest) Validate() error {
	errorCollection := errors.NewErrorCollection()

	if req.Name == "" {
		err := errors.New(errors.ErrCodeEmptyInput, "`client_name` is empty")
		errorCollection.Add(err)
	}

	if req.Type == Public && req.Secret != "" {
		err := errors.New(errors.ErrCodeClientSecretNotAllowed, "`client_secret` must not be provided")
		errorCollection.Add(err)
	}

	if req.TokenEndpointAuthMethod != "" && !slices.Contains(req.GrantTypes, ClientCredentials) {
		err := errors.New(errors.ErrCodeInvalidGrantType, "`token_endpoint_auth` is required for `client_credentials` grant")
		errorCollection.Add(err)
	}

	req.validateClientType(errorCollection)
	req.validateGrantType(errorCollection)
	req.validateRedirectURIS(errorCollection)
	req.validateScopes(errorCollection)
	req.validateResponseTypes(errorCollection)

	if errorCollection.HasErrors() {
		return errorCollection
	}

	return nil
}

// validateClientType ensures the client type is either Confidential or Public.
func (req *ClientRegistrationRequest) validateClientType(errorCollection *errors.ErrorCollection) {
	if req.Type != Confidential && req.Type != Public {
		err := errors.New(errors.ErrCodeInvalidClient, "client must be `public` or `confidential`")
		errorCollection.Add(err)
	}
}

// validateGrantType checks if the provided grant types are valid.
func (req *ClientRegistrationRequest) validateGrantType(errorCollection *errors.ErrorCollection) {
	if len(req.GrantTypes) == 0 {
		err := errors.New(errors.ErrCodeEmptyInput, "`grant_types` is empty")
		errorCollection.Add(err)
		return
	}

	validGrantTypes := getValidGrantTypes()
	for _, grantType := range req.GrantTypes {
		if _, ok := validGrantTypes[grantType]; !ok {
			err := errors.New(
				errors.ErrCodeInvalidGrantType,
				fmt.Sprintf("grant type `%s` is not supported", grantType.String()))
			errorCollection.Add(err)
			continue
		}
		if req.Type == Public {
			if grantType == ClientCredentials || grantType == PasswordGrant {
				err := errors.New(
					errors.ErrCodeInvalidGrantType,
					fmt.Sprintf("grant type `%s` is not supported for public clients", grantType.String()))
				errorCollection.Add(err)
			}
		}
		if grantType == RefreshToken && len(req.GrantTypes) == 0 {
			err := errors.New(errors.ErrCodeInvalidGrantType, fmt.Sprintf("`%s` requires another grant type", grantType.String()))
			errorCollection.Add(err)
		}
	}
}

// validateRedirectURIS checks if redirect URIs are well-formed and secure.
func (req *ClientRegistrationRequest) validateRedirectURIS(errorCollection *errors.ErrorCollection) {
	if len(req.RedirectURIS) == 0 {
		err := errors.New(errors.ErrCodeEmptyInput, "`redirect_uris` is empty")
		errorCollection.Add(err)
		return
	}

	mobileSchemePattern := regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9+.-]*:\/\/`)
	for _, uri := range req.RedirectURIS {
		if uri == "" {
			err := errors.New(errors.ErrCodeInvalidRedirectURI, "`redirect_uri` is empty")
			errorCollection.Add(err)
			continue
		}
		if strings.HasPrefix(uri, "http://localhost") || strings.HasPrefix(uri, "http://127.0.0.1") {
			continue
		}

		parsedURI, err := url.Parse(uri)
		if err != nil {
			err := errors.New(errors.ErrCodeInvalidRedirectURI, fmt.Sprintf("malformed redirect URI: %s", uri))
			errorCollection.Add(err)
			continue
		}

		switch req.Type {
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
func (req *ClientRegistrationRequest) validateScopes(errorCollection *errors.ErrorCollection) {
	if len(req.Scopes) == 0 {
		return
	}

	validScopes := map[Scope]bool{
		Read:  true,
		Write: true,
	}

	for _, scope := range req.Scopes {
		if _, ok := validScopes[scope]; !ok {
			err := errors.New(errors.ErrCodeInvalidScope, fmt.Sprintf("scope `%s` is not supported", scope.String()))
			errorCollection.Add(err)
		}
	}
}

// validateResponseTypes ensures all provided response types are valid and compatible with grant types.
func (req *ClientRegistrationRequest) validateResponseTypes(errorCollection *errors.ErrorCollection) {
	if len(req.ResponseTypes) == 0 {
		err := errors.New(errors.ErrCodeEmptyInput, "`response_types` is empty")
		errorCollection.Add(err)
		return
	}

	validResponseTypes := map[ResponseType]bool{
		CodeResponseType:    true,
		TokenResponseType:   true,
		IDTokenResponseType: true,
	}

	for _, responseType := range req.ResponseTypes {
		if _, ok := validResponseTypes[responseType]; !ok {
			err := errors.New(
				errors.ErrCodeInvalidResponseType,
				fmt.Sprintf("response type `%s` is not supported", responseType.String()))
			errorCollection.Add(err)
			continue
		}
	}

	// Validate compatibility with grant types
	authCodeOrDeviceCode := contains(req.GrantTypes, AuthorizationCode) || contains(req.GrantTypes, DeviceCode)
	implicitFlow := contains(req.GrantTypes, ImplicitFlow)
	clientCredsOrPasswordOrRefresh := contains(req.GrantTypes, ClientCredentials) || contains(req.GrantTypes, PasswordGrant) || contains(req.GrantTypes, RefreshToken)
	pkce := contains(req.GrantTypes, PKCE)
	idToken := contains(req.ResponseTypes, IDTokenResponseType)
	code := contains(req.ResponseTypes, CodeResponseType)
	token := contains(req.ResponseTypes, TokenResponseType)

	if authCodeOrDeviceCode && !code {
		err := errors.New(
			errors.ErrCodeInvalidResponseType,
			"`code` response type is required for `authorization_code` or `device_code` grant type")
		errorCollection.Add(err)
	}

	if implicitFlow && !token {
		err := errors.New(
			errors.ErrCodeInvalidResponseType,
			"`token` response type is required for `implicit_flow` grant type")
		errorCollection.Add(err)
	}

	if clientCredsOrPasswordOrRefresh && len(req.ResponseTypes) > 0 {
		err := errors.New(
			errors.ErrCodeInvalidResponseType,
			"response types are not allowed for `client_credentials`, `password_grant`, or `refresh_token` grant types")
		errorCollection.Add(err)
	}

	if pkce && !code {
		err := errors.New(
			errors.ErrCodeInvalidResponseType,
			"`code` response type is required when PKCE is used")
		errorCollection.Add(err)
	}

	if idToken && !(authCodeOrDeviceCode || implicitFlow) {
		err := errors.New(
			errors.ErrCodeInvalidResponseType,
			"`id_token` response type is only allowed with `authorization_code`, `device_code` or `implicit_flow` grant types")
		errorCollection.Add(err)
	}
}

// contains checks if a slice contains a specific element.
func contains[T comparable](slice []T, element T) bool {
	return slices.Contains(slice, element)
}

// isLoopbackIP checks if the given IP is a loopback address.
func isLoopbackIP(host string) bool {
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// getValidGrantTypes returns a map of available grant types.
func getValidGrantTypes() map[GrantType]bool {
	return map[GrantType]bool{
		AuthorizationCode: true,
		PKCE:              true,
		ClientCredentials: true,
		DeviceCode:        true,
		RefreshToken:      true,
		ImplicitFlow:      true,
		PasswordGrant:     true,
	}
}
