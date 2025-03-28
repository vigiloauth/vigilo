package domain

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
	SecretExpiration        int
	Type                    string
	RedirectURIS            []string
	GrantTypes              []string
	Scopes                  []string
	ResponseTypes           []string
	CreatedAt               time.Time
	UpdatedAt               time.Time
	TokenEndpointAuthMethod string
}

// ClientRegistrationRequest represents a request to register a new OAuth client.
type ClientRegistrationRequest struct {
	Name                    string   `json:"client_name"`
	RedirectURIS            []string `json:"redirect_uris"`
	Type                    string   `json:"client_type"`
	Secret                  string   `json:"client_secret,omitempty"`
	GrantTypes              []string `json:"grant_types"`
	Scopes                  []string `json:"scopes,omitempty"`
	ResponseTypes           []string `json:"response_types"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method,omitempty"`
}

// ClientRegistrationResponse represents a response after registering an OAuth client.
type ClientRegistrationResponse struct {
	ID                      string    `json:"client_id"`
	Name                    string    `json:"client_name"`
	Secret                  string    `json:"client_secret,omitempty"`
	SecretExpiration        int       `json:"client_secret_expires_at,omitempty"`
	Type                    string    `json:"client_type"`
	RedirectURIS            []string  `json:"redirect_uris"`
	GrantTypes              []string  `json:"grant_types"`
	Scopes                  []string  `json:"scopes,omitempty"`
	ResponseTypes           []string  `json:"response_types"`
	CreatedAt               time.Time `json:"created_at"`
	UpdatedAt               time.Time `json:"updated_at"`
	TokenEndpointAuthMethod string    `json:"token_endpoint_auth_method,omitempty"`
	RegistrationAccessToken string    `json:"registration_access_token"`
	ConfigurationEndpoint   string    `json:"client_configuration_endpoint"`
	IDIssuedAt              time.Time `json:"client_id_issued_at"`
}

type ClientConfigurationEndpoint struct {
	Name                    string    `json:"client_name"`
	RedirectURIS            []string  `json:"redirect_uris"`
	GrantTypes              []string  `json:"grant_types"`
	Scopes                  []string  `json:"scopes,omitempty"`
	ResponseTypes           []string  `json:"response_types"`
	CreatedAt               time.Time `json:"created_at"`
	UpdatedAt               time.Time `json:"updated_at"`
	IDIssuedAt              time.Time `json:"client_id_issued_at"`
	TokenEndpointAuthMethod string    `json:"token_endpoint_auth_method,omitempty"`
	ConfigurationEndpoint   string    `json:"client_configuration_endpoint"`
}

// ClientSecretRegenerationResponse represents the response when regenerating a client secret.
type ClientSecretRegenerationResponse struct {
	ClientID     string    `json:"client_id"`
	ClientSecret string    `json:"client_secret"`
	UpdatedAt    time.Time `json:"updated_at"`
}

// ClientAuthorizationRequest represents the incoming request to the /authorize endpoint.
type ClientAuthorizationRequest struct {
	ResponseType        string `schema:"response_type"`
	ClientID            string `schema:"client_id"`
	RedirectURI         string `schema:"redirect_uri"`
	Scope               string `schema:"scope,omitempty"`
	State               string `schema:"state,omitempty"`
	CodeChallenge       string `schema:"code_challenge,omitempty"`
	CodeChallengeMethod string `schema:"code_challenge_method,omitempty"`
}

type ClientInformationResponse struct {
	ID                      string `json:"client_id"`
	Secret                  string `json:"client_secret,omitempty"`
	RegistrationClientURI   string `json:"registration_client_uri"`
	RegistrationAccessToken string `json:"registration_access_token"`
}

// Predefined grant types.
const (
	AuthorizationCode string = "authorization_code"
	PKCE              string = "pkce"
	ClientCredentials string = "client_credentials"
	DeviceCode        string = "device_code"
	RefreshToken      string = "refresh_token"
	ImplicitFlow      string = "implicit_flow"
	PasswordGrant     string = "password_grant"
)

// Predefined client types.
const (
	Confidential string = "confidential"
	Public       string = "public"
)

// Predefined response types.
const (
	CodeResponseType    string = "code"
	TokenResponseType   string = "token"
	IDTokenResponseType string = "id_token"
)

// Predefined Scopes.
const (
	// Client Management Scopes
	ClientRead   string = "client:read"   // Read registered client details.
	ClientWrite  string = "client:write"  // Modify client details (except 'client_id' & 'client_secret')
	ClientDelete string = "client:delete" // Delete a registered client.
	ClientManage string = "client:manage" // Full control over all clients (includes 'read', 'write', and 'delete')

	// User Management Scopes
	UserRead   string = "user:read"   // Read user details (e.g., profile, email, etc.).
	UserWrite  string = "user:write"  // Modify user details.
	UserDelete string = "user:delete" // Delete a user account.
	UserManage string = "user:manage" // Full control over users ('read', 'write'. and 'delete').
)

// HasGrantType checks to see if the client has the required grant type.
func (c *Client) HasGrantType(requiredGrantType string) bool {
	return slices.Contains(c.GrantTypes, requiredGrantType)
}

// HasRedirectURI checks to see if the client has the required redirectURI.
func (c *Client) HasRedirectURI(redirectURI string) bool {
	return slices.Contains(c.RedirectURIS, redirectURI)
}

// HasScope checks to see if the client has the required scope.
func (c *Client) HasScope(requiredScope string) bool {
	return slices.Contains(c.Scopes, requiredScope)
}

// IsConfidential checks to see if the client is public or confidential.
func (c *Client) IsConfidential() bool {
	return c.Type == Confidential
}

func (c *Client) SecretsMatch(secret string) bool {
	return c.Secret == secret
}

func NewClientInformationResponse(clientID, clientSecret, registrationClientURI, registrationAccessToken string) *ClientInformationResponse {
	clientInfo := &ClientInformationResponse{
		ID:                      clientID,
		RegistrationClientURI:   registrationAccessToken,
		RegistrationAccessToken: registrationAccessToken,
	}

	if clientSecret != "" {
		clientInfo.Secret = clientSecret
	}

	return clientInfo
}

// Validate checks if the ClientRegistrationRequest contains valid values.
func (req *ClientRegistrationRequest) Validate() error {
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
		err := errors.New(errors.ErrCodeInvalidClient, "client must be 'public' or 'confidential'")
		errorCollection.Add(err)
	}
}

// validateGrantType checks if the provided grant types are valid.
func (req *ClientRegistrationRequest) validateGrantType(errorCollection *errors.ErrorCollection) {
	if len(req.GrantTypes) == 0 {
		err := errors.New(errors.ErrCodeEmptyInput, "'grant_types' is empty")
		errorCollection.Add(err)
		return
	}

	validGrantTypes := getValidGrantTypes()
	for _, grantType := range req.GrantTypes {
		if _, ok := validGrantTypes[grantType]; !ok {
			err := errors.New(
				errors.ErrCodeInvalidClientMetadata,
				fmt.Sprintf("grant type '%s' is not supported", grantType))
			errorCollection.Add(err)
			continue
		}
		if req.Type == Public {
			if grantType == ClientCredentials || grantType == PasswordGrant {
				err := errors.New(
					errors.ErrCodeInvalidClientMetadata,
					fmt.Sprintf("grant type '%s' is not supported for public clients", grantType))
				errorCollection.Add(err)
			}
		}
		if grantType == RefreshToken && len(req.GrantTypes) == 0 {
			err := errors.New(errors.ErrCodeInvalidClientMetadata, fmt.Sprintf("'%s' requires another grant type", grantType))
			errorCollection.Add(err)
		}
	}
}

// validateRedirectURIS checks if redirect URIs are well-formed and secure.
func (req *ClientRegistrationRequest) validateRedirectURIS(errorCollection *errors.ErrorCollection) {
	if len(req.RedirectURIS) == 0 {
		err := errors.New(errors.ErrCodeEmptyInput, "'redirect_uris' is empty")
		errorCollection.Add(err)
		return
	}

	mobileSchemePattern := regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9+.-]*:\/\/`)
	for _, uri := range req.RedirectURIS {
		if uri == "" {
			err := errors.New(errors.ErrCodeInvalidRedirectURI, "'redirect_uri' is empty")
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

	validScopes := map[string]bool{
		ClientRead:   true,
		ClientWrite:  true,
		ClientManage: true,
		UserManage:   true,
		UserRead:     true,
		UserWrite:    true,
	}

	for _, scope := range req.Scopes {
		if _, ok := validScopes[scope]; !ok {
			err := errors.New(errors.ErrCodeInvalidScope, fmt.Sprintf("scope `%s` is not supported", scope))
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

	validResponseTypes := map[string]bool{
		CodeResponseType:    true,
		TokenResponseType:   true,
		IDTokenResponseType: true,
	}

	for _, responseType := range req.ResponseTypes {
		if _, ok := validResponseTypes[responseType]; !ok {
			err := errors.New(
				errors.ErrCodeInvalidResponseType,
				fmt.Sprintf("response type `%s` is not supported", responseType))
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
func getValidGrantTypes() map[string]bool {
	return map[string]bool{
		AuthorizationCode: true,
		PKCE:              true,
		ClientCredentials: true,
		DeviceCode:        true,
		RefreshToken:      true,
		ImplicitFlow:      true,
		PasswordGrant:     true,
	}
}
