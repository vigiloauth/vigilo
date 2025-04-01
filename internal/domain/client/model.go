package domain

import (
	"slices"
	"time"
)

// Client represents an OAuth client with its attributes and authentication details.
type Client struct {
	Name                    string
	ID                      string
	Secret                  string
	Type                    string
	TokenEndpointAuthMethod string
	JwksURI                 string
	LogoURI                 string
	RedirectURIS            []string
	GrantTypes              []string
	Scopes                  []string
	ResponseTypes           []string
	CreatedAt               time.Time
	UpdatedAt               time.Time
	SecretExpiration        int
}

type ClientRequest interface {
	GetType() string
	GetGrantTypes() []string
	GetRedirectURIS() []string
	GetScopes() []string
	GetResponseTypes() []string
	SetScopes(scopes []string)
}

// ClientRegistrationRequest represents a request to register a new OAuth client.
type ClientRegistrationRequest struct {
	Name                    string   `json:"client_name"`
	Type                    string   `json:"client_type"`
	Secret                  string   `json:"client_secret,omitempty"`
	RedirectURIS            []string `json:"redirect_uris"`
	GrantTypes              []string `json:"grant_types"`
	Scopes                  []string `json:"scopes,omitempty"`
	ResponseTypes           []string `json:"response_types"`
	JwksURI                 string   `json:"jwks_uri,omitempty"`
	LogoURI                 string   `json:"logo_uri,omitempty"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method,omitempty"`
}

// ClientUpdateRequest represents a request to update an existing OAuth client.
type ClientUpdateRequest struct {
	ID                      string `json:"client_id"`
	Type                    string
	Secret                  string   `json:"client_secret,omitempty"`
	Name                    string   `json:"client_name,omitempty"`
	RedirectURIS            []string `json:"redirect_uris,omitempty"`
	GrantTypes              []string `json:"grant_types,omitempty"`
	Scopes                  []string `json:"scopes,omitempty"`
	ResponseTypes           []string `json:"response_types,omitempty"`
	JwksURI                 string   `json:"jwks_uri,omitempty"`
	LogoURI                 string   `json:"logo_uri,omitempty"`
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
	Scopes                  []string  `json:"scopes"`
	ResponseTypes           []string  `json:"response_types"`
	CreatedAt               time.Time `json:"created_at"`
	UpdatedAt               time.Time `json:"updated_at"`
	JwksURI                 string    `json:"jwks_uri,omitempty"`
	LogoURI                 string    `json:"logo_uri,omitempty"`
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

func (c *Client) UpdateValues(request *ClientUpdateRequest) {
	if request.Name != "" {
		c.Name = request.Name
	}
	if len(request.RedirectURIS) > 0 {
		c.RedirectURIS = append(c.RedirectURIS, request.RedirectURIS...)
	}
	if len(request.GrantTypes) > 0 {
		c.GrantTypes = append(c.GrantTypes, request.GrantTypes...)
	}
	if len(request.Scopes) > 0 {
		c.Scopes = append(c.Scopes, request.Scopes...)
	}
	if len(request.ResponseTypes) > 0 {
		c.ResponseTypes = append(c.ResponseTypes, request.ResponseTypes...)
	}
	if request.TokenEndpointAuthMethod != "" {
		c.TokenEndpointAuthMethod = request.TokenEndpointAuthMethod
	}
	c.UpdatedAt = time.Now()
}

func (req *ClientRegistrationRequest) GetType() string {
	return req.Type
}

func (req *ClientRegistrationRequest) GetGrantTypes() []string {
	return req.GrantTypes
}

func (req *ClientRegistrationRequest) GetRedirectURIS() []string {
	return req.RedirectURIS
}

func (req *ClientRegistrationRequest) GetScopes() []string {
	return req.Scopes
}

func (req *ClientRegistrationRequest) GetResponseTypes() []string {
	return req.ResponseTypes
}

func (req *ClientRegistrationRequest) SetScopes(scopes []string) {
	req.Scopes = scopes
}

func (req *ClientUpdateRequest) GetType() string {
	return req.Type
}

func (req *ClientUpdateRequest) GetGrantTypes() []string {
	return req.GrantTypes
}

func (req *ClientUpdateRequest) GetRedirectURIS() []string {
	return req.RedirectURIS
}

func (req *ClientUpdateRequest) GetScopes() []string {
	return req.Scopes
}

func (req *ClientUpdateRequest) GetResponseTypes() []string {
	return req.ResponseTypes
}

func (req *ClientUpdateRequest) SetScopes(scopes []string) {
	req.Scopes = scopes
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
	return ValidateClientRegistrationRequest(req)
}

func (req *ClientUpdateRequest) Validate() error {
	return ValidateClientUpdateRequest(req)
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

var ValidGrantTypes = map[string]bool{
	AuthorizationCode: true,
	PKCE:              true,
	ClientCredentials: true,
	DeviceCode:        true,
	RefreshToken:      true,
	ImplicitFlow:      true,
	PasswordGrant:     true,
}

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

var ValidResponseTypes = map[string]bool{
	CodeResponseType:    true,
	TokenResponseType:   true,
	IDTokenResponseType: true,
}

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

var ValidScopes = map[string]bool{
	ClientRead:   true,
	ClientWrite:  true,
	ClientManage: true,
	UserManage:   true,
	UserRead:     true,
	UserWrite:    true,
}
