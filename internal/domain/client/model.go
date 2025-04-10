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
	GetJwksURI() string
	GetLogoURI() string
	SetScopes(scopes []string)
	HasGrantType(grantType string) bool
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
	ClientID            string `schema:"client_id"`
	ResponseType        string `schema:"response_type"`
	RedirectURI         string `schema:"redirect_uri"`
	Scope               string `schema:"scope,omitempty"`
	State               string `schema:"state,omitempty"`
	CodeChallenge       string `schema:"code_challenge,omitempty"`
	CodeChallengeMethod string `schema:"code_challenge_method,omitempty"`
	UserID              string
	Client              *Client
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

func (c *Client) RequiresPKCE() bool {
	return slices.Contains(c.GrantTypes, PKCE)
}

// HasRedirectURI checks to see if the client has the required redirectURI.
func (c *Client) HasRedirectURI(redirectURI string) bool {
	return slices.Contains(c.RedirectURIS, redirectURI)
}

// HasScope checks to see if the client has the required scope.
func (c *Client) HasScope(requiredScope string) bool {
	return slices.Contains(c.Scopes, requiredScope)
}

func (c *Client) HasResponseType(responseType string) bool {
	return slices.Contains(c.ResponseTypes, responseType)
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
	if request.LogoURI != "" {
		c.LogoURI = request.LogoURI
	}
	if request.JwksURI != "" {
		c.JwksURI = request.JwksURI
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

func (req *ClientRegistrationRequest) GetLogoURI() string {
	return req.LogoURI
}

func (req *ClientRegistrationRequest) GetJwksURI() string {
	return req.JwksURI
}

func (req *ClientRegistrationRequest) SetScopes(scopes []string) {
	req.Scopes = scopes
}

func (req *ClientRegistrationRequest) HasGrantType(grantType string) bool {
	return slices.Contains(req.GrantTypes, grantType)
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

func (req *ClientUpdateRequest) GetLogoURI() string {
	return req.LogoURI
}

func (req *ClientUpdateRequest) GetJwksURI() string {
	return req.JwksURI
}

func (req *ClientUpdateRequest) SetScopes(scopes []string) {
	req.Scopes = scopes
}

func (req *ClientUpdateRequest) HasGrantType(grantType string) bool {
	return slices.Contains(req.GrantTypes, grantType)
}

func NewClientInformationResponse(clientID, clientSecret, registrationClientURI, registrationAccessToken string) *ClientInformationResponse {
	clientInfo := &ClientInformationResponse{
		ID:                      clientID,
		RegistrationClientURI:   registrationClientURI,
		RegistrationAccessToken: registrationAccessToken,
	}

	if clientSecret != "" {
		clientInfo.Secret = clientSecret
	}

	return clientInfo
}

func NewClientAuthorizationRequest(clientID, redirectURI, scope, state, responseType, codeChallenge, codeChallengeMethod, userID string) *ClientAuthorizationRequest {
	return &ClientAuthorizationRequest{
		ClientID:            clientID,
		RedirectURI:         redirectURI,
		Scope:               scope,
		State:               state,
		ResponseType:        responseType,
		CodeChallenge:       codeChallenge,
		CodeChallengeMethod: codeChallengeMethod,
		UserID:              userID,
	}
}

// Validate checks if the ClientRegistrationRequest contains valid values.
func (req *ClientRegistrationRequest) Validate() error {
	return ValidateClientRegistrationRequest(req)
}

// Validate checks if the ClientUpdateRequest contains valid values.
func (req *ClientUpdateRequest) Validate() error {
	return ValidateClientUpdateRequest(req)
}

// Validate checks if the ClientAuthorizationRequest contains valid values.
func (req *ClientAuthorizationRequest) Validate() error {
	return ValidateClientAuthorizationRequest(req)
}

// Predefined grant types.
const (
	AuthorizationCode string = "authorization_code"
	PKCE              string = "pkce"
	ClientCredentials string = "client_credentials"
	DeviceCode        string = "device_code"
	RefreshToken      string = "refresh_token"
	ImplicitFlow      string = "implicit_flow"
	PasswordGrant     string = "password"
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

// Predefined scopes.
const (
	// Client Management Scopes
	ClientRead       string = "clients:read"   // Read registered client details.
	ClientWrite      string = "clients:write"  // Modify client details (except 'client_id' & 'client_secret')
	ClientDelete     string = "clients:delete" // Delete a registered client.
	ClientManage     string = "clients:manage" // Full control over all clients (includes 'read', 'write', and 'delete')
	ClientIntrospect string = "clients:introspect"

	// User Management Scopes
	UserRead   string = "users:read"   // Read user details (e.g., profile, email, etc.).
	UserWrite  string = "users:write"  // Modify user details.
	UserDelete string = "users:delete" // Delete a user account.
	UserManage string = "users:manage" // Full control over users ('read', 'write'. and 'delete').
)

var ValidScopes = map[string]bool{
	ClientRead:       true,
	ClientWrite:      true,
	ClientDelete:     true,
	ClientManage:     true,
	ClientIntrospect: true,

	UserManage: true,
	UserRead:   true,
	UserDelete: true,
	UserWrite:  true,
}

// Predefined code challenge methods.
const (
	Plain string = "plain"
	S256  string = "SHA-256"
)

var ValidCodeChallengeMethods = map[string]bool{
	Plain: true,
	S256:  true,
}
