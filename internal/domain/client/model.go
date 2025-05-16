package domain

import (
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/vigiloauth/vigilo/v2/internal/constants"
	domain "github.com/vigiloauth/vigilo/v2/internal/domain/jwks"
)

// Client represents an OAuth 2.0 client application.
// It stores the client's metadata and configuration.
type Client struct {
	Name                    string       // The human-readable name of the client application.
	ID                      string       // The unique identifier assigned to the client.
	Secret                  string       // The client secret used for confidential client authentication.
	Type                    string       // The type of the client: "confidential" or "public".
	TokenEndpointAuthMethod string       // The authentication method used by the client at the token endpoint (e.g., "client_secret_basic", "client_secret_post", "private_key_jwt").
	JwksURI                 string       // The URL of the client's JSON Web Key Set (JWKS) document for verifying signatures.
	LogoURI                 string       // The URL of the client's logo.
	PolicyURI               string       // The URL of the client's privacy policy.
	SectorIdentifierURI     string       // The URL of the client's containing their redirect URI
	ApplicationType         string       // The type of the application (e.g., "web", "native").
	RegistrationAccessToken string       // The access token used to read and update the client's registration information.
	RedirectURIS            []string     // A list of allowed redirect URIs for the client.
	GrantTypes              []string     // A list of OAuth 2.0 grant types the client is authorized to use.
	Scopes                  []string     // A list of authorization scopes the client can request.
	ResponseTypes           []string     // A list of OAuth 2.0 response types the client is authorized to use.
	Contacts                []string     // A list of contact persons for the client.
	CreatedAt               time.Time    // The timestamp when the client was created.
	UpdatedAt               time.Time    // The timestamp when the client was last updated.
	IDIssuedAt              time.Time    // The timestamp when the client ID was issued.
	SecretExpiration        int          // The expiration time of the client secret in seconds (0 for no expiration).
	RequiresPKCE            bool         // Indicates if the client requires Proof Key for Code Exchange (PKCE) for the authorization code grant.
	JWKS                    *domain.Jwks // The client's JSON Web Key Set (JWKS) for verifying signatures, embedded directly.
	RegistrationClientURI   string       // The URL of the client's registration endpoint.

	// CanRequestScopes indicates if the client is restricted to its registered scopes during authorization.
	// If false, the client can request any valid scope.
	CanRequestScopes bool
}

type ClientReadResponse struct {
	ID                  string `json:"client_id,omitempty"`
	Name                string `json:"name,omitempty"`
	LogoURI             string `json:"logo_uri,omitempty"`
	PolicyURI           string `json:"policy_uri,omitempty"`
	SectorIdentifierURI string `json:"sector_identifier_uri,omitempty"`
}

type ClientRequest interface {
	GetType() string
	GetGrantTypes() []string
	GetRedirectURIS() []string
	GetScopes() []string
	GetResponseTypes() []string
	GetJwksURI() string
	GetLogoURI() string
	GetSectorIdentifierURI() string
	SetScopes(scopes []string)
	HasGrantType(grantType string) bool
}

// ClientRegistrationRequest represents a request to register a new OAuth client.
type ClientRegistrationRequest struct {
	Name                    string       `json:"client_name"`
	ApplicationType         string       `json:"application_type,omitempty"`
	RedirectURIS            []string     `json:"redirect_uris"`
	Scopes                  []string     `json:"scope,omitempty"`
	GrantTypes              []string     `json:"grant_types"`
	ResponseTypes           []string     `json:"response_types"`
	Contacts                []string     `json:"contacts,omitempty"`
	JwksURI                 string       `json:"jwks_uri,omitempty"`
	LogoURI                 string       `json:"logo_uri,omitempty"`
	PolicyURI               string       `json:"policy_uri,omitempty"`
	SectorIdentifierURI     string       `json:"sector_identifier_uri,omitempty"`
	TokenEndpointAuthMethod string       `json:"token_endpoint_auth_method,omitempty"`
	JWKS                    *domain.Jwks `json:"jwks,omitempty"`
	RequiresPKCE            bool
	Type                    string
}

// ClientUpdateRequest represents a request to update an existing OAuth client.
type ClientUpdateRequest struct {
	ID                      string `json:"client_id"`
	Type                    string
	Secret                  string   `json:"client_secret,omitempty"`
	Name                    string   `json:"client_name,omitempty"`
	ApplicationType         string   `json:"application_type,omitempty"`
	RedirectURIS            []string `json:"redirect_uris,omitempty"`
	GrantTypes              []string `json:"grant_types,omitempty"`
	Scopes                  []string `json:"scope,omitempty"`
	ResponseTypes           []string `json:"response_types,omitempty"`
	Contacts                []string `json:"contacts,omitempty"`
	JwksURI                 string   `json:"jwks_uri,omitempty"`
	LogoURI                 string   `json:"logo_uri,omitempty"`
	PolicyURI               string   `json:"policy_uri,omitempty"`
	SectorIdentifierURI     string   `json:"sector_identifier_uri,omitempty"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method,omitempty"`
}

// ClientRegistrationResponse represents a response after registering an OAuth client.
type ClientRegistrationResponse struct {
	ID                      string    `json:"client_id"`
	Name                    string    `json:"client_name"`
	Type                    string    `json:"client_type"`
	Secret                  string    `json:"client_secret,omitempty"`
	SecretExpiration        int       `json:"client_secret_expires_at,omitempty"`
	ApplicationType         string    `json:"application_type,omitempty"`
	RedirectURIS            []string  `json:"redirect_uris"`
	GrantTypes              []string  `json:"grant_types"`
	Scopes                  []string  `json:"scope"`
	ResponseTypes           []string  `json:"response_types"`
	Contacts                []string  `json:"contacts,omitempty"`
	CreatedAt               time.Time `json:"created_at"`
	UpdatedAt               time.Time `json:"updated_at"`
	JwksURI                 string    `json:"jwks_uri,omitempty"`
	LogoURI                 string    `json:"logo_uri,omitempty"`
	PolicyURI               string    `json:"policy_uri,omitempty"`
	SectorIdentifierURI     string    `json:"sector_identifier_uri,omitempty"`
	TokenEndpointAuthMethod string    `json:"token_endpoint_auth_method,omitempty"`
	RegistrationAccessToken string    `json:"registration_access_token"`
	RegistrationClientURI   string    `json:"registration_client_uri"`
	IDIssuedAt              time.Time `json:"client_id_issued_at"`
}

type ClientConfigurationEndpoint struct {
	Name                    string    `json:"client_name"`
	RedirectURIS            []string  `json:"redirect_uris"`
	GrantTypes              []string  `json:"grant_types"`
	Scopes                  []string  `json:"scope,omitempty"`
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
	ClientID               string `schema:"client_id"`
	ResponseType           string `schema:"response_type"`
	RedirectURI            string `schema:"redirect_uri"`
	Scope                  string `schema:"scope,omitempty"`
	State                  string `schema:"state,omitempty"`
	Nonce                  string `schema:"nonce,omitempty"`
	CodeChallenge          string `schema:"code_challenge,omitempty"`
	CodeChallengeMethod    string `schema:"code_challenge_method,omitempty"`
	Display                string `schema:"display,omitempty"`
	Prompt                 string `schema:"prompt,omitempty"`
	MaxAge                 string `schema:"max_age,omitempty"`
	UserID                 string
	ConsentApproved        bool
	Client                 *Client
	HTTPWriter             http.ResponseWriter
	HTTPRequest            *http.Request
	UserAuthenticationTime time.Time
}

type ClientInformationResponse struct {
	ID                      string `json:"client_id"`
	Secret                  string `json:"client_secret,omitempty"`
	RegistrationClientURI   string `json:"registration_client_uri"`
	RegistrationAccessToken string `json:"registration_access_token"`
}

func NewClientFromRegistrationRequest(req *ClientRegistrationRequest) *Client {
	client := &Client{
		Name:          req.Name,
		Type:          req.Type,
		RedirectURIS:  req.RedirectURIS,
		GrantTypes:    req.GrantTypes,
		ResponseTypes: req.ResponseTypes,
	}

	if req.ApplicationType != "" {
		client.ApplicationType = req.ApplicationType
	}

	if len(req.Scopes) != 0 {
		client.Scopes = req.Scopes
		client.CanRequestScopes = false
	} else {
		client.Scopes = []string{}
		client.CanRequestScopes = true
	}

	if len(req.Contacts) != 0 {
		client.Contacts = req.Contacts
	}
	if req.JwksURI != "" {
		client.JwksURI = req.JwksURI
	}
	if req.PolicyURI != "" {
		client.PolicyURI = req.PolicyURI
	}
	if req.SectorIdentifierURI != "" {
		client.SectorIdentifierURI = req.SectorIdentifierURI
	}
	if req.LogoURI != "" {
		client.LogoURI = req.LogoURI
	}
	if req.TokenEndpointAuthMethod != "" {
		client.TokenEndpointAuthMethod = req.TokenEndpointAuthMethod
	}
	if req.JWKS != nil {
		client.JWKS = req.JWKS
	}

	return client
}

func NewClientRegistrationResponseFromClient(client *Client) *ClientRegistrationResponse {
	response := &ClientRegistrationResponse{
		ID:                      client.ID,
		Name:                    client.Name,
		Type:                    client.Type,
		RedirectURIS:            client.RedirectURIS,
		GrantTypes:              client.RedirectURIS,
		Scopes:                  client.Scopes,
		ResponseTypes:           client.RedirectURIS,
		CreatedAt:               client.CreatedAt,
		UpdatedAt:               client.UpdatedAt,
		RegistrationAccessToken: client.RegistrationAccessToken,
		IDIssuedAt:              client.IDIssuedAt,
		RegistrationClientURI:   client.RegistrationClientURI,
	}

	if client.Secret != "" {
		response.Secret = client.Secret
		response.SecretExpiration = client.SecretExpiration
	}
	if client.ApplicationType != "" {
		response.ApplicationType = client.ApplicationType
	}
	if len(client.Contacts) != 0 {
		response.Contacts = client.Contacts
	}
	if client.JwksURI != "" {
		response.JwksURI = client.JwksURI
	}
	if client.TokenEndpointAuthMethod != "" {
		response.TokenEndpointAuthMethod = client.TokenEndpointAuthMethod
	}

	return response
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
	if request.PolicyURI != "" {
		c.PolicyURI = request.PolicyURI
	}
	if request.SectorIdentifierURI != "" {
		c.SectorIdentifierURI = request.SectorIdentifierURI
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

func (req *ClientRegistrationRequest) GetSectorIdentifierURI() string {
	return req.SectorIdentifierURI
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

func (req *ClientUpdateRequest) GetSectorIdentifierURI() string {
	return req.SectorIdentifierURI
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

func NewClientAuthorizationRequest(query url.Values) *ClientAuthorizationRequest {
	return &ClientAuthorizationRequest{
		ClientID:            query.Get(constants.ClientIDReqField),
		RedirectURI:         query.Get(constants.RedirectURIReqField),
		Scope:               query.Get(constants.ScopeReqField),
		State:               query.Get(constants.StateReqField),
		ResponseType:        query.Get(constants.ResponseTypeReqField),
		CodeChallenge:       query.Get(constants.CodeChallengeReqField),
		CodeChallengeMethod: query.Get(constants.CodeChallengeMethodReqField),
		Nonce:               query.Get(constants.NonceReqField),
		Display:             query.Get(constants.DisplayReqField),
		ConsentApproved:     query.Get(constants.ConsentApprovedURLValue) == "true",
		Prompt:              query.Get(constants.PromptReqField),
		MaxAge:              query.Get(constants.MaxAgeReqField),
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

// Predefined client types.
const (
	Confidential string = "confidential"
	Public       string = "public"
)

// Predefined code challenge methods.
const (
	Plain string = "plain"
	S256  string = "SHA-256"
)

var ValidCodeChallengeMethods = map[string]bool{
	Plain: true,
	S256:  true,
}

func (c *Client) String() string {
	secretStatus := "omitted"
	if c.Secret == "" {
		secretStatus = "none (not issued or known)"
	}

	regTokenStatus := "omitted"
	if c.RegistrationAccessToken == "" {
		regTokenStatus = "none"
	}

	redirectURIs := strings.Join(c.RedirectURIS, ", ")
	grantTypes := strings.Join(c.GrantTypes, ", ")
	scopes := strings.Join(c.Scopes, ", ")
	responseTypes := strings.Join(c.ResponseTypes, ", ")
	contacts := strings.Join(c.Contacts, ", ")

	jwksInfo := "none"
	if c.JWKS != nil && len(c.JWKS.Keys) > 0 {
		jwksInfo = fmt.Sprintf("present (%d keys)", len(c.JWKS.Keys))
	} else if c.JWKS != nil {
		jwksInfo = "present (0 keys)"
	}

	createdAtFormatted := c.CreatedAt.Format(time.RFC3339)
	updatedAtFormatted := c.UpdatedAt.Format(time.RFC3339)
	idIssuedAtFormatted := c.IDIssuedAt.Format(time.RFC3339)

	return fmt.Sprintf("Client{ID: %s, Name: %s, Type: %s, AppType: %s, AuthMethod: %s, Secret: %s, RegToken: %s, RequiresPKCE: %t, "+
		"RedirectURIs: [%s], GrantTypes: [%s], Scopes: [%s], ResponseTypes: [%s], Contacts: [%s], "+
		"JwksURI: %s, LogoURI: %s, JWKS: %s, RegistrationClientURI: %s, "+
		"CreatedAt: %s, UpdatedAt: %s, IDIssuedAt: %s, SecretExpiration: %d}",
		c.ID,
		c.Name,
		c.Type,
		c.ApplicationType,
		c.TokenEndpointAuthMethod,
		secretStatus,
		regTokenStatus,
		c.RequiresPKCE,
		redirectURIs,
		grantTypes,
		scopes,
		responseTypes,
		contacts,
		c.JwksURI,
		c.LogoURI,
		jwksInfo,
		c.RegistrationClientURI,
		createdAtFormatted,
		updatedAtFormatted,
		idIssuedAtFormatted,
		c.SecretExpiration,
	)
}
