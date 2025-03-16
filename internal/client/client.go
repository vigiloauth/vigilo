package client

import (
	"net"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/vigiloauth/vigilo/internal/errors"
)

type Client struct {
	Name                    string
	ID                      string
	Secret                  string
	Type                    ClientType
	RedirectURIS            []string
	GrantTypes              []GrantType
	Scopes                  []Scope
	CreatedAt               time.Time
	UpdatedAt               time.Time
	TokenEndpointAuthMethod string
}

type ClientRegistrationRequest struct {
	Name                    string      `json:"client_name"`
	RedirectURIS            []string    `json:"redirect_uris"`
	Secret                  string      `json:"client_secret,omitempty"`
	Type                    ClientType  `json:"client_type"`
	GrantTypes              []GrantType `json:"grant_types"`
	Scopes                  []Scope     `json:"scopes,omitempty"`
	TokenEndpointAuthMethod string      `json:"token_endpoint_auth_method,omitempty"`
}

type ClientRegistrationResponse struct {
	ID                      string      `json:"client_id"`
	Type                    ClientType  `json:"client_type"`
	Secret                  string      `json:"client_secret,omitempty"`
	RedirectURIS            []string    `json:"redirect_uris"`
	GrantTypes              []GrantType `json:"grant_types"`
	Scopes                  []Scope     `json:"scopes,omitempty"`
	CreatedAt               time.Time   `json:"created_at"`
	UpdatedAt               time.Time   `json:"updated_at"`
	TokenEndpointAuthMethod string      `json:"token_endpoint_auth_method,omitempty"`
}

type ClientType string
type GrantType string
type Scope string

const (
	Confidential ClientType = "confidential"
	Public       ClientType = "public"

	AuthorizationCode GrantType = "authorization_code"
	PKCE              GrantType = "pkce"
	ClientCredentials GrantType = "client_credentials"
	DeviceCode        GrantType = "device_code"
	RefreshToken      GrantType = "refresh_token"
	ImplicitFlow      GrantType = "implicit_flow"
	PasswordGrant     GrantType = "password_grant"

	Read  Scope = "read"
	Write Scope = "write"
)

func (ct ClientType) String() string { return string(ct) }
func (gt GrantType) String() string  { return string(gt) }
func (s Scope) String() string       { return string(s) }

func (req *ClientRegistrationRequest) Validate() error {
	errorCollection := errors.NewErrorCollection()

	if req.Name == "" {
		errorCollection.Add(errors.NewEmptyInputError("client_name"))
	}

	if req.Type == Public && req.Secret != "" {
		errorCollection.Add(errors.NewClientSecretError())
	}

	req.validateClientType(errorCollection)
	req.validateGrantType(errorCollection)
	req.validateRedirectURIS(errorCollection)
	req.validateScopes(errorCollection)

	if errorCollection.HasErrors() {
		return errorCollection
	}

	return nil
}

func (req *ClientRegistrationRequest) validateClientType(errorCollection *errors.ErrorCollection) {
	if req.Type != Confidential && req.Type != Public {
		errorCollection.Add(errors.NewInvalidClientTypeError())
		return
	}
}

func (req *ClientRegistrationRequest) validateGrantType(errorCollection *errors.ErrorCollection) {
	if len(req.GrantTypes) == 0 {
		errorCollection.Add(errors.NewEmptyInputError("grant_types"))
		return
	}

	validGrantTypes := getValidGrantTypes()
	for _, grantType := range req.GrantTypes {
		if _, ok := validGrantTypes[grantType]; !ok {
			errorCollection.Add(errors.NewInvalidGrantTypeError(grantType.String()))
			continue
		}

		if req.Type == Public {
			if grantType == ClientCredentials || grantType == PasswordGrant {
				errorCollection.Add(errors.NewInvalidGrantTypeError(grantType.String()))
			}
		}

		if grantType == RefreshToken && len(req.GrantTypes) == 0 {
			errorCollection.Add(errors.NewInvalidGrantCombinationError(grantType.String()))
		}
	}
}

func (req *ClientRegistrationRequest) validateRedirectURIS(errorCollection *errors.ErrorCollection) {
	if len(req.RedirectURIS) == 0 {
		errorCollection.Add(errors.NewEmptyInputError("redirect_uris"))
		return
	}

	mobileSchemePattern := regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9+.-]*:\/\/`)
	for _, uri := range req.RedirectURIS {
		if uri == "" {
			errorCollection.Add(errors.NewInvalidRedirectURIError("URI cannot be empty"))
			continue
		}
		if strings.HasPrefix(uri, "http://localhost") || strings.HasPrefix(uri, "http://127.0.0.1") {
			continue
		}

		parsedURI, err := url.Parse(uri)
		if err != nil {
			errorCollection.Add(errors.NewInvalidRedirectURIError("Malformed URI: " + uri))
			continue
		}

		switch req.Type {
		case Confidential:
			if parsedURI.Scheme != "https" {
				errorCollection.Add(errors.NewInvalidRedirectURIError("Confidential clients must use HTTPS: " + uri))
			}
			if net.ParseIP(parsedURI.Hostname()) != nil && !isLoopbackIP(parsedURI.Hostname()) {
				errorCollection.Add(errors.NewInvalidRedirectURIError("IP addresses not allowed as redirect URI hosts: " + uri))
			}
			if parsedURI.Fragment != "" {
				errorCollection.Add(errors.NewInvalidRedirectURIError("Fragment component not allowed: " + uri))
			}

		case Public:
			isMobileScheme := mobileSchemePattern.MatchString(uri) && parsedURI.Scheme != "http" && parsedURI.Scheme != "https"
			if isMobileScheme {
				if len(parsedURI.Scheme) < 4 {
					errorCollection.Add(errors.NewInvalidRedirectURIError("Mobile URI scheme too short: " + uri))
				}
			} else if parsedURI.Scheme != "https" {
				errorCollection.Add(errors.NewInvalidRedirectURIError("Public web clients must use HTTPS: " + uri))
			}
		}
	}
}

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
			errorCollection.Add(errors.NewInvalidScopeError(scope.String()))
			continue
		}
	}
}

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

func isLoopbackIP(host string) bool {
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	return ip.IsLoopback()
}
