package types

// TokenAuthMethod represents supported OAuth 2.0 token endpoint authentication methods.
// These values are typically used in the client authentication process when obtaining an access token.
type TokenAuthMethod string

const (
	// NoTokenAuth indicates that no client authentication is used at the token endpoint.
	NoTokenAuth TokenAuthMethod = "none"

	// ClientSecretPostTokenAuth indicates client authentication using HTTP POST parameters (client_id and client_secret in the body).
	ClientSecretPostTokenAuth TokenAuthMethod = "client_secret_post"

	// ClientSecretBasicTokenAuth indicates client authentication using HTTP Basic Authentication (client_id and client_secret in the Authorization header).
	ClientSecretBasicTokenAuth TokenAuthMethod = "client_secret_basic"
)

// SupportedTokenEndpointAuthMethods defines the set of supported and recognized token endpoint authentication methods.
// This can be used for validating incoming configuration or requests.
var SupportedTokenEndpointAuthMethods = map[TokenAuthMethod]bool{
	NoTokenAuth:                true,
	ClientSecretBasicTokenAuth: true,
	ClientSecretPostTokenAuth:  true,
}

func (t TokenAuthMethod) String() string {
	return string(t)
}
