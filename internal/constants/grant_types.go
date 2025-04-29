package constants

// Grant types define the methods by which a client can obtain an access token
// in the OAuth 2.0 and OpenID Connect protocols. These constants represent
// the supported grant types in the application.
const (
	AuthorizationCode string = "authorization_code" // Standard OAuth 2.0 Authorization Code Grant
	PKCE              string = "pkce"               // Proof Key for Code Exchange (PKCE) Grant
	ClientCredentials string = "client_credentials" // Client Credentials Grant
	DeviceCode        string = "device_code"        // Device Code Grant
	RefreshToken      string = "refresh_token"      // Refresh Token Grant
	ImplicitFlow      string = "implicit_flow"      // Implicit Flow (deprecated in OAuth 2.1)
	PasswordGrant     string = "password"           // Resource Owner Password Credentials Grant (deprecated)
)

// SupportedGrantTypes is a map of grant types supported by the application.
// The key is the grant type, and the value indicates whether it is supported.
var SupportedGrantTypes = map[string]bool{
	AuthorizationCode: true,
	PKCE:              true,
	ClientCredentials: true,
	DeviceCode:        true,
	RefreshToken:      true,
	ImplicitFlow:      true,
	PasswordGrant:     true,
}
