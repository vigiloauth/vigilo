package constants

// Grant types define the methods by which a client can obtain an access token
// in the OAuth 2.0 and OpenID Connect protocols. These constants represent
// the supported grant types in the application.
const (
	AuthorizationCodeGrantType string = "authorization_code"                           // Standard OAuth 2.0 Authorization Code Grant
	ClientCredentialsGrantType string = "client_credentials"                           // Client Credentials Grant
	DeviceCodeGrantType        string = "urn:ietf:params:oauth:grant-type:device_code" // Device Code Grant
	RefreshTokenGrantType      string = "refresh_token"                                // Refresh Token Grant
	ImplicitGrantType          string = "implicit"                                     // Implicit Flow (deprecated in OAuth 2.1)
	PasswordGrantType          string = "password"                                     // Resource Owner Password Credentials Grant (deprecated)
)

// SupportedGrantTypes is a map of grant types supported by the application.
// The key is the grant type, and the value indicates whether it is supported.
var SupportedGrantTypes = map[string]bool{
	AuthorizationCodeGrantType: true,
	ClientCredentialsGrantType: true,
	DeviceCodeGrantType:        true,
	RefreshTokenGrantType:      true,
	ImplicitGrantType:          true,
	PasswordGrantType:          true,
}
