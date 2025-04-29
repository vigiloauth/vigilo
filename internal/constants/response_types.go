package constants

// Response Types define the types of responses that can be returned
// in OAuth 2.0 and OpenID Connect flows.
const (
	CodeResponseType    string = "code"     // Authorization Code response type
	TokenResponseType   string = "token"    // Implicit Flow token response type
	IDTokenResponseType string = "id_token" // ID Token response type for OpenID Connect
)

// SupportedResponseTypes is a map of response types supported by the application.
// The key is the response type, and the value indicates whether it is supported.
var SupportedResponseTypes = map[string]bool{
	CodeResponseType:    true,
	TokenResponseType:   true,
	IDTokenResponseType: true,
}
