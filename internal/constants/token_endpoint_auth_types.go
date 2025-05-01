package constants

const (
	NoTokenAuth                string = "none"
	ClientSecretPostTokenAuth  string = "client_secret_post"
	ClientSecretBasicTokenAuth string = "client_secret_basic"
)

var ValidTokenEndpointAuthMethods = map[string]bool{
	NoTokenAuth:                true,
	ClientSecretBasicTokenAuth: true,
	ClientSecretPostTokenAuth:  true,
}
