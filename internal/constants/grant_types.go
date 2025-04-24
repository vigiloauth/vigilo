package constants

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
