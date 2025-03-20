package utils

const (
	defaultAuthEndpoint   string = "/auth"
	defaultClientEndpoint string = "/clients"
	defaultOAuthEndpoint  string = "/oauth"
)

var UserEndpoints = struct {
	Registration         string
	Login                string
	Logout               string
	RequestPasswordReset string
	ResetPassword        string
}{
	Registration:         defaultAuthEndpoint + "/signup",
	Login:                defaultAuthEndpoint + "/login",
	Logout:               defaultAuthEndpoint + "/logout",
	RequestPasswordReset: defaultAuthEndpoint + "/reset-password",
	ResetPassword:        defaultAuthEndpoint + "/reset-password/confirm",
}

var ClientEndpoints = struct {
	Registration     string
	RegenerateSecret string
}{
	Registration:     defaultClientEndpoint,
	RegenerateSecret: defaultAuthEndpoint + "/{client_id}/regenerate-secret",
}

var AuthEndpoints = struct {
	GenerateToken string
}{
	GenerateToken: defaultOAuthEndpoint + "/token",
}
