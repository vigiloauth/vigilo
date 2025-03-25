package web

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
	Registration:     defaultAuthEndpoint + "/" + defaultClientEndpoint,
	RegenerateSecret: defaultAuthEndpoint + defaultClientEndpoint + "/{client_id}/regenerate-secret",
}

var OAuthEndpoints = struct {
	ClientCredentialsToken string
	Authorize              string
	Login                  string
	UserConsent            string
	TokenExchange          string
}{
	ClientCredentialsToken: defaultOAuthEndpoint + "/token",
	Authorize:              defaultOAuthEndpoint + "/authorize",
	Login:                  defaultOAuthEndpoint + "/login",
	UserConsent:            defaultOAuthEndpoint + "/consent",
	TokenExchange:          "/token",
}
