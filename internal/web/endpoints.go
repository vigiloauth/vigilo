package web

const (
	defaultAuthEndpoint   string = "/auth"
	defaultClientEndpoint string = "/client"
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
	RegenerateSecret    string
	ClientConfiguration string
	Register            string
}{
	Register:            defaultClientEndpoint + "/register",
	RegenerateSecret:    defaultClientEndpoint + "/regenerate-secret",
	ClientConfiguration: defaultOAuthEndpoint + defaultClientEndpoint + "/register",
}

var OAuthEndpoints = struct {
	Token         string
	Authorize     string
	Login         string
	UserConsent   string
	TokenExchange string
	Introspect    string
}{
	Token:         defaultOAuthEndpoint + "/token",
	Authorize:     defaultOAuthEndpoint + "/authorize",
	Login:         defaultOAuthEndpoint + "/login/authorization",
	UserConsent:   defaultOAuthEndpoint + "/consent",
	TokenExchange: defaultOAuthEndpoint + "/token",
	Introspect:    defaultAuthEndpoint + "/introspect",
}
