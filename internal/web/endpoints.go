package web

const (
	defaultAuthEndpoint   string = "/auth"
	defaultClientEndpoint string = "/client"
	defaultOAuthEndpoint  string = "/oauth2"
	defaultTokenEndpoint  string = "/token"
	defaultAdminEndpoint  string = "/admin"
	wellKnown             string = "/.well-known"
)

var UserEndpoints = struct {
	Registration  string
	Login         string
	Logout        string
	ResetPassword string
	Verify        string
}{
	Registration:  defaultAuthEndpoint + "/signup",
	Login:         defaultAuthEndpoint + "/login",
	Logout:        defaultAuthEndpoint + "/logout",
	ResetPassword: defaultAuthEndpoint + "/reset-password/confirm",
	Verify:        defaultAuthEndpoint + "/verify",
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
	Token           string
	Authorize       string
	Login           string
	UserConsent     string
	TokenExchange   string
	IntrospectToken string
	RevokeToken     string
}{
	Token:           defaultOAuthEndpoint + "/token",
	Authorize:       defaultOAuthEndpoint + "/authorize",
	Login:           defaultOAuthEndpoint + "/authenticate",
	UserConsent:     defaultOAuthEndpoint + "/consent",
	TokenExchange:   defaultOAuthEndpoint + "/token",
	IntrospectToken: defaultOAuthEndpoint + defaultTokenEndpoint + "/introspect",
	RevokeToken:     defaultOAuthEndpoint + defaultTokenEndpoint + "/revoke",
}

var AdminEndpoints = struct {
	GetAuditEvents string
}{
	GetAuditEvents: defaultAdminEndpoint + "/audit-events",
}

var OIDCEndpoints = struct {
	UserInfo  string
	JWKS      string
	Discovery string
}{
	UserInfo:  defaultOAuthEndpoint + "/userinfo",
	JWKS:      defaultOAuthEndpoint + wellKnown + "/jwks.json",
	Discovery: defaultOAuthEndpoint + wellKnown + "/openid-configuration",
}
