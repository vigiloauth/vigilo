package constants

// HTTP Header Keys
const (
	AuthorizationHeader string = "Authorization"
	BasicAuthHeader     string = "Basic "
	BearerAuthHeader    string = "Bearer "
	CacheControlHeader  string = "Cache-Control"
	RequestIDHeader     string = "X-Request-ID"
	SessionTokenHeader  string = "vigilo-auth-session-token"
	XForwardedHeader    string = "X-Forwarded-For"
	NoStoreHeader       string = "no-store"
)

// URL Values
const (
	CodeURLValue                    string = "code"
	ClientCredentialsURLValue       string = "client_credentials"
	RefreshTokenURLValue            string = "refresh_token"
	RegistrationAccessTokenURLValue string = "registration_access_token"
	RedirectLocationURLValue        string = "Location"
	ConsentApprovedURLValue         string = "approved"
)
