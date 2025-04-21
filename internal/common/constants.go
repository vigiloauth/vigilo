package common

const (
	ClientID                      string = "client_id"
	ClientSecret                  string = "client_secret"
	RedirectURI                   string = "redirect_uri"
	Scope                         string = "scope"
	State                         string = "state"
	XForwardedHeader              string = "X-Forwarded-For"
	Approved                      string = "approved"
	GrantType                     string = "grant_type"
	ClientCredentials             string = "client_credentials"
	BearerAuthHeader              string = "Bearer "
	Authorization                 string = "Authorization"
	SessionToken                  string = "vigilo-auth-session-token"
	ResponseType                  string = "response_type"
	AuthzCode                     string = "code"
	Location                      string = "Location"
	ClientRegistrationAccessToken string = "registration_access_token"
	CacheControl                  string = "Cache-Control"
	NoStore                       string = "no-store"
	RequestIDHeader               string = "X-Request-ID"
	CodeChallenge                 string = "code_challenge"
	CodeChallengeMethod           string = "code_challenge_method"
	Username                      string = "username"
	Password                      string = "password"
	CodeVerifier                  string = "code_verifier"
	RefreshToken                  string = "refresh_token"
	Token                         string = "token"
	BasicAuthHeader               string = "Basic "
	FromAddress                   string = "From"
	EmailSubject                  string = "Subject"
	Recipient                     string = "To"
	HTMLBody                      string = "text/html"
	VerifyEmailAddress            string = "Verify Your Email Address"
	AccountDeletion               string = "Your Account Has Been Deleted"

	ActionDetails string = "action"
	MethodDetails string = "method"

	TokenSecretKeyENV string = "TOKEN_SECRET_KEY"
	TokenIssuerENV    string = "TOKEN_ISSUER"

	SMTPFromAddressENV string = "SMTP_FROM_ADDRESS"
	SMTPUsernameENV    string = "SMTP_USERNAME"
	SMTPPasswordENV    string = "SMTP_PASSWORD"
)

type ContextKey string

const (
	ContextKeyUserID    ContextKey = "user_id"
	ContextKeyRequestID ContextKey = "requestID"
	ContextKeyIPAddress ContextKey = "ip_address"
	ContextKeyUserAgent ContextKey = "user_agent"
	ContextKeySessionID ContextKey = "session_id"
)
