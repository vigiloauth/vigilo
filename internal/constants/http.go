package constants

// HTTP Header Keys define common HTTP headers used in the application.
const (
	AuthorizationHeader       string = "Authorization"                     // Header for authorization credentials
	BasicAuthHeader           string = "Basic "                            // Prefix for Basic Authentication
	BearerAuthHeader          string = "Bearer "                           // Prefix for Bearer Authentication
	CacheControlHeader        string = "Cache-Control"                     // Header for cache control directives
	RequestIDHeader           string = "X-Request-ID"                      // Header for tracking unique request IDs
	SessionTokenHeader        string = "vigilo-auth-session-token"         // Header for Vigilo session tokens
	XForwardedHeader          string = "X-Forwarded-For"                   // Header for identifying the originating IP address
	NoStoreHeader             string = "no-store"                          // Cache directive to prevent storing responses
	ContentTypeJSON           string = "application/json"                  // Content-Type for JSON data
	ContentTypeFormURLEncoded string = "application/x-www-form-urlencoded" // Content-Type for form data
	AccessTokenPost           string = "access_token"
)

// URL Values define common URL parameter keys and values used in the application.
const (
	CodeURLValue                    string = "code"                      // URL parameter for authorization codes
	ClientCredentialsURLValue       string = "client_credentials"        // URL parameter for client credentials grant
	RefreshTokenURLValue            string = "refresh_token"             // URL parameter for refresh tokens
	RegistrationAccessTokenURLValue string = "registration_access_token" // URL parameter for registration access tokens
	RedirectLocationURLValue        string = "Location"                  // URL parameter for redirect locations
	ConsentApprovedURLValue         string = "approved"                  // URL parameter for consent approval
)

// OAuth Request Fields define the keys used in OAuth 2.0 and OpenID Connect
// requests for exchanging tokens, authorizing clients, and other related operations.
const (
	ClientIDReqField            string = "client_id"             // Field for the client ID
	ClientSecretReqField        string = "client_secret"         // Field for the client secret
	CodeChallengeReqField       string = "code_challenge"        // Field for the PKCE code challenge
	NonceReqField               string = "nonce"                 // Field for the nonce
	CodeChallengeMethodReqField string = "code_challenge_method" // Field for the PKCE code challenge method
	CodeVerifierReqField        string = "code_verifier"         // Field for the PKCE code verifier
	GrantTypeReqField           string = "grant_type"            // Field for the grant type
	RedirectURIReqField         string = "redirect_uri"          // Field for the redirect URI
	ResponseTypeReqField        string = "response_type"         // Field for the response type
	ScopeReqField               string = "scope"                 // Field for the requested scopes
	StateReqField               string = "state"                 // Field for the state parameter
	TokenReqField               string = "token"                 // Field for the token
	UsernameReqField            string = "username"              // Field for the username (used in password grant)
	PasswordReqField            string = "password"              // Field for the password (used in password grant)
)
