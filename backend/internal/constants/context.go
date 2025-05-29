package constants

// ContextKey defines a type for keys used to store and retrieve values in a context.
// These keys are used throughout the application to pass and access request-specific data.
type ContextKey string

const (
	ContextKeyIPAddress   ContextKey = "ip_address"   // Key for storing the client's IP address in the context
	ContextKeyRequestID   ContextKey = "requestID"    // Key for storing the unique request ID in the context
	ContextKeySessionID   ContextKey = "session_id"   // Key for storing the session ID in the context
	ContextKeyUserAgent   ContextKey = "user_agent"   // Key for storing the client's user agent in the context
	ContextKeyUserID      ContextKey = "user_id"      // Key for storing the user ID in the context
	ContextKeyTokenClaims ContextKey = "token_claims" // Key for storing token claims in the context
	ContextKeyAccessToken ContextKey = "access_token" // Key for storing the access token in the context
)
