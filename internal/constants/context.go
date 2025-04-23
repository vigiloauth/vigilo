package constants

type ContextKey string

const (
	ContextKeyIPAddress ContextKey = "ip_address"
	ContextKeyRequestID ContextKey = "requestID"
	ContextKeySessionID ContextKey = "session_id"
	ContextKeyUserAgent ContextKey = "user_agent"
	ContextKeyUserID    ContextKey = "user_id"
)
