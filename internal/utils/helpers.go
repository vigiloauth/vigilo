package utils

import (
	"context"
	"net/url"

	"github.com/vigiloauth/vigilo/internal/constants"
)

// Helper function to truncate sensitive data for logging
func TruncateSensitive(data string) string {
	if len(data) > 5 {
		return data[:5] + "[REDACTED]"
	}
	return data
}

// Helper function to sanitize URLs for logging
func SanitizeURL(uri string) string {
	parsed, err := url.Parse(uri)
	if err != nil {
		return "[INVALID URL]"
	}
	parsed.RawQuery = "[REDACTED]"
	return parsed.String()
}

// GetRequestID retrieves the request ID from the context.
func GetRequestID(ctx context.Context) string {
	if requestID, ok := ctx.Value(constants.ContextKeyRequestID).(string); ok {
		return requestID
	}
	return ""
}

func GetValueFromContext(ctx context.Context, value constants.ContextKey) string {
	if value, ok := ctx.Value(value).(string); ok {
		return value
	}
	return ""
}

func AddKeyValueToContext(ctx context.Context, key constants.ContextKey, value string) context.Context {
	return context.WithValue(ctx, key, value)
}
