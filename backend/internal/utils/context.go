package utils

import (
	"context"

	"github.com/vigiloauth/vigilo/v2/internal/constants"
)

// GetRequestID retrieves the request ID from the context.
//
// Parameters:
//   - ctx context.Context: The context containing the request ID.
//
// Returns:
//   - string: The request ID as a string if present, otherwise an empty string.
func GetRequestID(ctx context.Context) string {
	if requestID, ok := ctx.Value(constants.ContextKeyRequestID).(string); ok {
		return requestID
	}

	return ""
}

// GetValueFromContext retrieves a string value from the context based on the provided key.
//
// Parameters:
//   - ctx ctx.Context: The context from which to retrieve the value.
//   - value constants.ContextKey: The key of type constants.ContextKey used to retrieve the value.
//
// Returns:
//   - any: The value if found, otherwise an empty string.
func GetValueFromContext(ctx context.Context, value constants.ContextKey) any {
	return ctx.Value(value)
}

// AddKeyValueToContext returns a new context with the specified key-value pair added.
//
// Parameters:
//   - ctx context.Context: The base context.
//   - key constants.ContextKey: The key of type constants.ContextKey to associate with the value.
//   - value any: The value to store in the context.
//
// Returns:
//   - context.Context: A new context with the key-value pair added.
func AddKeyValueToContext(ctx context.Context, key constants.ContextKey, value any) context.Context {
	return context.WithValue(ctx, key, value)
}
