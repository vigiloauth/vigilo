package domain

import (
	"context"
	"net/http"
)

type SessionManager interface {
	// GetUserIDFromSession checks if the user session is active based on the provided context and HTTP request.
	//
	// Parameters:
	//   - ctx Context: The context for managing timeouts and cancellations.
	//   - r *http.Request: The HTTP request associated with the user session.
	//
	// Returns:
	//   - string: The user ID if the session is active, or an empty string if not.
	//   - error: An error if the session data retrieval fails.
	GetUserIDFromSession(ctx context.Context, r *http.Request) (string, error)

	// GetUserAuthenticationTime retrieves the authentication time of the user session based on the provided context and HTTP request.
	//
	// Parameters:
	//   - ctx Context: The context for managing timeouts and cancellations.
	//   - r *http.Request: The HTTP request associated with the user session.
	//
	// Returns:
	//   - int64: The authentication time in Unix timestamp format.
	//   - error: An error if the session data retrieval fails.
	GetUserAuthenticationTime(ctx context.Context, r *http.Request) (int64, error)
}
