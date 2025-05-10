package domain

import (
	"context"
	"net/http"
)

// SessionService defines the interface for session management.
type SessionService interface {
	// GetOrCreateSession attempts to retrieve an existing session or creates one if it doesn't exist.
	//
	// Parameters:
	//	- ctx context.Context: Context for managing timeouts and request IDs.
	//	- w http.ResponseWriter: The HTTP response writer.
	//	- r *http.Request: The HTTP request.
	//	- sessionData *SessionData: The session data.
	//
	// Returns:
	//	- *SessionData: The retrieved or created session data.
	//	- error: An error if retrieval or creation fails.
	GetOrCreateSession(ctx context.Context, w http.ResponseWriter, r *http.Request, sessionData *SessionData) (*SessionData, error)

	// InvalidateSession invalidates the session token by adding it to the blacklist.
	//
	// Parameters:
	//	- w http.ResponseWriter: The HTTP response writer.
	//	- r *http.Request: The HTTP request.
	//
	// Returns:
	//	- error: An error if token parsing or blacklist addition fails.
	InvalidateSession(w http.ResponseWriter, r *http.Request) error

	// GetUserIDFromSession retrieves the user ID from the current session.
	//
	// Parameters:
	//	- r *http.Request: The HTTP request.
	//
	// Returns:
	//	- string: The user ID.
	GetUserIDFromSession(r *http.Request) string

	// UpdateSession updates the current session.
	//
	// Parameters:
	//	- r *http.Request: The HTTP request.
	//	- sessionData *SessionData: The sessionData to update.
	//
	// Returns:
	//	- error: If an error occurs during the update.
	UpdateSession(r *http.Request, sessionData *SessionData) error

	// GetSessionData retrieves the current session.
	//
	// Parameters:
	//	- r *http.Request: The HTTP request.
	//
	// Returns:
	//	- *SessionData: The session data is successful.
	//	- error: An error if retrieval fails.
	GetSessionData(r *http.Request) (*SessionData, error)
}
