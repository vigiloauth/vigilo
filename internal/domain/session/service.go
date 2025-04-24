package domain

import (
	"context"
	"net/http"
	"time"
)

// SessionService defines the interface for session management.
type SessionService interface {
	// CreateSession creates a new session token and sets it in an HttpOnly cookie.
	//
	// Parameters:
	//	- w http.ResponseWriter: The HTTP response writer.
	//	- r *http.Request: The HTTP request.
	//	- userID string: The user's ID address.
	//	- sessionExpiration time.Duration: The session expiration time.
	//
	// Returns:
	//	- error: An error if token generation or cookie setting fails.
	CreateSession(w http.ResponseWriter, r *http.Request, userID string, sessionExpiration time.Duration) error

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

	// ClearStateFromSession clears the state value from the session data.
	//
	// Parameters:
	//  - ctx Context: The context for managing timeouts and cancellations.
	//	- sessionData *SessionData: The session data to be updated.
	//
	// Returns:
	//	- error: An error if the session update fails, or nil if successful.
	ClearStateFromSession(ctx context.Context, sessionData *SessionData) error

	// ValidateSessionState retrieves session data and verifies that the state parameter in the request matches the stored session state.
	//
	// Parameters:
	//	- r *http.Request: The HTTP request containing the session information.
	//
	// Returns:
	//	- *SessionData: The retrieved session data if validation is successful.
	//	- error: An error if retrieving session data fails or if the state parameter does not match.
	ValidateSessionState(r *http.Request) (*SessionData, error)
}
