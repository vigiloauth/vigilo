package domain

import (
	"net/http"
)

// SessionService defines the interface for session management.
type SessionService interface {
	// CreateSession creates a new session token and sets it in an HttpOnly cookie.
	//
	// Parameters:
	//   - w http.ResponseWriter: The HTTP response writer.
	//   - r *http.Request: The HTTP request.
	//   - userID string: The user's ID address.
	//   - sessionExpiration time.Duration: The session expiration time.
	//
	// Returns:
	//   - error: An error if token generation or cookie setting fails.
	CreateSession(w http.ResponseWriter, r *http.Request, sessionData *SessionData) error

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
