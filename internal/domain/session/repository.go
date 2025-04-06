package domain

import "time"

// SessionRepository defines the interface for session management operations.
type SessionRepository interface {
	// SaveSession creates a new session and returns the session ID.
	//
	// Parameters:
	//
	//   - sessionData SessionData: The data to store in the new session.
	// Returns:
	//
	//   - error: An error if the session creation fails.
	SaveSession(sessionData *SessionData) error

	// GetSessionByID retrieves session data for a given session ID.
	//
	// Parameters:
	//
	//   - sessionID string: The unique identifier of the session to retrieve.
	// Returns:
	//
	//   - SessionData: The session data associated with the session ID.
	//   - error: An error if the session is not found or retrieval fails.
	GetSessionByID(sessionID string) (*SessionData, error)

	// UpdateSessionByID updates the session data for a given session ID.
	//
	// Parameters:
	//
	//   - sessionID string: The unique identifier of the session to update.
	//   - sessionData SessionData: The updated session data.
	// Returns:
	//
	//   - error: An error if the update fails.
	UpdateSessionByID(sessionID string, sessionData *SessionData) error

	// DeleteSessionByID removes a session with the given session ID.
	//
	// Parameters:
	//
	//   - sessionID string: The unique identifier of the session to delete.
	// Returns:
	//
	//   - error: An error if the deletion fails.
	DeleteSessionByID(sessionID string) error

	// CleanupExpiredSessions starts a go routine and removes all expired sessions from the repository.
	CleanupExpiredSessions(ticket *time.Ticker)
}
