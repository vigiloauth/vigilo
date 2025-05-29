package domain

import (
	"context"
)

// SessionRepository defines the interface for session management operations.
type SessionRepository interface {
	// SaveSession creates a new session and returns the session ID.
	//
	// Parameters:
	//	- ctx Context: The context for managing timeouts and cancellations.
	//  - sessionData SessionData: The data to store in the new session.
	//
	// Returns:
	//  - error: An error if the session creation fails.
	SaveSession(ctx context.Context, sessionData *SessionData) error

	// GetSessionByID retrieves session data for a given session ID.
	//
	// Parameters:
	//	- ctx Context: The context for managing timeouts and cancellations.
	//  - sessionID string: The unique identifier of the session to retrieve.
	//
	// Returns:
	//  - *SessionData: The session data associated with the session ID.
	//  - error: An error if the session is not found or retrieval fails.
	GetSessionByID(ctx context.Context, sessionID string) (*SessionData, error)

	// UpdateSessionByID updates the session data for a given session ID.
	//
	// Parameters:
	//	- ctx Context: The context for managing timeouts and cancellations.
	//  - sessionID string: The unique identifier of the session to update.
	//  - sessionData SessionData: The updated session data.
	//
	// Returns:
	//  - error: An error if the update fails.
	UpdateSessionByID(ctx context.Context, sessionID string, sessionData *SessionData) error

	// DeleteSessionByID removes a session with the given session ID.
	//
	// Parameters:
	//	- ctx Context: The context for managing timeouts and cancellations.
	//  - sessionID string: The unique identifier of the session to delete.
	//
	// Returns:
	//  - error: An error if the deletion fails.
	DeleteSessionByID(ctx context.Context, sessionID string) error
}
