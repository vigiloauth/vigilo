package domain

import "context"

// UserConsentRepository defines the interface for storing and managing user consent data.
type UserConsentRepository interface {
	// HasConsent checks if a user has granted consent to a client for specific scopes.
	//
	// Parameters:
	//	- ctx Context: The context for managing timeouts and cancellations.
	//	- userID string: The ID of the user.
	//	- clientID string: The ID of the client application.
	//	- requestedScope string: The requested scope(s).
	//
	// Returns:
	//   bool: True if consent exists, false otherwise.
	//   error: An error if the check fails, or nil if successful.
	HasConsent(ctx context.Context, userID, clientID, requestedScope string) (bool, error)

	// SaveConsent stores a user's consent for a client and scope.
	//
	// Parameters:
	//	- ctx Context: The context for managing timeouts and cancellations.
	//	- userID string: The ID of the user.
	//	- clientID string: The ID of the client application.
	//	- scope string: The granted scope(s).
	//
	// Returns:
	//	- error: An error if the consent cannot be saved, or nil if successful.
	SaveConsent(ctx context.Context, userID, clientID, scope string) error

	// RevokeConsent removes a user's consent for a client.
	//
	// Parameters:
	//	- ctx Context: The context for managing timeouts and cancellations.
	//	- userID string: The ID of the user.
	//	- clientID string: The ID of the client application.
	//
	// Returns:
	//	- error: An error if the consent cannot be revoked, or nil if successful.
	RevokeConsent(ctx context.Context, userID, clientID string) error
}
