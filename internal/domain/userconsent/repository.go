package domain

// ConsentRepository defines the interface for storing and managing user consent data.
type ConsentRepository interface {
	// HasConsent checks if a user has granted consent to a client for specific scopes.
	//
	// Parameters:
	//
	//   userID string: The ID of the user.
	//   clientID string: The ID of the client application.
	//   requestedScope string: The requested scope(s).
	//
	// Returns:
	//
	//   bool: True if consent exists, false otherwise.
	//   error: An error if the check fails, or nil if successful.
	HasConsent(userID, clientID, requestedScope string) (bool, error)

	// SaveConsent stores a user's consent for a client and scope.
	//
	// Parameters:
	//
	//   userID string: The ID of the user.
	//   clientID string: The ID of the client application.
	//   scope string: The granted scope(s).
	//
	// Returns:
	//
	//   error: An error if the consent cannot be saved, or nil if successful.
	SaveConsent(userID, clientID, scope string) error

	// RevokeConsent removes a user's consent for a client.
	//
	// Parameters:
	//
	//   userID string: The ID of the user.
	//   clientID string: The ID of the client application.
	//
	// Returns:
	//
	//   error: An error if the consent cannot be revoked, or nil if successful.
	RevokeConsent(userID, clientID string) error
}
