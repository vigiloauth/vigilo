package domain

// ConsentService defines the interface for managing user consent operations
// in the OAuth2 authorization flow.
type ConsentService interface {
	// CheckUserConsent verifies if a user has previously granted consent to a client
	// for the requested scope.
	//
	// Parameters:
	//
	//   userID string: The unique identifier of the user.
	//   clientID string: The identifier of the client application requesting access.
	//   scope string: The space-separated list of permissions being requested.
	//
	// Returns:
	//
	//   bool: True if consent exists, false if consent is needed.
	//   error: An error if the consent check operation fails.
	CheckUserConsent(userID, clientID, scope string) (bool, error)

	// SaveUserConsent records a user's consent for a client application
	// to access resources within the specified scope.
	//
	// Parameters:
	//
	//   userID string: The unique identifier of the user granting consent.
	//   clientID string: The identifier of the client application receiving consent.
	//   scope string: The space-separated list of permissions being granted.
	//
	// Returns:
	//
	//   error: An error if the consent cannot be saved, or nil if successful.
	SaveUserConsent(userID, clientID, scope string) error

	// RevokeConsent removes a user's consent for a client.
	//
	// Parameters:
	//
	//	userID string: The ID of the user.
	//	clientID string: The ID of the client application.
	//
	// Returns:
	//
	//	error: An error if the consent cannot be revoked, or nil if successful.
	RevokeConsent(userID, clientID string) error
}
