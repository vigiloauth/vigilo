package domain

import "time"

type AuthorizationCodeRepository interface {
	// StoreAuthorizationCode persists an authorization code with its associated data.
	//
	// Parameters:
	//
	//   code string: The authorization code.
	//   data *AuthorizationCodeData: The data associated with the code.
	//   expiresAt time.Time: When the code expires.
	//
	// Returns:
	//
	//   error: An error if storing fails, nil otherwise.
	StoreAuthorizationCode(code string, data *AuthorizationCodeData, expiresAt time.Time) error

	// GetAuthorizationCode retrieves the data associated with an authorization code.
	//
	// Parameters:
	//
	//   code string: The authorization code to look up.
	//
	// Returns:
	//
	//   *AuthorizationCodeData: The associated data if found.
	//   bool: Whether the code exists and is valid.
	//   error: An error if retrieval fails.
	GetAuthorizationCode(code string) (*AuthorizationCodeData, bool, error)

	// DeleteAuthorizationCode deletes an authorization code after use.
	//
	// Parameters:
	//
	//   code string: The authorization code to remove.
	//
	// Returns:
	//
	//   error: An error if removal fails, nil otherwise.
	DeleteAuthorizationCode(code string) error

	// CleanupExpiredAuthorizationCodes removes all expired authorization codes.
	//
	// Returns:
	//
	//   error: An error if the cleanup fails, nil otherwise.
	CleanupExpiredAuthorizationCodes() error

	// Close stops the background cleanup routines if its running.
	Close()
}
