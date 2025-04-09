package domain

import "time"

// TokenRepository defines the interface for storing and managing tokens.
type TokenRepository interface {
	// SaveToken adds a token to the store.
	//
	// Parameters:
	//
	//   token string: The token string to add.
	//   id string: The id associated with the token.
	//   expiration time.Time: The token's expiration time.
	SaveToken(token string, id string, expiration time.Time)

	// IsTokenBlacklisted checks if a token is blacklisted.
	//
	// Parameters:
	//
	//   token string: The token string to check.
	//
	// Returns:
	//
	//   bool: True if the token is blacklisted, false otherwise.
	IsTokenBlacklisted(token string) bool

	// GetToken retrieves a token from the store and validates it.
	//
	// Parameters:
	//
	//   tokenStr string: The token string to retrieve.
	//   id string: The id to validate against.
	//
	// Returns:
	//
	//   *TokenData: The TokenData if the token is valid, or nil if not found or invalid.
	//   error: An error if the token is not found, expired, or the email doesn't match.
	GetToken(tokenStr string, id string) (*TokenData, error)

	// DeleteToken removes a token from the store.
	//
	// Parameters:
	//
	//   token string: The token string to delete.
	//
	// Returns:
	//
	//   error: An error if the token deletion fails.
	DeleteToken(token string) error

	BlacklistToken(token string) error
}
