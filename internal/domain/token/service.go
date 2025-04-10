package domain

import (
	"time"
)

// TokenService defines the interface for managing JWT tokens.
type TokenService interface {
	// GenerateToken generates a JWT token for the given subject and expiration time.
	//
	// Parameters:
	//
	//   subject string: The subject of the token (e.g., user email).
	//   expirationTime time.Duration: The duration for which the token is valid.
	//
	// Returns:
	//
	//   string: The generated JWT token string.
	//   error: An error if token generation fails.
	GenerateToken(subject, scopes string, expirationTime time.Duration) (string, error)

	// GenerateTokenPair generates an access & refresh token.
	//
	// Parameters:
	//
	//	userID string: The ID of the user. Will be used as the subject.
	//	clientID string: The ID of the client. Will be used as the audience.
	//
	// Returns:
	//
	//	string: The access token.
	//	string: The refresh token.
	//	error: An error if an error occurs while generating the tokens.
	GenerateTokenPair(userID, clientID, scopes string) (string, string, error)

	// ParseToken parses and validates a JWT token string.
	//
	// Parameters:
	//
	//   tokenString string: The JWT token string to parse.
	//
	// Returns:
	//
	//   *TokenClaims: The parsed standard claims from the token.
	//   error: An error if token parsing or validation fails.
	ParseToken(tokenString string) (*TokenClaims, error)

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

	// SaveToken adds a token to the token store.
	//
	// Parameters:
	//
	//   token string: The token string to add.
	//   id string: The id associated with the token.
	//   expirationTime time.Time: The token's expiration time.
	SaveToken(token string, id string, expirationTime time.Time)

	// GetToken retrieves a token from the token store and validates it.
	//
	// Parameters:
	//
	//   token string: The token string to retrieve.
	//
	// Returns:
	//
	//   *TokenData: The TokenData if the token is valid, or nil if not found or invalid.
	//   error: An error if the token is not found, expired, or the email doesn't match.
	GetToken(token string) (*TokenData, error)

	// DeleteToken removes a token from the token repository.
	//
	// Parameters:
	//
	//   token string: The token string to delete.
	//
	// Returns:
	//
	//   error: An error if the token deletion fails.
	DeleteToken(token string) error

	// DeleteToken removes a token from the token repository asynchronously.
	//
	// Parameters:
	//
	//   token string: The token string to delete.
	//
	// Returns:
	//
	//   error: An error if the token deletion fails.
	DeleteTokenAsync(token string) <-chan error

	// IsTokenExpired checks to see if the provided token is expired.
	//
	// Parameters:
	//
	//	token string: The token string
	//
	// Returns:
	//
	//	bool: True is expired, otherwise false.
	IsTokenExpired(token string) bool

	// ValidateToken checks to see if a token is blacklisted or expired.
	//
	// Parameters:
	//
	//	token string: The token string to check.
	//
	// Returns:
	//
	//	error: An error if the token is blacklisted or expired.
	ValidateToken(token string) error

	// GenerateRefreshAndAccessTokens generates new tokens with the given subject.
	//
	// Parameters:
	//
	//	subject string: The subject for the token claims.
	//
	//	Returns:
	//
	//	refreshToken string: A new refresh token.
	//	accessToken string: A new access token.
	//	error: An error if an error occurs during generation.
	GenerateRefreshAndAccessTokens(subject, scopes string) (string, string, error)

	// BlacklistToken adds the specified token to the blacklist, preventing it from being used
	// for further authentication or authorization. The token is marked as invalid, even if it
	// has not yet expired.
	//
	// Parameters:
	//
	//	token (string): The token to be blacklisted. This is the token that will no longer
	//     be valid for further use.
	//
	// Returns:
	//
	// 	error: An error if the token is not found in the token store or if it has already
	//     expired, in which case it cannot be blacklisted.
	BlacklistToken(token string) error
}
