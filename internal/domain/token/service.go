package domain

import (
	"time"

	"github.com/golang-jwt/jwt"
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
	GenerateToken(subject string, expirationTime time.Duration) (string, error)

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
	GenerateTokenPair(userID, clientID string) (string, string, error)

	// ParseToken parses and validates a JWT token string.
	//
	// Parameters:
	//
	//   tokenString string: The JWT token string to parse.
	//
	// Returns:
	//
	//   *jwt.StandardClaims: The parsed standard claims from the token.
	//   error: An error if token parsing or validation fails.
	ParseToken(tokenString string) (*jwt.StandardClaims, error)

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
	//   email string: The email to validate against.
	//   token string: The token string to retrieve.
	//
	// Returns:
	//
	//   *TokenData: The TokenData if the token is valid, or nil if not found or invalid.
	//   error: An error if the token is not found, expired, or the email doesn't match.
	GetToken(email string, token string) (*TokenData, error)

	// DeleteToken removes a token from the token store.
	//
	// Parameters:
	//
	//   token string: The token string to delete.
	//
	// Returns:
	//
	//   error: An error if the token deletion fails.
	DeleteToken(token string) error

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
}
