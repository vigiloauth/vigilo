package domain

import (
	"context"
	"time"
)

// TokenService defines the interface for managing JWT tokens.
type TokenService interface {
	// GenerateToken generates a JWT token for the given subject and expiration time.
	//
	// Parameters:
	//	- ctx Context: The context for managing timeouts and cancellations.
	//	- subject string: The subject of the token (e.g., user email).
	//	- scopes string: The scopes to be added to the token (can be an empty string if none are needed)..
	//	- roles string: The roles to be added to the token (can be an empty string if none are needed).
	//	- expirationTime time.Duration: The duration for which the token is valid.
	//
	// Returns:
	//	- string: The generated JWT token string.
	//	- error: An error if token generation fails.
	GenerateToken(ctx context.Context, subject, scopes, roles string, expirationTime time.Duration) (string, error)

	// GenerateTokensWithAudience generates an access & refresh token.
	//
	// Parameters:
	//	- ctx Context: The context for managing timeouts and cancellations.
	//	- userID string: The ID of the user. Will be used as the subject.
	//	- clientID string: The ID of the client. Will be used as the audience.
	//	- scopes string: The scopes to be added to the token (can be an empty string if none are needed)..
	//	- roles string: The roles to be added to the token (can be an empty string if none are needed).
	//
	// Returns:
	//	- string: The access token.
	//	- string: The refresh token.
	//	- error: An error if an error occurs while generating the tokens.
	GenerateTokensWithAudience(ctx context.Context, userID, clientID, scopes, roles string) (string, string, error)

	// ParseToken parses and validates a JWT token string.
	//
	// Parameters:
	//	- tokenString string: The JWT token string to parse.
	//
	// Returns:
	//	- *TokenClaims: The parsed standard claims from the token.
	//	- error: An error if token parsing or validation fails.
	ParseToken(tokenString string) (*TokenClaims, error)

	// IsTokenBlacklisted checks if a token is blacklisted.
	//
	// Parameters:
	//	- ctx Context: The context for managing timeouts and cancellations.
	//	- token string: The token string to check.
	//
	// Returns:
	//	- bool: True if the token is blacklisted, false otherwise.
	//	- error: An error if querying the database fails.
	IsTokenBlacklisted(ctx context.Context, token string) (bool, error)

	// SaveToken adds a token to the token store.
	//
	// Parameters:
	//	- ctx Context: The context for managing timeouts and cancellations.
	//	- token string: The token string to add.
	//	- id string: The id associated with the token.
	//	- expirationTime time.Time: The token's expiration time.
	//
	// Returns:
	//	- error: If a database error occurs.
	SaveToken(ctx context.Context, token string, id string, expirationTime time.Time) error

	// GetToken retrieves a token from the token store and validates it.
	//
	// Parameters:
	//	- ctx Context: The context for managing timeouts and cancellations.
	//	- token string: The token string to retrieve.
	//
	// Returns:
	//	- *TokenData: The TokenData if the token is valid, or nil if not found or invalid.
	//	- error: An error if the token is not found, expired, or the subject doesn't match.
	GetToken(ctx context.Context, token string) (*TokenData, error)

	// DeleteToken removes a token from the token repository.
	//
	// Parameters:
	//	- ctx Context: The context for managing timeouts and cancellations.
	//	- token string: The token string to delete.
	//
	// Returns:
	//	- error: An error if the token deletion fails.
	DeleteToken(ctx context.Context, token string) error

	// DeleteToken removes a token from the token repository asynchronously.
	//
	// Parameters:
	//	- ctx Context: The context for managing timeouts and cancellations.
	//	- token string: The token string to delete.
	//
	// Returns:
	//	- error: An error if the token deletion fails.
	DeleteTokenAsync(ctx context.Context, token string) <-chan error

	// IsTokenExpired checks to see if the provided token is expired.
	//
	// Parameters:
	//	- token string: The token string
	//
	// Returns:
	//	- bool: True is expired, otherwise false.
	IsTokenExpired(token string) bool

	// ValidateToken checks to see if a token is blacklisted or expired.
	//
	// Parameters:
	//	- ctx Context: The context for managing timeouts and cancellations.
	//	- token string: The token string to check.
	//
	// Returns:
	//	- error: An error if the token is blacklisted or expired.
	ValidateToken(ctx context.Context, token string) error

	// GenerateRefreshAndAccessTokens generates new tokens with the given subject.
	//
	// Parameters:
	//	- ctx Context: The context for managing timeouts and cancellations.
	//	- subject string: The subject for the token claims.
	//	- scopes string: The scopes to be added to the token (can be an empty string if none are needed)..
	//	- roles string: The roles to be added to the token (can be an empty string if none are needed).
	//
	//	Returns:
	//	- accessToken string: A new access token.
	//	- refreshToken string: A new refresh token.
	//	- error: An error if an error occurs during generation.
	GenerateRefreshAndAccessTokens(ctx context.Context, subject, scopes, roles string) (string, string, error)

	// BlacklistToken adds the specified token to the blacklist, preventing it from being used
	// for further authentication or authorization. The token is marked as invalid, even if it
	// has not yet expired.
	//
	// Parameters:
	//	- ctx Context: The context for managing timeouts and cancellations.
	//	- token string: The token to be blacklisted. This is the token that will no longer be valid for further use.
	//
	// Returns:
	//	- error: An error if the token is not found in the token store or if it has already expired, in which case it cannot be blacklisted.
	BlacklistToken(ctx context.Context, token string) error

	// DeleteExpiredTokens retrieves expired tokens from the repository and deletes them.
	//
	// Parameters:
	//	- ctx Context: The context for managing timeouts and cancellations.
	//
	// Returns:
	//	- error: An error if retrieval or deletion fails.
	DeleteExpiredTokens(ctx context.Context) error
}
