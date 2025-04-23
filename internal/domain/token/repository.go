package domain

import (
	"context"
	"time"
)

// TokenRepository defines the interface for storing and managing tokens.
type TokenRepository interface {
	// SaveToken adds a token to the store.
	//
	// Parameters:
	//	- ctx Context: The context for managing timeouts and cancellations.
	//	- token string: The token string to add.
	//	- id string: The id associated with the token.
	//	- expiration time.Time: The token's expiration time.
	//
	// Returns:
	//	- error: If an error occurs saving the token.
	SaveToken(ctx context.Context, token string, id string, expiration time.Time) error

	// IsTokenBlacklisted checks if a token is blacklisted.
	//
	// Parameters:
	//	- ctx Context: The context for managing timeouts and cancellations.
	//	- token string: The token string to check.
	//
	// Returns:
	//	- bool: True if the token is blacklisted, false otherwise.
	//	- error: If an error occurs checking the token.
	IsTokenBlacklisted(ctx context.Context, token string) (bool, error)

	// GetToken retrieves a token from the store and validates it.
	//
	// Parameters:
	//	- ctx Context: The context for managing timeouts and cancellations.
	//	- tokenStr string: The token string to retrieve.
	//
	// Returns:
	//	- *TokenData: The TokenData if the token is valid, or nil if not found.
	//	- error: If an error occurs retrieving the token.
	GetToken(ctx context.Context, tokenStr string) (*TokenData, error)

	// DeleteToken removes a token from the store.
	//
	// Parameters:
	//	- ctx Context: The context for managing timeouts and cancellations.
	//	- token string: The token string to delete.
	//
	// Returns:
	//	- error: An error if the token deletion fails.
	DeleteToken(ctx context.Context, token string) error

	// BlacklistToken adds a token to the blacklist.
	//
	// Parameters:
	//	- ctx Context: The context for managing timeouts and cancellations.
	//	- token string: The token string to delete.
	//
	// Returns:
	//	- error: An error if the token blacklisting fails.
	BlacklistToken(ctx context.Context, token string) error

	// ExistsByTokenID checks to see if the given ID matches with any token in the repository.
	//
	// Parameters:
	//	- ctx Context: The context for managing timeouts and cancellations.
	//	- tokenID string: The token ID to search.
	//
	// Returns:
	//	- error: An error if the searching for the token fails.
	ExistsByTokenID(ctx context.Context, tokenID string) (bool, error)

	// GetExpiredTokens searches for all expired tokens in the repository.
	//
	// Parameters:
	//	- ctx Context: The context for managing timeouts and cancellations.
	//
	// Returns:
	//	- []*TokenData: A slice of token data.
	//	- error: An error if searching fails.
	GetExpiredTokens(ctx context.Context) ([]*TokenData, error)
}
