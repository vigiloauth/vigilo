package domain

import "context"

// TokenManager defines operations for managing existing tokens.
type TokenManager interface {
	// Introspect checks the validity and metadata of the given token string.
	//
	// Parameters:
	//	- ctx Context: The context for managing timeouts and cancellations.
	//	- tokenStr string: The token to introspect.
	//
	// Returns:
	//	- *TokenIntrospectionResponse: TokenIntrospectionResponse containing information about the token.
	Introspect(ctx context.Context, tokenStr string) *TokenIntrospectionResponse

	// Revoke invalidates the given token string, rendering it unusable.
	//
	// Parameters:
	//	- ctx Context: The context for managing timeouts and cancellations.
	//	- tokenStr string: The token to introspect.
	//
	// Returns:
	// 	- error: An error if revocation fails.
	Revoke(ctx context.Context, tokenStr string) error

	// GetTokenData retrieves the token data from the token repository.
	//
	// Parameters:
	//	- ctx Context: The context for managing timeouts and cancellations.
	//	- token string: The token string to retrieve.
	//
	// Returns:
	//	- *TokenData: The TokenData if the token is valid, or nil if not found.
	//	- error: An error if the token is not found
	GetTokenData(ctx context.Context, tokenStr string) (*TokenData, error)

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

	// DeleteToken removes a token from the token repository.
	//
	// Parameters:
	//	- ctx Context: The context for managing timeouts and cancellations.
	//	- token string: The token string to delete.
	//
	// Returns:
	//	- error: An error if the token deletion fails.
	DeleteToken(ctx context.Context, token string) error
}
