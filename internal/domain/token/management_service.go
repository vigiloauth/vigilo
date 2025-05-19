package domain

import "context"

// TokenManagementService defines operations for managing tokens,
// including introspection and revocation.
type TokenManagementService interface {
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
}
