package domain

import "context"

type TokenValidator interface {

	// ValidateToken checks to see if a token is blacklisted or expired.
	//
	// Parameters:
	//	- ctx Context: The context for managing timeouts and cancellations.
	//	- tokenStr string: The token string to check.
	//
	// Returns:
	//	- error: An error if the token is blacklisted or expired.
	ValidateToken(ctx context.Context, tokenStr string) error
}
