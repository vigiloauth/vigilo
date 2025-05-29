package domain

import (
	"context"
)

type AuthorizationCodeManager interface {
	// RevokeAuthorizationCode explicitly invalidates a code.
	//
	// Parameters:
	//	- ctx Context: The context for managing timeouts and cancellations.
	//	- code string: The authorization code to revoke.
	//
	// Returns:
	//	- error: An error if revocation fails.
	RevokeAuthorizationCode(ctx context.Context, code string) error

	// GetAuthorizationCode retrieves the authorization code data for a given code.
	//
	// Parameters:
	//	- ctx Context: The context for managing timeouts and cancellations.
	//	- code string: The authorization code to retrieve.
	//
	// Returns:
	//	- *AuthorizationCodeData: The authorization code data if found, or nil if no matching code exists.
	GetAuthorizationCode(ctx context.Context, code string) (*AuthorizationCodeData, error)

	// UpdateAuthorizationCode updates the provided authorization code data in the repository.
	//
	// Parameters:
	//	- ctx Context: The context for managing timeouts and cancellations.
	//	- authData (*authz.AuthorizationCodeData): The authorization code data to be updated.
	//
	// Returns:
	//	- error: An error if updated the authorization code fails, or nil if the operation succeeds.
	UpdateAuthorizationCode(ctx context.Context, authData *AuthorizationCodeData) error
}
