package domain

import (
	"context"
	"time"
)

type AuthorizationCodeRepository interface {
	// StoreAuthorizationCode persists an authorization code with its associated data.
	//
	// Parameters:
	//	- ctx Context: The context for managing timeouts and cancellations.
	//	- code string: The authorization code.
	//  - data *AuthorizationCodeData: The data associated with the code.
	//  - expiresAt time.Time: When the code expires.
	//
	// Returns:
	//	- error: An error if storing fails, nil otherwise.
	StoreAuthorizationCode(ctx context.Context, code string, data *AuthorizationCodeData, expiresAt time.Time) error

	// GetAuthorizationCode retrieves the data associated with an authorization code.
	//
	// Parameters:
	//	- ctx Context: The context for managing timeouts and cancellations.
	//	- code string: The authorization code to look up.
	//
	// Returns:
	//	- *AuthorizationCodeData: The associated data if found.
	//	- error: An error if retrieval fails.
	GetAuthorizationCode(ctx context.Context, code string) (*AuthorizationCodeData, error)

	// DeleteAuthorizationCode deletes an authorization code after use.
	//
	// Parameters:
	//	- ctx Context: The context for managing timeouts and cancellations.
	//	- code string: The authorization code to remove.
	//
	// Returns:
	//	- error: An error if removal fails, nil otherwise.
	DeleteAuthorizationCode(ctx context.Context, code string) error

	// UpdateAuthorizationCode updates existing authorization code data.
	//
	// Parameters:
	//	- ctx Context: The context for managing timeouts and cancellations.
	//	- code string: The authorization code to update.
	//	- authData *AuthorizationCodeData: The update authorization code data.
	//
	// Returns:
	//	- error: An error if update fails, nil otherwise.
	UpdateAuthorizationCode(ctx context.Context, code string, authData *AuthorizationCodeData) error
}
