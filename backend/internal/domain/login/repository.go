package domain

import (
	"context"

	user "github.com/vigiloauth/vigilo/v2/internal/domain/user"
)

// LoginAttemptRepository defines the interface for storing and retrieving login attempts.
type LoginAttemptRepository interface {

	// SaveLoginAttempt saves a login attempt.
	//
	// Parameters:
	//	- ctx Context: The context for managing timeouts and cancellations.
	//	- attempt *UserLoginAttempt: The login attempt to save.
	//
	// Returns:
	//	- error: If an error occurs saving the login attempts.
	SaveLoginAttempt(ctx context.Context, attempt *user.UserLoginAttempt) error

	// GetLoginAttemptsByUserID retrieves all login attempts for a given user.
	//
	// Parameters:
	//	- ctx Context: The context for managing timeouts and cancellations.
	//	- userID string: The user ID.
	//
	// Returns:
	//	- []*UserLoginAttempt: A slice of login attempts for the user.
	//	- error: If an error occurs retrieving user login attempts.
	GetLoginAttemptsByUserID(ctx context.Context, userID string) ([]*user.UserLoginAttempt, error)
}
