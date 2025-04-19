package domain

import (
	"context"

	domain "github.com/vigiloauth/vigilo/internal/domain/user"
)

type LoginAttemptService interface {
	// SaveLoginAttempt logs a login attempt.
	//
	// Parameters:
	//	- ctx Context: The context for managing timeouts and cancellations.
	//	- attempt *UserLoginAttempt: The login attempt to save.
	SaveLoginAttempt(ctx context.Context, attempt *domain.UserLoginAttempt) error

	// GetLoginAttemptsByUserID retrieves all login attempts for a given user.
	//
	// Parameters:
	//	- ctx Context: The context for managing timeouts and cancellations.
	//	- userID string: The user ID.
	//
	// Returns:
	//	- []*UserLoginAttempt: A slice of login attempts for the user.
	//	- error: An error if retrieval fails.
	GetLoginAttemptsByUserID(ctx context.Context, userID string) ([]*domain.UserLoginAttempt, error)

	// HandleFailedLoginAttempt handles a failed login attempt.
	// It updates the user's last failed login time, saves the login attempt, and locks the account if necessary.
	//
	// Parameters:
	//	- ctx Context: The context for managing timeouts and cancellations.
	//	- user *User: The user who attempted to log in.
	//	- attempt *UserLoginAttempt: The login attempt information.
	//
	// Returns:
	//	- error: An error if an operation fails.
	HandleFailedLoginAttempt(ctx context.Context, user *domain.User, attempt *domain.UserLoginAttempt) error
}
