package domain

import "context"

type UserManager interface {
	// GetUserByUsername retrieves a user using their username.
	//
	// Parameter:
	//	- ctx Context: The context for managing timeouts and cancellations.
	//	- username string: The username of the user to retrieve.
	//
	// Returns:
	//	- *User: The retrieved user, otherwise nil.
	//	- error: If an error occurs retrieving the user.
	GetUserByUsername(ctx context.Context, username string) (*User, error)

	// GetUserByID retrieves a user from the store using their ID.
	//
	// Parameters:
	//	- ctx Context: The context for managing timeouts and cancellations.
	//	- userID string: The ID used to retrieve the user.
	//
	// Returns:
	//	- *User: The User object if found, or nil if not found.
	//	- error: If an error occurs retrieving the user.
	GetUserByID(ctx context.Context, userID string) (*User, error)

	// DeleteUnverifiedUsers deletes any user that hasn't verified their account and
	// has been created for over a week.
	//
	// Parameter:
	//	- ctx Context: The context for managing timeouts and cancellations.
	//
	// Returns:
	//	- error: an error if deletion fails, otherwise nil.
	DeleteUnverifiedUsers(ctx context.Context) error

	// ResetPassword resets the user's password using the provided reset token.
	//
	// Parameters:
	//	- ctx Context: The context for managing timeouts and cancellations.
	//	- userEmail string: The user's email address.
	//	- newPassword string: The new password.
	//	- resetToken string: The reset token.
	//
	// Returns:
	//	- *users.UserPasswordResetResponse: A response message.
	//	- error: An error if the operation fails.
	ResetPassword(ctx context.Context, userEmail, newPassword, resetToken string) (*UserPasswordResetResponse, error)
}
