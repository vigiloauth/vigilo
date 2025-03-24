package domain

import user "github.com/vigiloauth/vigilo/internal/domain/user"

// PasswordResetService defines the interface for password reset operations.
type PasswordResetService interface {
	// SendPasswordResetEmail sends a password reset email to the user.
	//
	// Parameters:
	//
	//	userEmail string: The user's email address.
	//
	// Returns:
	//
	//	*users.UserPasswordResetResponse: A response message.
	//	error: An error if the operation fails.
	SendPasswordResetEmail(userEmail string) (*user.UserPasswordResetResponse, error)

	// ResetPassword resets the user's password using the provided reset token.
	//
	// Parameters:
	//
	//	userEmail string: The user's email address.
	//	newPassword string: The new password.
	//	resetToken string: The reset token.
	//
	// Returns:
	//
	//	*users.UserPasswordResetResponse: A response message.
	//	error: An error if the operation fails.
	ResetPassword(userEmail, newPassword, resetToken string) (*user.UserPasswordResetResponse, error)
}
