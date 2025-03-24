package domain

import domain "github.com/vigiloauth/vigilo/internal/domain/user"

type LoginAttemptService interface {
	// SaveLoginAttempt logs a login attempt.
	//
	// Parameters:
	//
	//   attempt *UserLoginAttempt: The login attempt to save.
	SaveLoginAttempt(attempt *domain.UserLoginAttempt) error

	// GetLoginAttempts retrieves all login attempts for a given user.
	//
	// Parameters:
	//
	//   userID string: The user ID.
	//
	// Returns:
	//
	//   []*UserLoginAttempt: A slice of login attempts for the user.
	GetLoginAttempts(userID string) []*domain.UserLoginAttempt

	// HandleFailedLoginAttempt handles a failed login attempt.
	// It updates the user's last failed login time, saves the login attempt, and locks the account if necessary.
	//
	// Parameters:
	//
	//	user *User: The user who attempted to log in.
	//	attempt *UserLoginAttempt: The login attempt information.
	//
	// Returns:
	//
	//	error: An error if an operation fails.
	HandleFailedLoginAttempt(user *domain.User, attempt *domain.UserLoginAttempt) error
}
