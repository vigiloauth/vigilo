package domain

import user "github.com/vigiloauth/vigilo/internal/domain/user"

// LoginAttemptRepository defines the interface for storing and retrieving login attempts.
type LoginAttemptRepository interface {

	// SaveLoginAttempt logs a login attempt.
	//
	// Parameters:
	//   attempt *UserLoginAttempt: The login attempt to save.
	SaveLoginAttempt(attempt *user.UserLoginAttempt) error

	// GetLoginAttempts retrieves all login attempts for a given user.
	//
	// Parameters:
	//   userID string: The user ID.
	//
	// Returns:
	//   []*UserLoginAttempt: A slice of login attempts for the user.
	GetLoginAttempts(userID string) []*user.UserLoginAttempt
}
