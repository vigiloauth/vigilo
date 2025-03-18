package auth

// LoginAttemptStore defines the interface for storing and retrieving login attempts.
type LoginAttemptStore interface {
	// SaveLoginAttempt logs a login attempt.
	//
	// Parameters:
	//   attempt *LoginAttempt: The login attempt to save.
	SaveLoginAttempt(attempt *LoginAttempt)

	// GetLoginAttempts retrieves all login attempts for a given user.
	//
	// Parameters:
	//   userID string: The user ID.
	//
	// Returns:
	//   []*LoginAttempt: A slice of login attempts for the user.
	GetLoginAttempts(userID string) []*LoginAttempt
}
